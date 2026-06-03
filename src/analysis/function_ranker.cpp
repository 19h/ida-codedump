#include "function_ranker.h"

#include "common/function_filter.h"

#include <ida/entry.hpp>
#include <ida/address.hpp>
#include <ida/function.hpp>
#include <ida/segment.hpp>
#include <ida/xref.hpp>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <map>
#include <numeric>
#include <optional>
#include <queue>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace codedump {

namespace {

struct NodeSignals {
    std::set<ida::Address> callers;
    bool address_taken = false;
    bool anchor = false;
    bool system = false;
    std::size_t function_size = 0;
};

struct SccGraph {
    std::vector<int> node_to_scc;
    std::vector<std::vector<int>> members;
    std::vector<std::vector<int>> dag;
};

struct WeightedGraph {
    std::vector<std::vector<std::pair<int, double>>> out;
    std::vector<std::vector<std::pair<int, double>>> in;
    std::vector<double> indegree;
    std::vector<double> outdegree;
};

bool has_any_type(const Edge &edge, std::initializer_list<RefType> types) {
    for (RefType type : types)
        if (edge.types.count(type)) return true;
    return false;
}

bool is_strong_call_edge(const Edge &edge) {
    return has_any_type(edge, {RefType::DirectCall, RefType::TailCallPushRet});
}

bool is_resolved_call_edge(const Edge &edge) {
    return is_strong_call_edge(edge)
        || has_any_type(edge, {
            RefType::IndirectCall,
            RefType::VirtualCall,
            RefType::JumpTable
        });
}

bool is_address_taken_edge(const Edge &edge) {
    return has_any_type(edge, {RefType::DataRef, RefType::ImmediateRef});
}

double resolved_edge_confidence(const Edge &edge) {
    double confidence = 0.0;
    if (edge.types.count(RefType::IndirectCall))
        confidence = std::max(confidence, 0.6);
    if (edge.types.count(RefType::JumpTable))
        confidence = std::max(confidence, 0.6);
    if (edge.types.count(RefType::VirtualCall))
        confidence = std::max(confidence, 0.4);
    return confidence;
}

std::string canonical_name(std::string_view raw) {
    std::string name{raw};
    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    bool changed = true;
    while (changed) {
        changed = false;
        for (std::string_view prefix : {"j_", "__imp_", "_imp_", "imp_", "."}) {
            if (name.size() >= prefix.size()
                && name.substr(0, prefix.size()) == prefix) {
                name.erase(0, prefix.size());
                changed = true;
            }
        }
        while (!name.empty() && name.front() == '_') {
            name.erase(name.begin());
            changed = true;
        }
    }

    if (!name.empty() && name.front() != '?') {
        if (size_t pos = name.find('@'); pos != std::string::npos)
            name.erase(pos);
    }
    return name;
}

bool name_is_entry_like(std::string_view raw) {
    std::string name = canonical_name(raw);
    static constexpr std::string_view exact[] = {
        "main", "wmain", "winmain", "wwinmain", "dllmain", "start",
        "thread_start", "threadproc", "thread_proc", "start_routine"
    };
    for (std::string_view candidate : exact)
        if (name == candidate) return true;
    return false;
}

std::optional<ida::Address> function_start(ida::Address ea) {
    ida::Result<ida::function::Function> function = ida::function::at(ea);
    if (!function) return std::nullopt;
    return static_cast<ida::Address>(function->start());
}

std::size_t function_size(ida::Address ea) {
    ida::Result<ida::function::Function> function = ida::function::at(ea);
    if (!function) return 0;
    return static_cast<std::size_t>(function->size());
}

bool function_is_thunk(ida::Address ea) {
    ida::Result<ida::function::Function> function = ida::function::at(ea);
    return function && function->is_thunk();
}

void mark_entry_anchors(
    const std::unordered_map<ida::Address, int> &index_by_ea,
    std::vector<NodeSignals> &signals
) {
    ida::Result<std::size_t> count = ida::entry::count();
    if (count) {
        for (std::size_t i = 0; i < *count; ++i) {
            ida::Result<ida::entry::EntryPoint> ep = ida::entry::by_index(i);
            if (!ep || ep->address == ida::BadAddress) continue;
            std::optional<ida::Address> start = function_start(ep->address);
            if (!start) continue;
            auto it = index_by_ea.find(*start);
            if (it != index_by_ea.end()) signals[it->second].anchor = true;
        }
    }

    for (const auto &[ea, index] : index_by_ea) {
        ida::Result<std::string> name = ida::function::name_at(ea);
        if (name && name_is_entry_like(*name))
            signals[index].anchor = true;
    }
}

std::vector<int> topological_order(const std::vector<std::vector<int>> &dag) {
    std::vector<int> indegree(dag.size(), 0);
    for (const auto &succs : dag)
        for (int succ : succs) ++indegree[succ];

    std::queue<int> ready;
    for (int i = 0; i < static_cast<int>(dag.size()); ++i)
        if (indegree[i] == 0) ready.push(i);

    std::vector<int> order;
    while (!ready.empty()) {
        int node = ready.front();
        ready.pop();
        order.push_back(node);
        for (int succ : dag[node]) {
            if (--indegree[succ] == 0)
                ready.push(succ);
        }
    }
    return order;
}

SccGraph condense_graph(const std::vector<std::vector<int>> &adj) {
    const int n = static_cast<int>(adj.size());
    int next_index = 0;
    std::vector<int> index(n, -1);
    std::vector<int> lowlink(n, 0);
    std::vector<int> stack;
    std::vector<char> on_stack(n, false);
    std::vector<int> node_to_scc(n, -1);
    std::vector<std::vector<int>> members;

    std::function<void(int)> visit = [&](int v) {
        index[v] = lowlink[v] = next_index++;
        stack.push_back(v);
        on_stack[v] = true;

        for (int w : adj[v]) {
            if (index[w] == -1) {
                visit(w);
                lowlink[v] = std::min(lowlink[v], lowlink[w]);
            } else if (on_stack[w]) {
                lowlink[v] = std::min(lowlink[v], index[w]);
            }
        }

        if (lowlink[v] != index[v]) return;

        int scc = static_cast<int>(members.size());
        members.emplace_back();
        while (true) {
            int w = stack.back();
            stack.pop_back();
            on_stack[w] = false;
            node_to_scc[w] = scc;
            members.back().push_back(w);
            if (w == v) break;
        }
    };

    for (int v = 0; v < n; ++v)
        if (index[v] == -1) visit(v);

    std::set<std::pair<int, int>> dag_edges;
    for (int from = 0; from < n; ++from) {
        int from_scc = node_to_scc[from];
        for (int to : adj[from]) {
            int to_scc = node_to_scc[to];
            if (from_scc != to_scc)
                dag_edges.emplace(from_scc, to_scc);
        }
    }

    std::vector<std::vector<int>> dag(members.size());
    for (const auto &[from, to] : dag_edges)
        dag[from].push_back(to);

    return {std::move(node_to_scc), std::move(members), std::move(dag)};
}

std::vector<std::size_t> reachability_counts(
    const SccGraph &scc,
    const std::vector<std::size_t> &scc_sizes,
    const std::vector<int> &topo
) {
    const int n = static_cast<int>(scc.dag.size());
    std::vector<std::size_t> counts(n, 0);
    std::size_t total_scc_size = 0;
    for (std::size_t size : scc_sizes)
        total_scc_size += size;

    // Exact bitset DP is fast enough for normal dump sizes and avoids duplicate
    // counting on DAG joins. For very large all-function dumps, fall back to a
    // duplicate-tolerant descendant estimate; dominator size remains exact and
    // is the primary ranking signal.
    constexpr int max_exact_sccs = 8192;
    if (n > max_exact_sccs) {
        for (auto it = topo.rbegin(); it != topo.rend(); ++it) {
            int node = *it;
            std::size_t total = scc_sizes[node];
            for (int succ : scc.dag[node])
                total += counts[succ];
            counts[node] = std::min(total, total_scc_size);
        }
        return counts;
    }

    const int words = (n + 63) / 64;
    std::vector<std::vector<std::uint64_t>> reach(
        n, std::vector<std::uint64_t>(words, 0));

    auto set_bit = [&](int node, int bit) {
        reach[node][bit / 64] |= (std::uint64_t{1} << (bit % 64));
    };
    auto test_bit = [&](int node, int bit) {
        return (reach[node][bit / 64] & (std::uint64_t{1} << (bit % 64))) != 0;
    };

    for (auto it = topo.rbegin(); it != topo.rend(); ++it) {
        int node = *it;
        set_bit(node, node);
        for (int succ : scc.dag[node]) {
            for (int w = 0; w < words; ++w)
                reach[node][w] |= reach[succ][w];
        }
    }

    for (int node = 0; node < n; ++node) {
        std::size_t total = 0;
        for (int bit = 0; bit < n; ++bit)
            if (test_bit(node, bit)) total += scc_sizes[bit];
        counts[node] = total;
    }

    return counts;
}

std::vector<std::size_t> dominator_subtree_sizes(
    const SccGraph &scc,
    const std::vector<std::size_t> &scc_sizes,
    const std::set<int> &anchor_sccs,
    std::vector<int> *out_depth
) {
    const int root = static_cast<int>(scc.dag.size());
    const int total_nodes = root + 1;

    std::vector<std::vector<int>> graph(total_nodes);
    std::vector<std::vector<int>> preds(total_nodes);
    for (int node = 0; node < root; ++node) {
        graph[node] = scc.dag[node];
        for (int succ : graph[node])
            preds[succ].push_back(node);
    }

    std::vector<int> indegree(root, 0);
    for (int node = 0; node < root; ++node)
        for (int succ : scc.dag[node]) ++indegree[succ];

    std::set<int> roots = anchor_sccs;
    for (int node = 0; node < root; ++node)
        if (indegree[node] == 0) roots.insert(node);

    for (int node : roots) {
        graph[root].push_back(node);
        preds[node].push_back(root);
    }

    std::vector<int> order = topological_order(graph);
    std::vector<int> idom(total_nodes, -1);
    idom[root] = root;

    auto intersect = [&](int a, int b) {
        std::unordered_set<int> ancestors;
        while (a != idom[a]) {
            ancestors.insert(a);
            a = idom[a];
        }
        ancestors.insert(a);

        while (!ancestors.count(b))
            b = idom[b];
        return b;
    };

    bool changed = true;
    while (changed) {
        changed = false;
        for (int node : order) {
            if (node == root) continue;

            int new_idom = -1;
            for (int pred : preds[node]) {
                if (idom[pred] == -1) continue;
                new_idom = new_idom == -1 ? pred : intersect(pred, new_idom);
            }

            if (new_idom != -1 && idom[node] != new_idom) {
                idom[node] = new_idom;
                changed = true;
            }
        }
    }

    std::vector<std::vector<int>> children(total_nodes);
    for (int node = 0; node < total_nodes; ++node) {
        if (node == root || idom[node] == -1) continue;
        children[idom[node]].push_back(node);
    }

    std::vector<std::size_t> subtree(total_nodes, 0);
    std::function<std::size_t(int)> dfs_size = [&](int node) {
        std::size_t total = node < root ? scc_sizes[node] : 0;
        for (int child : children[node])
            total += dfs_size(child);
        subtree[node] = total;
        return total;
    };
    dfs_size(root);

    std::vector<int> depth(total_nodes, std::numeric_limits<int>::max());
    std::queue<int> ready;
    depth[root] = 0;
    ready.push(root);
    while (!ready.empty()) {
        int node = ready.front();
        ready.pop();
        for (int succ : graph[node]) {
            if (depth[node] + 1 < depth[succ]) {
                depth[succ] = depth[node] + 1;
                ready.push(succ);
            }
        }
    }
    if (out_depth) *out_depth = std::move(depth);

    subtree.resize(root);
    return subtree;
}

WeightedGraph build_weighted_graph(
    const std::vector<ida::Address> &ordered,
    const std::unordered_map<ida::Address, int> &index_by_ea,
    const std::vector<Edge> &edges,
    const std::vector<NodeSignals> &signals
) {
    std::map<std::pair<int, int>, double> weights;

    auto add_weight = [&](int from, int to, double weight) {
        if (from == to || weight <= 0.0) return;
        if (signals[from].system) weight *= 0.1;
        if (signals[to].system) weight *= 0.1;
        weights[std::make_pair(from, to)] += weight;
    };

    for (int to = 0; to < static_cast<int>(ordered.size()); ++to) {
        ida::Result<std::vector<ida::xref::Reference>> refs =
            ida::xref::refs_to(ordered[to]);
        if (!refs) continue;

        for (const ida::xref::Reference &xref : *refs) {
            if (!ida::xref::is_call(xref.type) && !ida::xref::is_jump(xref.type))
                continue;
            std::optional<ida::Address> caller = function_start(xref.from);
            if (!caller || function_is_thunk(*caller)) continue;
            auto it = index_by_ea.find(*caller);
            if (it == index_by_ea.end()) continue;
            add_weight(it->second, to, 1.0);
        }
    }

    for (const Edge &edge : edges) {
        double confidence = resolved_edge_confidence(edge);
        if (confidence <= 0.0) continue;
        auto from_it = index_by_ea.find(edge.from);
        auto to_it = index_by_ea.find(edge.to);
        if (from_it == index_by_ea.end() || to_it == index_by_ea.end()) continue;
        add_weight(from_it->second, to_it->second, confidence);
    }

    WeightedGraph graph;
    graph.out.resize(ordered.size());
    graph.in.resize(ordered.size());
    graph.indegree.assign(ordered.size(), 0.0);
    graph.outdegree.assign(ordered.size(), 0.0);

    for (const auto &[key, weight] : weights) {
        int from = key.first;
        int to = key.second;
        graph.out[from].emplace_back(to, weight);
        graph.in[to].emplace_back(from, weight);
        graph.outdegree[from] += weight;
        graph.indegree[to] += weight;
    }

    return graph;
}

std::vector<std::vector<int>> unweighted_adj(const WeightedGraph &graph) {
    std::vector<std::vector<int>> adj(graph.out.size());
    for (int from = 0; from < static_cast<int>(graph.out.size()); ++from) {
        for (const auto &[to, _] : graph.out[from])
            adj[from].push_back(to);
    }
    return adj;
}

std::vector<double> normalized_personalization(
    const std::vector<NodeSignals> &signals
) {
    std::vector<double> p(signals.size(), 0.0);
    double total = 0.0;
    for (int i = 0; i < static_cast<int>(signals.size()); ++i) {
        if (!signals[i].anchor) continue;
        p[i] = signals[i].system ? 0.1 : 1.0;
        total += p[i];
    }
    if (total == 0.0) {
        for (int i = 0; i < static_cast<int>(signals.size()); ++i) {
            p[i] = signals[i].system ? 0.1 : 1.0;
            total += p[i];
        }
    }
    if (total == 0.0) return p;
    for (double &value : p) value /= total;
    return p;
}

std::vector<double> uniform_personalization(
    const std::vector<NodeSignals> &signals
) {
    std::vector<double> p(signals.size(), 0.0);
    double total = 0.0;
    for (int i = 0; i < static_cast<int>(signals.size()); ++i) {
        p[i] = signals[i].system ? 0.1 : 1.0;
        total += p[i];
    }
    if (total == 0.0) return p;
    for (double &value : p) value /= total;
    return p;
}

std::vector<double> pagerank(
    const std::vector<std::vector<std::pair<int, double>>> &out,
    const std::vector<std::vector<std::pair<int, double>>> &in,
    const std::vector<double> &outdegree,
    const std::vector<double> &personalization,
    double alpha = 0.85,
    int max_iter = 80,
    double tolerance = 1e-10
) {
    const int n = static_cast<int>(out.size());
    std::vector<double> rank(n, n ? 1.0 / static_cast<double>(n) : 0.0);
    std::vector<double> next(n, 0.0);

    for (int iter = 0; iter < max_iter; ++iter) {
        double dangling = 0.0;
        for (int i = 0; i < n; ++i)
            if (out[i].empty() || outdegree[i] <= 0.0)
                dangling += rank[i];

        double diff = 0.0;
        for (int i = 0; i < n; ++i) {
            double value = (1.0 - alpha) * personalization[i]
                + alpha * dangling * personalization[i];
            for (const auto &[pred, weight] : in[i]) {
                if (outdegree[pred] > 0.0)
                    value += alpha * rank[pred] * (weight / outdegree[pred]);
            }
            next[i] = value;
            diff += std::abs(next[i] - rank[i]);
        }

        rank.swap(next);
        if (diff < tolerance) break;
    }
    return rank;
}

std::vector<double> pagerank_reversed(
    const WeightedGraph &graph,
    const std::vector<double> &personalization
) {
    return pagerank(graph.in, graph.out, graph.indegree, personalization);
}

std::pair<std::vector<double>, std::vector<double>> hits(
    const WeightedGraph &graph,
    int max_iter = 80,
    double tolerance = 1e-10
) {
    const int n = static_cast<int>(graph.out.size());
    std::vector<double> hubs(n, n ? 1.0 / static_cast<double>(n) : 0.0);
    std::vector<double> auth(n, n ? 1.0 / static_cast<double>(n) : 0.0);
    std::vector<double> next_hubs(n, 0.0), next_auth(n, 0.0);

    auto normalize = [](std::vector<double> &values) {
        double norm = 0.0;
        for (double value : values) norm += value * value;
        norm = std::sqrt(norm);
        if (norm == 0.0) return;
        for (double &value : values) value /= norm;
    };

    for (int iter = 0; iter < max_iter; ++iter) {
        std::fill(next_auth.begin(), next_auth.end(), 0.0);
        std::fill(next_hubs.begin(), next_hubs.end(), 0.0);

        for (int node = 0; node < n; ++node) {
            for (const auto &[pred, weight] : graph.in[node])
                next_auth[node] += hubs[pred] * weight;
            for (const auto &[succ, weight] : graph.out[node])
                next_hubs[node] += auth[succ] * weight;
        }
        normalize(next_auth);
        normalize(next_hubs);

        double diff = 0.0;
        for (int i = 0; i < n; ++i) {
            diff += std::abs(next_auth[i] - auth[i]);
            diff += std::abs(next_hubs[i] - hubs[i]);
        }
        auth.swap(next_auth);
        hubs.swap(next_hubs);
        if (diff < tolerance) break;
    }

    return {hubs, auth};
}

std::vector<int> deterministic_pivots(int n, int max_pivots) {
    std::vector<int> pivots;
    int k = std::min(n, max_pivots);
    if (k <= 0) return pivots;
    pivots.reserve(k);
    std::set<int> seen;
    for (int i = 0; i < k; ++i) {
        int pivot = static_cast<int>((static_cast<long long>(i) * n) / k);
        if (seen.insert(pivot).second)
            pivots.push_back(pivot);
    }
    return pivots;
}

std::vector<double> sampled_betweenness(
    const std::vector<std::vector<int>> &adj
) {
    const int n = static_cast<int>(adj.size());
    std::vector<double> bc(n, 0.0);
    if (n < 3) return bc;

    int max_pivots = n <= 2048 ? n : 512;
    std::vector<int> pivots = deterministic_pivots(n, max_pivots);

    std::vector<std::vector<int>> predecessors(n);
    std::vector<int> distance(n, -1);
    std::vector<double> sigma(n, 0.0);
    std::vector<double> delta(n, 0.0);

    for (int source : pivots) {
        for (auto &p : predecessors) p.clear();
        std::fill(distance.begin(), distance.end(), -1);
        std::fill(sigma.begin(), sigma.end(), 0.0);
        std::fill(delta.begin(), delta.end(), 0.0);

        std::vector<int> stack;
        std::queue<int> queue;
        distance[source] = 0;
        sigma[source] = 1.0;
        queue.push(source);

        while (!queue.empty()) {
            int v = queue.front();
            queue.pop();
            stack.push_back(v);
            for (int w : adj[v]) {
                if (distance[w] < 0) {
                    distance[w] = distance[v] + 1;
                    queue.push(w);
                }
                if (distance[w] == distance[v] + 1) {
                    sigma[w] += sigma[v];
                    predecessors[w].push_back(v);
                }
            }
        }

        while (!stack.empty()) {
            int w = stack.back();
            stack.pop_back();
            for (int v : predecessors[w]) {
                if (sigma[w] != 0.0)
                    delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w]);
            }
            if (w != source)
                bc[w] += delta[w];
        }
    }

    double scale = 1.0;
    if (!pivots.empty())
        scale = static_cast<double>(n) / static_cast<double>(pivots.size());
    double norm = (static_cast<double>(n - 1) * static_cast<double>(n - 2));
    for (double &value : bc)
        value = norm > 0.0 ? (value * scale / norm) : 0.0;
    return bc;
}

std::pair<std::vector<double>, std::vector<double>> harmonic_centrality(
    const std::vector<std::vector<int>> &adj
) {
    const int n = static_cast<int>(adj.size());
    std::vector<double> out_harm(n, 0.0);
    std::vector<double> in_harm(n, 0.0);
    if (n > 4096) return {out_harm, in_harm};

    std::vector<int> distance(n, -1);
    for (int source = 0; source < n; ++source) {
        std::fill(distance.begin(), distance.end(), -1);
        std::queue<int> queue;
        distance[source] = 0;
        queue.push(source);
        while (!queue.empty()) {
            int v = queue.front();
            queue.pop();
            for (int w : adj[v]) {
                if (distance[w] >= 0) continue;
                distance[w] = distance[v] + 1;
                queue.push(w);
                double contribution = 1.0 / static_cast<double>(distance[w]);
                out_harm[source] += contribution;
                in_harm[w] += contribution;
            }
        }
    }
    return {out_harm, in_harm};
}

std::vector<double> coreness(
    const std::vector<std::vector<int>> &adj
) {
    const int n = static_cast<int>(adj.size());
    std::vector<std::set<int>> undirected(n);
    for (int from = 0; from < n; ++from) {
        for (int to : adj[from]) {
            if (from == to) continue;
            undirected[from].insert(to);
            undirected[to].insert(from);
        }
    }

    std::vector<int> degree(n, 0);
    std::vector<char> active(n, true);
    using Item = std::pair<int, int>;
    std::priority_queue<Item, std::vector<Item>, std::greater<Item>> heap;
    for (int i = 0; i < n; ++i) {
        degree[i] = static_cast<int>(undirected[i].size());
        heap.emplace(degree[i], i);
    }

    std::vector<double> core(n, 0.0);
    while (!heap.empty()) {
        auto [deg, node] = heap.top();
        heap.pop();
        if (!active[node] || deg != degree[node]) continue;
        active[node] = false;
        core[node] = static_cast<double>(deg);
        for (int neigh : undirected[node]) {
            if (!active[neigh]) continue;
            if (degree[neigh] > deg)
                --degree[neigh];
            heap.emplace(degree[neigh], neigh);
        }
    }
    return core;
}

std::vector<double> sized_metric(
    const std::vector<NodeSignals> &signals
) {
    std::vector<double> result(signals.size(), 0.0);
    for (int i = 0; i < static_cast<int>(signals.size()); ++i)
        result[i] = static_cast<double>(signals[i].function_size);
    return result;
}

bool is_global_data_address(ida::Address ea) {
    ida::Result<ida::segment::Segment> segment = ida::segment::at(ea);
    return segment && !segment->permissions().execute;
}

std::vector<double> shared_state_coupling(
    const std::vector<ida::Address> &ordered
) {
    std::vector<double> coupling(ordered.size(), 0.0);
    if (ordered.size() > 20000) return coupling;

    std::unordered_map<ida::Address, std::vector<int>> global_to_funcs;
    for (int i = 0; i < static_cast<int>(ordered.size()); ++i) {
        ida::Result<ida::function::Function> function = ida::function::at(ordered[i]);
        if (!function) continue;

        std::unordered_set<ida::Address> globals;
        ida::Address start = static_cast<ida::Address>(function->start());
        ida::Address end = static_cast<ida::Address>(function->end());
        for (ida::Address ea = start; ea < end && ea != ida::BadAddress; ) {
            ida::Result<std::vector<ida::xref::Reference>> refs =
                ida::xref::data_refs_from(ea);
            if (refs) {
                for (const ida::xref::Reference &xref : *refs) {
                    if (is_global_data_address(xref.to))
                        globals.insert(xref.to);
                }
            }

            ida::Result<ida::Address> next = ida::address::next_head(ea, end);
            if (!next || *next == ida::BadAddress || *next <= ea) break;
            ea = static_cast<ida::Address>(*next);
        }

        for (ida::Address global : globals)
            global_to_funcs[global].push_back(i);
    }

    for (const auto &[_, funcs] : global_to_funcs) {
        if (funcs.size() < 2) continue;
        double contribution = static_cast<double>(funcs.size() - 1);
        for (int func : funcs)
            coupling[func] += contribution;
    }
    return coupling;
}

void add_rrf_channel(
    const std::vector<double> &score,
    std::vector<double> &rrf,
    double weight = 1.0
) {
    bool any_nonzero = false;
    for (double value : score) {
        if (value != 0.0 && std::isfinite(value)) {
            any_nonzero = true;
            break;
        }
    }
    if (!any_nonzero) return;

    std::vector<int> order(score.size());
    std::iota(order.begin(), order.end(), 0);
    std::sort(order.begin(), order.end(), [&](int a, int b) {
        double av = std::isfinite(score[a]) ? score[a] : 0.0;
        double bv = std::isfinite(score[b]) ? score[b] : 0.0;
        if (av != bv) return av > bv;
        return a < b;
    });

    constexpr double k = 60.0;
    for (int rank = 0; rank < static_cast<int>(order.size()); ++rank)
        rrf[order[rank]] += weight / (k + static_cast<double>(rank + 1));
}

} // namespace

std::vector<ida::Address> order_functions_by_address(
    const std::set<ida::Address> &functions
) {
    return std::vector<ida::Address>(functions.begin(), functions.end());
}

std::vector<ida::Address> order_functions_by_entryness(
    const std::set<ida::Address> &functions,
    const std::vector<Edge> &edges,
    const std::set<ida::Address> &start_functions
) {
    std::vector<ida::Address> ordered = order_functions_by_address(functions);
    if (ordered.size() < 2) return ordered;

    std::unordered_map<ida::Address, int> index_by_ea;
    for (int i = 0; i < static_cast<int>(ordered.size()); ++i)
        index_by_ea.emplace(ordered[i], i);

    std::vector<NodeSignals> signals(ordered.size());
    for (int i = 0; i < static_cast<int>(ordered.size()); ++i) {
        ida::Address ea = ordered[i];
        signals[i].anchor = start_functions.count(ea) != 0;
        signals[i].system = is_system_function(ea);
        signals[i].function_size = function_size(ea);
    }
    mark_entry_anchors(index_by_ea, signals);

    std::vector<std::vector<int>> adj(ordered.size());
    auto add_graph_edge = [&](int from, int to) {
        if (from == to) return;
        adj[from].push_back(to);
    };

    for (const Edge &edge : edges) {
        auto from_it = index_by_ea.find(edge.from);
        auto to_it = index_by_ea.find(edge.to);
        if (to_it == index_by_ea.end()) continue;

        if (is_address_taken_edge(edge))
            signals[to_it->second].address_taken = true;

        if (from_it == index_by_ea.end()) continue;
        if (!is_resolved_call_edge(edge)) continue;
        if (signals[from_it->second].system) continue;

        add_graph_edge(from_it->second, to_it->second);
        if (is_strong_call_edge(edge))
            signals[to_it->second].callers.insert(edge.from);
    }

    for (int to = 0; to < static_cast<int>(ordered.size()); ++to) {
        ida::Result<std::vector<ida::xref::Reference>> refs =
            ida::xref::refs_to(ordered[to]);
        if (!refs) continue;

        for (const ida::xref::Reference &xref : *refs) {
            if (xref.from == ida::BadAddress) continue;

            if (xref.type == ida::xref::ReferenceType::Offset) {
                signals[to].address_taken = true;
                continue;
            }

            if (!ida::xref::is_call(xref.type) && !ida::xref::is_jump(xref.type))
                continue;

            std::optional<ida::Address> caller = function_start(xref.from);
            if (!caller || *caller == ordered[to]) continue;
            if (function_is_thunk(*caller) || is_system_function(*caller)) continue;

            signals[to].callers.insert(*caller);
            auto caller_it = index_by_ea.find(*caller);
            if (caller_it != index_by_ea.end())
                add_graph_edge(caller_it->second, to);
        }
    }

    for (auto &succs : adj) {
        std::sort(succs.begin(), succs.end());
        succs.erase(std::unique(succs.begin(), succs.end()), succs.end());
    }

    SccGraph scc = condense_graph(adj);
    std::vector<std::size_t> scc_sizes(scc.members.size(), 0);
    std::set<int> anchor_sccs;
    for (int scc_index = 0; scc_index < static_cast<int>(scc.members.size()); ++scc_index) {
        for (int member : scc.members[scc_index]) {
            ++scc_sizes[scc_index];
            if (signals[member].anchor)
                anchor_sccs.insert(scc_index);
        }
    }

    std::vector<int> topo = topological_order(scc.dag);
    std::vector<std::size_t> reach = reachability_counts(scc, scc_sizes, topo);
    std::vector<int> scc_depth;
    std::vector<std::size_t> dom =
        dominator_subtree_sizes(scc, scc_sizes, anchor_sccs, &scc_depth);

    std::size_t max_reach = std::max<std::size_t>(1, *std::max_element(reach.begin(), reach.end()));
    std::size_t max_dom = std::max<std::size_t>(1, *std::max_element(dom.begin(), dom.end()));
    int max_depth = 1;
    for (int d : scc_depth)
        if (d != std::numeric_limits<int>::max())
            max_depth = std::max(max_depth, d);

    std::vector<std::size_t> caller_counts(ordered.size(), 0);
    for (int i = 0; i < static_cast<int>(ordered.size()); ++i) {
        int my_scc = scc.node_to_scc[i];
        std::size_t count = 0;
        for (ida::Address caller : signals[i].callers) {
            auto it = index_by_ea.find(caller);
            if (it != index_by_ea.end()
                && scc.node_to_scc[it->second] == my_scc)
                continue;
            ++count;
        }
        caller_counts[i] = count;
    }

    struct Ranked {
        ida::Address ea;
        double score = 0.0;
        std::size_t callers = 0;
        std::size_t dom = 0;
        std::size_t reach = 0;
        std::size_t function_size = 0;
        int depth = 0;
        bool anchor = false;
        bool address_taken_uncalled = false;
        bool system = false;
    };

    std::vector<Ranked> ranked;
    ranked.reserve(ordered.size());
    for (int i = 0; i < static_cast<int>(ordered.size()); ++i) {
        int node_scc = scc.node_to_scc[i];
        int depth = scc_depth[node_scc] == std::numeric_limits<int>::max()
            ? max_depth
            : scc_depth[node_scc];
        bool address_taken_uncalled =
            signals[i].address_taken && caller_counts[i] == 0;

        double depth_norm = static_cast<double>(depth) / static_cast<double>(max_depth);
        double score =
            3.0 * static_cast<double>(signals[i].anchor)
            + 1.5 * static_cast<double>(address_taken_uncalled)
            + 1.0 / static_cast<double>(1 + caller_counts[i])
            + 2.0 * (static_cast<double>(reach[node_scc]) / static_cast<double>(max_reach))
            + 3.0 * (static_cast<double>(dom[node_scc]) / static_cast<double>(max_dom))
            + 0.25 * (1.0 - depth_norm);

        if (signals[i].system)
            score -= 4.0;

        ranked.push_back({
            ordered[i],
            score,
            caller_counts[i],
            dom[node_scc],
            reach[node_scc],
            signals[i].function_size,
            depth,
            signals[i].anchor,
            address_taken_uncalled,
            signals[i].system
        });
    }

    std::sort(ranked.begin(), ranked.end(), [](const Ranked &a, const Ranked &b) {
        if (a.score != b.score) return a.score > b.score;
        if (a.anchor != b.anchor) return a.anchor;
        if (a.address_taken_uncalled != b.address_taken_uncalled)
            return a.address_taken_uncalled;
        if (a.system != b.system) return !a.system;
        if (a.callers != b.callers) return a.callers < b.callers;
        if (a.dom != b.dom) return a.dom > b.dom;
        if (a.reach != b.reach) return a.reach > b.reach;
        if (a.function_size != b.function_size) return a.function_size > b.function_size;
        if (a.depth != b.depth) return a.depth < b.depth;
        return a.ea < b.ea;
    });

    ordered.clear();
    ordered.reserve(ranked.size());
    for (const Ranked &entry : ranked)
        ordered.push_back(entry.ea);
    return ordered;
}

std::vector<ida::Address> order_functions_by_centrality(
    const std::set<ida::Address> &functions,
    const std::vector<Edge> &edges,
    const std::set<ida::Address> &start_functions
) {
    std::vector<ida::Address> ordered = order_functions_by_address(functions);
    if (ordered.size() < 2) return ordered;

    std::unordered_map<ida::Address, int> index_by_ea;
    for (int i = 0; i < static_cast<int>(ordered.size()); ++i)
        index_by_ea.emplace(ordered[i], i);

    std::vector<NodeSignals> signals(ordered.size());
    for (int i = 0; i < static_cast<int>(ordered.size()); ++i) {
        ida::Address ea = ordered[i];
        signals[i].anchor = start_functions.count(ea) != 0;
        signals[i].system = is_system_function(ea);
        signals[i].function_size = function_size(ea);
    }
    mark_entry_anchors(index_by_ea, signals);

    for (const Edge &edge : edges) {
        if (!is_address_taken_edge(edge)) continue;
        auto it = index_by_ea.find(edge.to);
        if (it != index_by_ea.end())
            signals[it->second].address_taken = true;
    }

    for (int to = 0; to < static_cast<int>(ordered.size()); ++to) {
        ida::Result<std::vector<ida::xref::Reference>> refs =
            ida::xref::refs_to(ordered[to]);
        if (!refs) continue;
        for (const ida::xref::Reference &xref : *refs) {
            if (xref.type == ida::xref::ReferenceType::Offset)
                signals[to].address_taken = true;
        }
    }

    WeightedGraph graph = build_weighted_graph(ordered, index_by_ea, edges, signals);
    std::vector<std::vector<int>> adj = unweighted_adj(graph);

    std::vector<double> personalization = uniform_personalization(signals);
    std::vector<double> pr_authority = pagerank(
        graph.out, graph.in, graph.outdegree, personalization);
    std::vector<double> pr_orchestrator = pagerank_reversed(graph, personalization);

    std::vector<double> seeded = normalized_personalization(signals);
    bool has_anchor_seed = false;
    for (const NodeSignals &signal : signals)
        if (signal.anchor) has_anchor_seed = true;
    if (!has_anchor_seed)
        seeded = normalized_personalization(signals);
    std::vector<double> pr_seeded = pagerank(
        graph.out, graph.in, graph.outdegree, seeded);

    auto [hits_hubs, hits_auth] = hits(graph);
    std::vector<double> betweenness = sampled_betweenness(adj);
    auto [harm_out, harm_in] = harmonic_centrality(adj);
    std::vector<double> core = coreness(adj);
    std::vector<double> state_coupling = shared_state_coupling(ordered);

    SccGraph scc = condense_graph(adj);
    std::vector<std::size_t> scc_sizes(scc.members.size(), 0);
    std::set<int> anchor_sccs;
    for (int scc_index = 0; scc_index < static_cast<int>(scc.members.size()); ++scc_index) {
        for (int member : scc.members[scc_index]) {
            ++scc_sizes[scc_index];
            if (signals[member].anchor)
                anchor_sccs.insert(scc_index);
        }
    }
    std::vector<int> topo = topological_order(scc.dag);
    std::vector<std::size_t> reach = reachability_counts(scc, scc_sizes, topo);
    std::vector<int> scc_depth;
    std::vector<std::size_t> dom =
        dominator_subtree_sizes(scc, scc_sizes, anchor_sccs, &scc_depth);

    std::vector<double> reach_metric(ordered.size(), 0.0);
    std::vector<double> dom_metric(ordered.size(), 0.0);
    std::vector<double> address_taken_metric(ordered.size(), 0.0);
    std::vector<double> anchor_metric(ordered.size(), 0.0);
    for (int i = 0; i < static_cast<int>(ordered.size()); ++i) {
        int node_scc = scc.node_to_scc[i];
        reach_metric[i] = static_cast<double>(reach[node_scc]);
        dom_metric[i] = static_cast<double>(dom[node_scc]);
        address_taken_metric[i] = signals[i].address_taken ? 1.0 : 0.0;
        anchor_metric[i] = signals[i].anchor ? 1.0 : 0.0;
    }

    std::vector<double> rrf(ordered.size(), 0.0);
    add_rrf_channel(graph.indegree, rrf);
    add_rrf_channel(graph.outdegree, rrf);
    add_rrf_channel(pr_authority, rrf, 1.25);
    add_rrf_channel(pr_orchestrator, rrf, 1.1);
    add_rrf_channel(pr_seeded, rrf, 1.5);
    add_rrf_channel(hits_auth, rrf, 1.2);
    add_rrf_channel(hits_hubs, rrf, 1.1);
    add_rrf_channel(betweenness, rrf, 1.25);
    add_rrf_channel(harm_in, rrf);
    add_rrf_channel(harm_out, rrf);
    add_rrf_channel(core, rrf);
    add_rrf_channel(state_coupling, rrf, 0.8);
    add_rrf_channel(reach_metric, rrf);
    add_rrf_channel(dom_metric, rrf, 1.1);
    add_rrf_channel(address_taken_metric, rrf, 0.35);
    add_rrf_channel(anchor_metric, rrf, 0.35);
    add_rrf_channel(sized_metric(signals), rrf, 0.4);

    struct Ranked {
        ida::Address ea;
        double score = 0.0;
        double seeded = 0.0;
        double authority = 0.0;
        double hub = 0.0;
        double betweenness = 0.0;
        double indegree = 0.0;
        double outdegree = 0.0;
        std::size_t function_size = 0;
        bool system = false;
    };

    std::vector<Ranked> ranked;
    ranked.reserve(ordered.size());
    for (int i = 0; i < static_cast<int>(ordered.size()); ++i) {
        double score = rrf[i];
        if (signals[i].system)
            score *= 0.25;
        ranked.push_back({
            ordered[i],
            score,
            pr_seeded[i],
            hits_auth[i],
            hits_hubs[i],
            betweenness[i],
            graph.indegree[i],
            graph.outdegree[i],
            signals[i].function_size,
            signals[i].system
        });
    }

    std::sort(ranked.begin(), ranked.end(), [](const Ranked &a, const Ranked &b) {
        if (a.score != b.score) return a.score > b.score;
        if (a.system != b.system) return !a.system;
        if (a.seeded != b.seeded) return a.seeded > b.seeded;
        if (a.authority != b.authority) return a.authority > b.authority;
        if (a.hub != b.hub) return a.hub > b.hub;
        if (a.betweenness != b.betweenness) return a.betweenness > b.betweenness;
        if (a.indegree != b.indegree) return a.indegree > b.indegree;
        if (a.outdegree != b.outdegree) return a.outdegree > b.outdegree;
        if (a.function_size != b.function_size) return a.function_size > b.function_size;
        return a.ea < b.ea;
    });

    ordered.clear();
    ordered.reserve(ranked.size());
    for (const Ranked &entry : ranked)
        ordered.push_back(entry.ea);
    return ordered;
}

std::vector<ida::Address> order_functions(
    const std::set<ida::Address> &functions,
    const std::vector<Edge> &edges,
    const std::set<ida::Address> &start_functions,
    FunctionOrder order
) {
    switch (order) {
        case FunctionOrder::Entryness:
            return order_functions_by_entryness(functions, edges, start_functions);
        case FunctionOrder::Centrality:
            return order_functions_by_centrality(functions, edges, start_functions);
        case FunctionOrder::Address:
        default:
            return order_functions_by_address(functions);
    }
}

} // namespace codedump
