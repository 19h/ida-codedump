#include "subsystem_clusterer.h"

#include "common/function_filter.h"

#include <ida/address.hpp>
#include <ida/database.hpp>
#include <ida/function.hpp>
#include <ida/segment.hpp>
#include <ida/xref.hpp>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <format>
#include <functional>
#include <map>
#include <numeric>
#include <optional>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace codedump {

namespace {

using Resource = ida::Address;

struct NodeFeatures {
    std::vector<Resource> globals;
    std::vector<Resource> imports;
    std::map<std::string, int> import_families;
    int call_fanin = 0;
    bool system = false;
};

struct WeightedGraph {
    std::vector<std::vector<std::pair<int, double>>> adj;
    std::vector<double> degree;
    double total_weight = 0.0;
};

std::optional<ida::Address> function_start(ida::Address ea) {
    ida::Result<ida::function::Function> function = ida::function::at(ea);
    if (!function) return std::nullopt;
    return static_cast<ida::Address>(function->start());
}

bool is_call_or_jump(ida::xref::ReferenceType type) {
    return ida::xref::is_call(type) || ida::xref::is_jump(type);
}

bool is_global_data_address(ida::Address ea) {
    ida::Result<ida::segment::Segment> segment = ida::segment::at(ea);
    return segment && !segment->permissions().execute;
}

std::string lower_ascii(std::string_view text) {
    std::string out{text};
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

std::string import_family(std::string_view raw_name) {
    std::string name = lower_ascii(raw_name);
    auto has = [&](std::string_view needle) {
        return name.find(needle) != std::string::npos;
    };

    if (has("crypt") || has("ssl") || has("tls") || has("aes") ||
        has("sha") || has("md5") || has("rsa") || has("bcrypt"))
        return "crypto";
    if (has("recv") || has("send") || has("socket") || has("connect") ||
        has("bind") || has("listen") || has("accept") || has("http") ||
        has("inet") || has("dns") || has("net"))
        return "network";
    if (has("createfile") || has("readfile") || has("writefile") ||
        has("fopen") || has("fread") || has("fwrite") || has("open") ||
        has("read") || has("write") || has("stat"))
        return "file";
    if (has("malloc") || has("calloc") || has("realloc") || has("free") ||
        has("memcpy") || has("memmove") || has("memset") || has("heap"))
        return "memory";
    if (has("thread") || has("mutex") || has("criticalsection") ||
        has("waitfor") || has("event") || has("semaphore") || has("pthread"))
        return "threading";
    if (has("regopen") || has("regquery") || has("regset") || has("registry"))
        return "registry";
    if (has("window") || has("messagebox") || has("dialog") || has("user32") ||
        has("gdi") || has("direct") || has("gl") || has("render"))
        return "ui";
    if (has("compress") || has("inflate") || has("deflate") || has("zlib") ||
        has("lz") || has("zip"))
        return "compression";
    if (has("sql") || has("sqlite") || has("database") || has("db_"))
        return "database";
    if (has("printf") || has("puts") || has("log") || has("assert"))
        return "logging";
    return "api";
}

std::string function_prefix(std::string_view raw_name) {
    std::string name{raw_name};
    if (name.rfind("sub_", 0) == 0 || name.rfind("nullsub_", 0) == 0)
        return {};
    size_t cut = name.find_first_of("_:.");
    if (cut == std::string::npos || cut < 3) return {};
    return name.substr(0, cut);
}

std::map<ida::Address, std::string> import_names() {
    std::map<ida::Address, std::string> names;
    ida::Result<std::vector<ida::database::ImportModule>> modules =
        ida::database::import_modules();
    if (!modules) return names;

    for (const auto &module : *modules) {
        for (const auto &symbol : module.symbols) {
            if (symbol.address == ida::BadAddress) continue;
            names[symbol.address] = symbol.name.empty()
                ? module.name
                : symbol.name;
        }
    }
    return names;
}

void add_undirected(
    std::map<std::pair<int, int>, double> &weights,
    int a,
    int b,
    double value) {
    if (a == b || value <= 0.0) return;
    if (a > b) std::swap(a, b);
    weights[std::make_pair(a, b)] += value;
}

WeightedGraph materialize_graph(
    int n,
    const std::map<std::pair<int, int>, double> &weights) {
    WeightedGraph graph;
    graph.adj.resize(n);
    graph.degree.assign(n, 0.0);

    for (const auto &[edge, weight] : weights) {
        int a = edge.first;
        int b = edge.second;
        graph.adj[a].emplace_back(b, weight);
        graph.adj[b].emplace_back(a, weight);
        graph.degree[a] += weight;
        graph.degree[b] += weight;
        graph.total_weight += weight;
    }
    return graph;
}

std::vector<int> core_numbers(const WeightedGraph &graph) {
    int n = static_cast<int>(graph.adj.size());
    std::vector<int> degree(n, 0);
    std::vector<char> active(n, true);
    using Item = std::pair<int, int>;
    std::priority_queue<Item, std::vector<Item>, std::greater<Item>> heap;

    for (int i = 0; i < n; ++i) {
        degree[i] = static_cast<int>(graph.adj[i].size());
        heap.emplace(degree[i], i);
    }

    std::vector<int> core(n, 0);
    while (!heap.empty()) {
        auto [deg, node] = heap.top();
        heap.pop();
        if (!active[node] || deg != degree[node]) continue;
        active[node] = false;
        core[node] = deg;
        for (const auto &[neigh, _] : graph.adj[node]) {
            if (!active[neigh]) continue;
            if (degree[neigh] > deg) --degree[neigh];
            heap.emplace(degree[neigh], neigh);
        }
    }
    return core;
}

std::vector<char> detect_utility_hubs(
    const std::vector<NodeFeatures> &features,
    const WeightedGraph &graph) {
    int n = static_cast<int>(features.size());
    std::vector<int> fanin;
    fanin.reserve(n);
    for (const auto &feature : features)
        fanin.push_back(feature.call_fanin);
    std::sort(fanin.begin(), fanin.end());

    int p98 = fanin.empty()
        ? 0
        : fanin[static_cast<size_t>(0.98 * static_cast<double>(fanin.size() - 1))];
    p98 = std::max(p98, 3);

    std::vector<int> core = core_numbers(graph);
    std::vector<char> utility(n, false);
    for (int i = 0; i < n; ++i) {
        if (features[i].system) {
            utility[i] = true;
        } else if (features[i].call_fanin >= p98 && core[i] <= 2) {
            utility[i] = true;
        }
    }
    return utility;
}

std::vector<int> louvain_local_move(
    const WeightedGraph &graph,
    const std::vector<char> &excluded,
    double resolution) {
    int n = static_cast<int>(graph.adj.size());
    std::vector<int> comm(n, -1);
    std::vector<double> total(n, 0.0);
    for (int i = 0; i < n; ++i) {
        if (excluded[i]) continue;
        comm[i] = i;
        total[i] = graph.degree[i];
    }

    double m2 = std::max(1e-9, 2.0 * graph.total_weight);
    bool moved = true;
    for (int sweep = 0; sweep < 25 && moved; ++sweep) {
        moved = false;
        for (int node = 0; node < n; ++node) {
            if (excluded[node] || graph.degree[node] == 0.0) continue;
            int old = comm[node];
            total[old] -= graph.degree[node];

            std::map<int, double> neighbor_weight;
            neighbor_weight[old] = 0.0;
            for (const auto &[neigh, weight] : graph.adj[node]) {
                if (excluded[neigh] || comm[neigh] < 0) continue;
                neighbor_weight[comm[neigh]] += weight;
            }

            int best = old;
            double best_gain = 0.0;
            for (const auto &[candidate, kin] : neighbor_weight) {
                double gain = kin
                    - resolution * graph.degree[node] * total[candidate] / m2;
                if (gain > best_gain + 1e-9 ||
                    (std::abs(gain - best_gain) <= 1e-9 && candidate < best)) {
                    best_gain = gain;
                    best = candidate;
                }
            }

            total[best] += graph.degree[node];
            if (best != old) {
                comm[node] = best;
                moved = true;
            } else {
                comm[node] = old;
            }
        }
    }

    std::map<int, int> compact;
    int next = 0;
    for (int i = 0; i < n; ++i) {
        if (comm[i] < 0) continue;
        auto [it, inserted] = compact.emplace(comm[i], next);
        if (inserted) ++next;
        comm[i] = it->second;
    }
    return comm;
}

std::vector<int> louvain_multilevel(
    const WeightedGraph &graph,
    const std::vector<char> &excluded,
    double resolution) {
    const int original_n = static_cast<int>(graph.adj.size());
    std::vector<int> original_to_active(original_n, -1);
    std::vector<int> active_to_original;
    active_to_original.reserve(original_n);

    for (int node = 0; node < original_n; ++node) {
        if (excluded[node]) continue;
        original_to_active[node] = static_cast<int>(active_to_original.size());
        active_to_original.push_back(node);
    }

    const int active_n = static_cast<int>(active_to_original.size());
    std::vector<int> final_cluster(original_n, -1);
    if (active_n == 0) return final_cluster;

    std::map<std::pair<int, int>, double> active_weights;
    for (int original = 0; original < original_n; ++original) {
        int active = original_to_active[original];
        if (active < 0) continue;
        for (const auto &[neigh_original, weight] : graph.adj[original]) {
            int neigh_active = original_to_active[neigh_original];
            if (neigh_active < 0 || active >= neigh_active) continue;
            add_undirected(active_weights, active, neigh_active, weight);
        }
    }

    WeightedGraph current = materialize_graph(active_n, active_weights);
    std::vector<std::vector<int>> members(active_n);
    for (int active = 0; active < active_n; ++active)
        members[active].push_back(active_to_original[active]);

    for (int level = 0; level < 8; ++level) {
        std::vector<char> none_excluded(current.adj.size(), false);
        std::vector<int> local = louvain_local_move(
            current, none_excluded, resolution);

        int community_count = 0;
        for (int c : local)
            community_count = std::max(community_count, c + 1);
        if (community_count <= 0) break;

        std::vector<std::vector<int>> next_members(community_count);
        for (int node = 0; node < static_cast<int>(members.size()); ++node) {
            int c = local[node];
            next_members[c].insert(next_members[c].end(),
                                   members[node].begin(), members[node].end());
        }

        members = std::move(next_members);
        if (community_count == static_cast<int>(current.adj.size()))
            break;

        std::map<std::pair<int, int>, double> next_weights;
        for (int node = 0; node < static_cast<int>(current.adj.size()); ++node) {
            int cn = local[node];
            for (const auto &[neigh, weight] : current.adj[node]) {
                if (node >= neigh) continue;
                int cm = local[neigh];
                if (cn == cm) continue;
                add_undirected(next_weights, cn, cm, weight);
            }
        }

        current = materialize_graph(community_count, next_weights);
        if (current.total_weight <= 0.0)
            break;
    }

    for (int cluster = 0; cluster < static_cast<int>(members.size()); ++cluster)
        for (int original : members[cluster])
            final_cluster[original] = cluster;

    return final_cluster;
}

void merge_tiny_clusters(
    std::vector<int> &cluster,
    const WeightedGraph &graph,
    const std::vector<char> &utility,
    int min_size = 2) {
    std::map<int, int> sizes;
    for (int c : cluster)
        if (c >= 0) ++sizes[c];

    for (int node = 0; node < static_cast<int>(cluster.size()); ++node) {
        int c = cluster[node];
        if (c < 0 || utility[node] || sizes[c] >= min_size) continue;

        std::map<int, double> by_cluster;
        for (const auto &[neigh, weight] : graph.adj[node]) {
            int nc = cluster[neigh];
            if (nc >= 0 && nc != c && !utility[neigh])
                by_cluster[nc] += weight;
        }
        if (by_cluster.empty()) continue;

        auto best = std::max_element(
            by_cluster.begin(), by_cluster.end(),
            [](const auto &a, const auto &b) {
                if (a.second != b.second) return a.second < b.second;
                return a.first > b.first;
            });
        --sizes[c];
        cluster[node] = best->first;
        ++sizes[best->first];
    }
}

std::string label_for_cluster(
    int cluster_id,
    const std::vector<int> &members,
    const std::vector<ida::Address> &ordered,
    const std::vector<NodeFeatures> &features,
    bool utility) {
    if (utility)
        return std::format("Utilities ({} funcs)", members.size());

    std::map<std::string, int> families;
    std::map<std::string, int> prefixes;
    for (int node : members) {
        for (const auto &[family, count] : features[node].import_families)
            families[family] += count;
        ida::Result<std::string> name = ida::function::name_at(ordered[node]);
        if (name) {
            std::string prefix = function_prefix(*name);
            if (!prefix.empty()) ++prefixes[prefix];
        }
    }

    auto best_label = [](const std::map<std::string, int> &counts) -> std::string {
        if (counts.empty()) return {};
        auto best = std::max_element(
            counts.begin(), counts.end(),
            [](const auto &a, const auto &b) {
                if (a.second != b.second) return a.second < b.second;
                return a.first > b.first;
            });
        return best->first;
    };

    std::string label = best_label(families);
    if (label.empty()) label = best_label(prefixes);
    if (label.empty()) label = std::format("Subsystem {}", cluster_id + 1);

    return std::format("{} ({} funcs)", label, members.size());
}

} // namespace

SubsystemClustering cluster_subsystems(
    const std::set<ida::Address> &functions,
    const std::vector<Edge> &edges,
    double resolution) {
    SubsystemClustering result;
    std::vector<ida::Address> ordered(functions.begin(), functions.end());
    int n = static_cast<int>(ordered.size());
    if (n == 0) return result;

    std::unordered_map<ida::Address, int> index_by_ea;
    for (int i = 0; i < n; ++i)
        index_by_ea.emplace(ordered[i], i);

    std::map<ida::Address, std::string> imports = import_names();
    std::vector<NodeFeatures> features(n);
    std::vector<std::vector<int>> callees(n);
    std::map<std::pair<int, int>, int> call_sites;
    std::map<std::pair<int, int>, double> weights;

    auto add_call_site = [&](int from, int to, double weight) {
        if (from == to) return;
        call_sites[std::make_pair(from, to)] += 1;
        callees[from].push_back(to);
        add_undirected(weights, from, to, weight);
    };

    for (int i = 0; i < n; ++i) {
        features[i].system = is_system_function(ordered[i]);
        ida::Result<ida::function::Function> function = ida::function::at(ordered[i]);
        if (!function) continue;

        std::unordered_set<Resource> globals;
        std::unordered_set<Resource> import_set;
        ida::Address start = static_cast<ida::Address>(function->start());
        ida::Address end = static_cast<ida::Address>(function->end());

        for (ida::Address ea = start; ea < end && ea != ida::BadAddress; ) {
            ida::Result<std::vector<ida::xref::Reference>> refs =
                ida::xref::refs_from(ea);
            if (refs) {
                for (const ida::xref::Reference &xref : *refs) {
                    if (xref.to == ida::BadAddress) continue;
                    if (xref.is_code && is_call_or_jump(xref.type)) {
                        ida::Address target = xref.to;
                        auto imp = imports.find(target);
                        if (imp != imports.end()) {
                            import_set.insert(target);
                            ++features[i].import_families[import_family(imp->second)];
                        }
                        std::optional<ida::Address> callee = function_start(target);
                        if (callee) {
                            auto it = index_by_ea.find(*callee);
                            if (it != index_by_ea.end())
                                add_call_site(i, it->second, 1.0);
                        }
                    } else if (ida::xref::is_data(xref.type)) {
                        auto imp = imports.find(xref.to);
                        if (imp != imports.end()) {
                            import_set.insert(xref.to);
                            ++features[i].import_families[import_family(imp->second)];
                        } else if (is_global_data_address(xref.to)) {
                            globals.insert(xref.to);
                        }
                    }
                }
            }

            ida::Result<ida::Address> next = ida::address::next_head(ea, end);
            if (!next || *next == ida::BadAddress || *next <= ea) break;
            ea = static_cast<ida::Address>(*next);
        }

        features[i].globals.assign(globals.begin(), globals.end());
        features[i].imports.assign(import_set.begin(), import_set.end());
    }

    for (const Edge &edge : edges) {
        auto from = index_by_ea.find(edge.from);
        auto to = index_by_ea.find(edge.to);
        if (from == index_by_ea.end() || to == index_by_ea.end()) continue;
        if (edge.types.count(RefType::IndirectCall) || edge.types.count(RefType::JumpTable))
            add_undirected(weights, from->second, to->second, 0.5);
        if (edge.types.count(RefType::VirtualCall))
            add_undirected(weights, from->second, to->second, 0.35);
    }

    for (const auto &[edge, count] : call_sites) {
        (void)count;
        ++features[edge.second].call_fanin;
    }

    for (auto &cs : callees) {
        std::sort(cs.begin(), cs.end());
        cs.erase(std::unique(cs.begin(), cs.end()), cs.end());
        if (cs.size() > 40) continue;
        for (size_t i = 0; i < cs.size(); ++i)
            for (size_t j = i + 1; j < cs.size(); ++j)
                add_undirected(weights, cs[i], cs[j], 0.35);
    }

    auto add_resource_edges = [&](const std::vector<std::vector<Resource>> &by_func,
                                  double channel_weight) {
        std::map<Resource, std::vector<int>> resource_to_funcs;
        for (int i = 0; i < n; ++i)
            for (Resource r : by_func[i])
                resource_to_funcs[r].push_back(i);

        int df_cap = std::max(8, n / 20);
        for (auto &[resource, funcs_for_resource] : resource_to_funcs) {
            std::sort(funcs_for_resource.begin(), funcs_for_resource.end());
            funcs_for_resource.erase(
                std::unique(funcs_for_resource.begin(), funcs_for_resource.end()),
                funcs_for_resource.end());
            int df = static_cast<int>(funcs_for_resource.size());
            if (df < 2 || df > df_cap) continue;
            double score = channel_weight * std::log(
                static_cast<double>(std::max(2, n)) / static_cast<double>(df));
            for (size_t i = 0; i < funcs_for_resource.size(); ++i)
                for (size_t j = i + 1; j < funcs_for_resource.size(); ++j)
                    add_undirected(weights, funcs_for_resource[i], funcs_for_resource[j], score);
        }
    };

    std::vector<std::vector<Resource>> globals_by_func(n), imports_by_func(n);
    for (int i = 0; i < n; ++i) {
        globals_by_func[i] = features[i].globals;
        imports_by_func[i] = features[i].imports;
    }
    add_resource_edges(globals_by_func, 1.0);
    add_resource_edges(imports_by_func, 0.8);

    std::vector<int> by_addr(n);
    std::iota(by_addr.begin(), by_addr.end(), 0);
    std::sort(by_addr.begin(), by_addr.end(), [&](int a, int b) {
        return ordered[a] < ordered[b];
    });
    constexpr int locality_window = 6;
    constexpr double sigma = 16384.0;
    constexpr double sigma2 = 2.0 * sigma * sigma;
    for (int i = 0; i < n; ++i) {
        for (int j = 1; j <= locality_window && i + j < n; ++j) {
            int a = by_addr[i];
            int b = by_addr[i + j];
            double delta = static_cast<double>(ordered[b] - ordered[a]);
            add_undirected(weights, a, b, 0.6 * std::exp(-(delta * delta) / sigma2));
        }
    }

    WeightedGraph graph = materialize_graph(n, weights);
    std::vector<char> utility = detect_utility_hubs(features, graph);
    std::vector<int> cluster = louvain_multilevel(
        graph, utility, std::max(0.05, resolution));
    merge_tiny_clusters(cluster, graph, utility);

    std::map<int, std::vector<int>> members_by_cluster;
    std::vector<int> utility_members;
    for (int i = 0; i < n; ++i) {
        if (utility[i]) {
            utility_members.push_back(i);
        } else if (cluster[i] >= 0) {
            members_by_cluster[cluster[i]].push_back(i);
        }
    }

    int next_cluster_id = 0;
    for (auto &[_, members] : members_by_cluster) {
        if (members.empty()) continue;
        std::sort(members.begin(), members.end(), [&](int a, int b) {
            return ordered[a] < ordered[b];
        });
        SubsystemCluster out;
        out.id = next_cluster_id++;
        out.utility = false;
        out.label = label_for_cluster(out.id, members, ordered, features, false);
        for (int node : members) {
            out.functions.push_back(ordered[node]);
            result.cluster_by_function[ordered[node]] = out.id;
        }
        result.clusters.push_back(std::move(out));
    }

    if (!utility_members.empty()) {
        std::sort(utility_members.begin(), utility_members.end(), [&](int a, int b) {
            return ordered[a] < ordered[b];
        });
        SubsystemCluster utilities;
        utilities.id = next_cluster_id++;
        utilities.utility = true;
        utilities.label = label_for_cluster(utilities.id, utility_members, ordered, features, true);
        for (int node : utility_members) {
            utilities.functions.push_back(ordered[node]);
            result.cluster_by_function[ordered[node]] = utilities.id;
        }
        result.clusters.push_back(std::move(utilities));
    }

    return result;
}

} // namespace codedump
