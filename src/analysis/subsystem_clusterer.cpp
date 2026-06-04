#include "subsystem_clusterer.h"

#include "common/function_filter.h"

#include <ida/address.hpp>
#include <ida/data.hpp>
#include <ida/database.hpp>
#include <ida/entry.hpp>
#include <ida/function.hpp>
#include <ida/name.hpp>
#include <ida/segment.hpp>
#include <ida/xref.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <format>
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

namespace codedump {

namespace {

using Resource = ida::Address;

// Token document accumulated per function from every evidence channel
// (function scope name, referenced string literals, imported API names).
// `tokens` is a weighted bag; `token_set` is the distinct set for bigram
// co-occurrence; `module_hits`/`file_basenames` corroborate domain/category.
struct NodeFeatures {
    std::vector<Resource> globals;
    std::vector<Resource> imports;
    std::map<std::string, double> tokens;
    std::set<std::string> token_set;
    std::vector<std::string> module_hits;
    std::vector<std::string> file_basenames;
    int call_fanin = 0;
    bool system = false;
};

struct ImportInfo {
    std::string symbol;
    std::string module;
};

struct WeightedGraph {
    std::vector<std::vector<std::pair<int, double>>> adj;
    std::vector<double> degree;
    double total_weight = 0.0;
};

struct NodeEdgeAccumulator {
    std::set<RefType> types;
    int count = 0;
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

// ── Text / token analysis ───────────────────────────────────────────────

// Grammatical noise and binary-identity tokens. Domain nouns (type, graph,
// node, edge, register, ...) are deliberately NOT here: c-TF-IDF suppresses
// them only when they are genuinely global, and surfaces them when they are
// distinctive to one cluster.
const std::unordered_set<std::string> &stopwords() {
    static const std::unordered_set<std::string> set = {
        "the", "for", "and", "from", "with", "that", "this", "not", "into",
        "get", "set", "put", "has", "use", "via", "out", "off", "all", "any",
        "ida", "codedump", "std", "gnu", "cxx", "abi", "cxxabi", "libc",
        "ptr", "ref", "val", "value", "view", "iter", "impl", "detail",
        "const", "void", "char", "int", "bool", "long", "auto", "size",
        "idx", "index", "tmp", "obj", "self", "args", "arg", "ret", "res",
        "begin", "end", "first", "last", "next", "prev", "true", "false",
        "null", "nullptr", "nullsub", "sub", "loc", "off", "var", "fld", "qword",
    };
    return set;
}

// Sink STL / libc / runtime mangled names BEFORE any token is extracted.
// This is the root fix for the spurious "network" cluster: a symbol such as
// std::__detail::_NFA<...>::_M_insert_accept is dropped wholesale here, so its
// "accept" substring can never reach a domain family. Cheap prefix/substring
// checks only — no std::regex in this hot path.
bool is_runtime_text(std::string_view s) {
    if (s.empty()) return false;
    auto pre = [&](std::string_view p) {
        return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
    };
    auto has = [&](std::string_view p) {
        return s.find(p) != std::string_view::npos;
    };
    if (pre("_Z") || pre("__") || pre("std::") || pre("`") || pre("."))
        return true;
    if (has("_M_") || has("__gnu_cxx") || has("cxxabi") || has("__cxa"))
        return true;
    if (has("gxx_personality") || has("_Unwind") || has("operator"))
        return true;
    if (has("GLIBC") || has("GCC_") || has("CXXABI") || has("GLIBCXX"))
        return true;

    // Disassembled prologue junk: an all-uppercase/digit run (e.g. "AWAVAUATSPH"),
    // optionally suffixed by 'h' or '.'.
    size_t lim = s.size();
    if (lim >= 5 && (s.back() == 'h' || s.back() == '.')) --lim;
    if (lim >= 4) {
        bool junk = true;
        for (size_t i = 0; i < lim; ++i) {
            unsigned char c = static_cast<unsigned char>(s[i]);
            if (!(std::isupper(c) || std::isdigit(c))) { junk = false; break; }
        }
        if (junk) return true;
    }
    return false;
}

// Split a string into lowercase tokens on non-alphanumeric and camelCase
// boundaries; keep 3..24-char alpha-led tokens that are not stopwords. Format
// placeholders (%s, {:x}) die naturally via the length filter.
// A token that is entirely hex characters and contains at least one digit is
// almost always an address fragment (a580, cf9030, b10) from an IDA loc_/off_
// name, not a word. Hex-letter words with no digit (face, feed, cafe) survive;
// tokens with a non-hex letter (md5, x509, utf8, sha256) survive.
bool is_hex_fragment(const std::string &s) {
    bool digit = false;
    for (char c : s) {
        unsigned char u = static_cast<unsigned char>(c);
        if (!std::isxdigit(u)) return false;
        if (std::isdigit(u)) digit = true;
    }
    return digit;
}

void split_tokens(std::string_view raw, std::vector<std::string> &out) {
    std::string cur;
    auto flush = [&]() {
        if (cur.size() >= 3 && cur.size() <= 24) {
            std::string low = lower_ascii(cur);
            if (std::isalpha(static_cast<unsigned char>(low[0])) &&
                !is_hex_fragment(low) && !stopwords().count(low))
                out.push_back(std::move(low));
        }
        cur.clear();
    };
    for (char ch : raw) {
        unsigned char c = static_cast<unsigned char>(ch);
        if (!std::isalnum(c)) { flush(); continue; }
        if (!cur.empty() && std::isupper(c)) {
            unsigned char back = static_cast<unsigned char>(cur.back());
            if (std::islower(back) || std::isdigit(back)) flush();
        }
        cur.push_back(static_cast<char>(ch));
    }
    flush();
}

std::vector<std::string> tokenize(std::string_view raw) {
    std::vector<std::string> out;
    if (is_runtime_text(raw)) return out;
    split_tokens(raw, out);
    return out;
}

// If `text` is (or ends in) a source-file basename like "graph_builder.cpp",
// return the extension-stripped stem ("graph_builder"); else empty.
std::string source_file_stem(std::string_view text) {
    size_t slash = text.find_last_of("/\\");
    std::string_view base = slash == std::string_view::npos
        ? text : text.substr(slash + 1);
    size_t dot = base.find_last_of('.');
    if (dot == std::string_view::npos || dot == 0) return {};
    std::string_view stem = base.substr(0, dot);
    std::string_view ext = base.substr(dot + 1);
    static constexpr std::string_view exts[] = {
        "cpp", "cc", "cxx", "c", "hpp", "hxx", "hh", "h",
        "rs", "go", "py", "java", "cs", "swift", "m", "mm",
    };
    bool ok = false;
    for (std::string_view e : exts) if (ext == e) { ok = true; break; }
    if (!ok) return {};
    if (stem.size() < 3 || stem.size() > 48) return {};
    for (char c : stem)
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-'))
            return {};
    return std::string{stem};
}

// Coarse module key from a demangled name: the first one or two
// namespace/class components ("clang::Sema::ActOn..." -> "clang::sema",
// "llvm::APInt::foo" -> "llvm::apint", a free function -> ""). This is the
// semantic decomposition lever for a huge library (LLVM/Clang) whose call
// graph is too sparse — after a shallow auto-analysis — for community
// detection to break up structurally.
std::string module_key(std::string_view demangled) {
    while (demangled.rfind("(anonymous namespace)::", 0) == 0)
        demangled.remove_prefix(23);
    std::string s;                              // strip template args and (args)
    int depth = 0;
    for (char c : demangled) {
        if (c == '<') { ++depth; continue; }
        if (c == '>') { if (depth) --depth; continue; }
        if (c == '(' && depth == 0) break;
        if (depth == 0) s.push_back(c);
    }
    size_t p1 = s.find("::");
    if (p1 == std::string::npos || p1 == 0) return {};
    size_t p2 = s.find("::", p1 + 2);
    std::string key = (p2 == std::string::npos) ? s.substr(0, p1) : s.substr(0, p2);
    if (key.size() > 40) return {};
    return lower_ascii(key);
}

// Coarse category (drives node color). Sensitive categories (network/crypto/...)
// require corroboration before being assigned — see assign_category().
std::string token_category(const std::string &t) {
    struct Row { const char *cat; std::vector<std::string_view> toks; };
    static const std::vector<Row> table = {
        {"decompiler", {"decompile","decompiler","ctree","pseudocode","hexrays","qflow","microcode","mba","cexpr","citem","visitor","expression"}},
        {"types",      {"type","types","udt","tinfo","typedef","declaration","decl","enum","struct","member","udm","collector","prototype","typeinfo","field","sizeof"}},
        {"graph",      {"graph","dot","cluster","subsystem","centrality","louvain","digraph","entryness","ranker","modularity"}},
        {"output",     {"writer","render","emit","output","dump","serialize","escape","indent","pretty","code"}},
        {"xref",       {"xref","cref","dref","reference","crossref","callgraph","caller","callee","fanin","fanout"}},
        {"disasm",     {"disasm","insn","instruction","mnem","opcode","operand","mnemonic","prologue","epilogue"}},
        {"segment",    {"segment","segm","section","memmap","mapping","relocation","fixup","loader","header","binary"}},
        {"register",   {"register","liveness","regs","clobber","incoming","outgoing","frame","argloc"}},
        {"io",         {"ofstream","fopen","filepath","filesystem","clipboard","stdout","stderr","ifstream","pathname","tempfile"}},
        {"cli",        {"argv","argc","option","usage","getopt","cmdline","cli","subcommand","helptext"}},
        {"provenance", {"ptn","ptnemitter","provenance","alias","aliaschain","origin","summary","taint","dataflow","liveset"}},
        {"crypto",     {"crypto","aes","rsa","hmac","cipher","x509","ecdsa","blake","chacha","keccak"}},
        {"network",    {"socket","getaddrinfo","recvfrom","sendto","winsock","epoll","sockaddr","htons","setsockopt","wsastartup"}},
        {"compression",{"zlib","inflate","deflate","lzma","zstd","huffman","brotli","gunzip","unzip"}},
        {"database",   {"sqlite","cursor","resultset","prepared","rowid","schema","btree","pager","vacuum"}},
        {"text",       {"format","formatter","formatting","regex","lexer","parser","grammar","unicode","codepoint","tokenizer","syntax","json","nlohmann"}},
    };
    for (const Row &row : table)
        for (std::string_view k : row.toks)
            if (t == k) return row.cat;
    return {};
}

bool is_sensitive_category(std::string_view cat) {
    return cat == "network" || cat == "crypto" ||
           cat == "compression" || cat == "database";
}

std::string import_module_token(std::string_view module) {
    std::string m = lower_ascii(module);
    size_t slash = m.find_last_of("/\\");
    if (slash != std::string::npos) m = m.substr(slash + 1);
    for (std::string_view p : {"lib"}) {
        if (m.compare(0, p.size(), p) == 0) m.erase(0, p.size());
    }
    size_t dot = m.find_first_of('.');           // strip .dll / .so(.x)
    if (dot != std::string::npos) m = m.substr(0, dot);
    if (m.size() < 3 || m.size() > 24 || stopwords().count(m)) return {};
    return m;
}

std::string import_names_module_clean(std::string_view name) {
    // Many import symbols are plain C names; mangled ones are routed out by
    // tokenize() via is_runtime_text. Just hand the raw symbol to tokenize.
    return std::string{name};
}

// ── Graph machinery (unchanged) ──────────────────────────────────────────

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

    std::vector<std::vector<std::vector<int>>> hierarchy;
    hierarchy.push_back(members);

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
        hierarchy.push_back(members);
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

    auto choose_level = [&]() -> const std::vector<std::vector<int>>& {
        constexpr int min_readable = 8;
        constexpr int max_readable = 40;

        // Prefer the FINEST readable level (most clusters within range): the
        // user wants granular, per-module subsystems, not a few mega-blobs.
        int selected = -1;
        int selected_count = -1;
        for (int i = 0; i < static_cast<int>(hierarchy.size()); ++i) {
            int count = static_cast<int>(hierarchy[i].size());
            if (count >= min_readable && count <= max_readable &&
                count > selected_count) {
                selected = i;
                selected_count = count;
            }
        }
        if (selected >= 0)
            return hierarchy[selected];

        selected_count = std::numeric_limits<int>::max();
        for (int i = 0; i < static_cast<int>(hierarchy.size()); ++i) {
            int count = static_cast<int>(hierarchy[i].size());
            if (count > max_readable && count < selected_count) {
                selected = i;
                selected_count = count;
            }
        }
        if (selected >= 0)
            return hierarchy[selected];

        selected = 0;
        selected_count = 0;
        for (int i = 0; i < static_cast<int>(hierarchy.size()); ++i) {
            int count = static_cast<int>(hierarchy[i].size());
            if (count > selected_count) {
                selected = i;
                selected_count = count;
            }
        }
        return hierarchy[selected];
    };

    const auto &selected_members = choose_level();
    for (int cluster = 0; cluster < static_cast<int>(selected_members.size()); ++cluster)
        for (int original : selected_members[cluster])
            final_cluster[original] = cluster;

    return final_cluster;
}

void merge_tiny_clusters(
    std::vector<int> &cluster,
    const WeightedGraph &graph,
    const std::vector<char> &pinned,
    int min_size = 2) {
    std::map<int, int> sizes;
    for (int c : cluster)
        if (c >= 0) ++sizes[c];

    for (int node = 0; node < static_cast<int>(cluster.size()); ++node) {
        int c = cluster[node];
        if (c < 0 || pinned[node] || sizes[c] >= min_size) continue;

        std::map<int, double> by_cluster;
        for (const auto &[neigh, weight] : graph.adj[node]) {
            int nc = cluster[neigh];
            if (nc >= 0 && nc != c && !pinned[neigh])
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

// Partition a member set by running one Louvain local-move pass over the
// induced subgraph at `resolution`. Returns the non-empty groups.
std::vector<std::vector<int>> split_members(
    const std::vector<int> &members,
    const WeightedGraph &graph,
    double resolution) {
    int k = static_cast<int>(members.size());
    std::unordered_map<int, int> local_index;
    local_index.reserve(k * 2);
    for (int i = 0; i < k; ++i) local_index[members[i]] = i;

    std::map<std::pair<int, int>, double> w;
    for (int i = 0; i < k; ++i) {
        for (const auto &[neigh, weight] : graph.adj[members[i]]) {
            auto it = local_index.find(neigh);
            if (it == local_index.end() || it->second <= i) continue;
            add_undirected(w, i, it->second, weight);
        }
    }
    WeightedGraph sub = materialize_graph(k, w);
    std::vector<char> none(k, false);
    std::vector<int> local = louvain_local_move(sub, none, resolution);

    int count = 0;
    for (int c : local) count = std::max(count, c + 1);
    std::vector<std::vector<int>> groups(std::max(0, count));
    for (int i = 0; i < k; ++i) groups[local[i]].push_back(members[i]);
    groups.erase(std::remove_if(groups.begin(), groups.end(),
                                [](const std::vector<int> &g) { return g.empty(); }),
                 groups.end());
    return groups;
}

// Structural split: the FEWEST natural pieces — the lowest resolution above
// base that breaks the members into >=2 communities, preferring a handful.
std::vector<std::vector<int>> split_structural(
    const std::vector<int> &members,
    const WeightedGraph &graph,
    double base_resolution) {
    std::vector<std::vector<int>> best;
    for (double mult : {1.1, 1.25, 1.45, 1.7, 2.0, 2.5, 3.5, 5.0}) {
        std::vector<std::vector<int>> groups =
            split_members(members, graph, base_resolution * mult);
        if (groups.size() >= 2) {
            if (groups.size() <= 8) return groups;
            if (best.empty()) best = std::move(groups);
        }
    }
    if (!best.empty()) return best;
    return {members};
}

// Semantic split: group members by demangled namespace/class module. This is
// the lever that decomposes a huge library whose call graph is too sparse to
// cluster structurally — llvm::CodeGen, clang::Sema, etc. stay meaningful even
// when there are almost no resolved call edges. Members with no module key are
// returned as a single trailing group (later chunked if still too big).
std::vector<std::vector<int>> split_by_module(
    const std::vector<int> &members,
    const std::vector<std::string> &node_module) {
    std::map<std::string, std::vector<int>> by_module;
    std::vector<int> no_module;
    for (int nd : members) {
        const std::string &m = node_module[nd];
        if (m.empty()) no_module.push_back(nd);
        else by_module[m].push_back(nd);
    }
    std::vector<std::vector<int>> groups;
    for (auto &[m, g] : by_module) groups.push_back(std::move(g));
    if (!no_module.empty()) groups.push_back(std::move(no_module));
    return groups;
}

// Last-resort split: cut an address-sorted member list (node indices are in
// address order) into bounded contiguous chunks. Arbitrary but guarantees
// termination and a bounded, readable cluster size.
std::vector<std::vector<int>> split_by_chunks(std::vector<int> members, int cap) {
    std::sort(members.begin(), members.end());
    int parts = std::max(2, (static_cast<int>(members.size()) + cap - 1) / cap);
    int per = (static_cast<int>(members.size()) + parts - 1) / parts;
    std::vector<std::vector<int>> groups;
    for (size_t i = 0; i < members.size(); i += per)
        groups.emplace_back(members.begin() + i,
                            members.begin() + std::min(members.size(), i + per));
    return groups;
}

int readable_cap(int active_n) { return std::max(700, active_n / 8); }

// Decompose every community larger than `cap` until all are a readable size.
// Tries structural community detection first; if that makes no real progress
// (the largest piece is still ~the whole input — the LLVM/Clang-blob case on a
// shallowly-analysed binary), falls back to a semantic module split, then to
// address chunking. This GUARANTEES a bounded max cluster size regardless of
// how degraded the call graph is. Small binaries never trip the cap.
void subdivide_large_clusters(
    std::vector<int> &cluster,
    const WeightedGraph &graph,
    const std::vector<std::string> &node_module,
    int active_n,
    double base_resolution) {
    int cap = readable_cap(active_n);

    std::map<int, std::vector<int>> members;
    int max_id = -1;
    for (int i = 0; i < static_cast<int>(cluster.size()); ++i)
        if (cluster[i] >= 0) {
            members[cluster[i]].push_back(i);
            max_id = std::max(max_id, cluster[i]);
        }
    int next_id = max_id + 1;

    std::vector<std::pair<std::vector<int>, int>> work;  // (members, depth)
    for (auto &[cid, mem] : members)
        if (static_cast<int>(mem.size()) > cap)
            work.emplace_back(std::move(mem), 0);

    auto largest = [](const std::vector<std::vector<int>> &gs) {
        size_t m = 0;
        for (const auto &g : gs) m = std::max(m, g.size());
        return m;
    };

    for (size_t wi = 0; wi < work.size(); ++wi) {
        std::vector<int> mem = work[wi].first;
        int depth = work[wi].second;

        std::vector<std::vector<int>> groups =
            split_structural(mem, graph, base_resolution);
        // No real progress => the community is structurally indivisible.
        if (groups.size() <= 1 ||
            largest(groups) > static_cast<size_t>(0.85 * mem.size())) {
            std::vector<std::vector<int>> by_mod = split_by_module(mem, node_module);
            if (by_mod.size() >= 2 &&
                largest(by_mod) < static_cast<size_t>(0.95 * mem.size()))
                groups = std::move(by_mod);
            else
                groups = split_by_chunks(mem, cap);
        }

        if (groups.size() <= 1) {                 // truly atomic: accept as leaf
            int id = next_id++;
            for (int nd : mem) cluster[nd] = id;
            continue;
        }
        for (std::vector<int> &g : groups) {
            if (static_cast<int>(g.size()) > cap && depth < 9)
                work.emplace_back(std::move(g), depth + 1);
            else {
                int id = next_id++;
                for (int nd : g) cluster[nd] = id;
            }
        }
    }
}

// Subdivision deliberately over-segments a huge program (it can shatter a dense
// 30k-node community into hundreds of fragments). Agglomerate back up to a
// readable target by repeatedly merging the smallest cluster into its
// strongest-connected neighbour, never exceeding the size cap — so fragments
// rejoin their parent subsystem without any blob reforming. Net effect: a
// bounded, readable number of clusters regardless of binary size.
void agglomerate_to_target(
    std::vector<int> &cluster,
    const WeightedGraph &graph,
    int active_n) {
    std::vector<int> ids;
    std::unordered_map<int, int> id_index;
    for (int c : cluster)
        if (c >= 0 && id_index.emplace(c, static_cast<int>(ids.size())).second)
            ids.push_back(c);
    int K = static_cast<int>(ids.size());
    int target = std::clamp(active_n / 700, 28, 60);
    if (K <= target) return;
    int cap = readable_cap(active_n);

    std::vector<int> size(K, 0);
    std::vector<std::map<int, double>> adj(K);
    for (int u = 0; u < static_cast<int>(cluster.size()); ++u) {
        int cu = cluster[u];
        if (cu < 0) continue;
        int iu = id_index[cu];
        ++size[iu];
        for (const auto &[v, w] : graph.adj[u]) {
            int cv = cluster[v];
            if (cv < 0 || cv == cu) continue;
            adj[iu][id_index[cv]] += w;
        }
    }

    std::vector<int> parent(K);
    std::iota(parent.begin(), parent.end(), 0);
    std::function<int(int)> find = [&](int x) {
        while (parent[x] != x) { parent[x] = parent[parent[x]]; x = parent[x]; }
        return x;
    };

    int count = K;
    std::vector<char> frozen(K, false);              // isolated clusters: skip
    while (count > target) {
        int s = -1;                                  // smallest live cluster
        for (int i = 0; i < K; ++i)
            if (find(i) == i && !frozen[i] && (s < 0 || size[i] < size[s])) s = i;
        if (s < 0) break;                            // everything else is frozen

        int t = -1;
        double best_w = -1.0;
        for (const auto &[j, w] : adj[s]) {
            int jr = find(j);
            if (jr == s) continue;
            if (size[jr] + size[s] <= cap && w > best_w) { best_w = w; t = jr; }
        }
        // No neighbour we can merge into without exceeding the cap: freeze this
        // cluster (keep it separate) rather than forcing an over-cap merge —
        // that fallback is exactly what funnelled every spoke into one 58k blob.
        if (t < 0) { frozen[s] = true; continue; }

        parent[s] = t;
        size[t] += size[s];
        for (const auto &[j, w] : adj[s]) {
            int jr = find(j);
            if (jr == t || jr == s) continue;
            adj[t][jr] += w;
            adj[jr][t] += w;
        }
        --count;
    }

    for (int &c : cluster)
        if (c >= 0) c = ids[find(id_index[c])];
}

// ── Import table (module-attributed) ─────────────────────────────────────

std::unordered_map<ida::Address, ImportInfo> import_table() {
    std::unordered_map<ida::Address, ImportInfo> table;
    ida::Result<std::vector<ida::database::ImportModule>> modules =
        ida::database::import_modules();
    if (!modules) return table;
    for (const auto &module : *modules)
        for (const auto &symbol : module.symbols) {
            if (symbol.address == ida::BadAddress) continue;
            table[symbol.address] = ImportInfo{symbol.name, module.name};
        }
    return table;
}

// ── Discriminative (c-TF-IDF) labeling ───────────────────────────────────

struct ScoredToken {
    std::string token;
    double score = 0.0;
};

// True if a demangled name belongs to the C++ standard library / runtime, so
// the function can be routed to the Utilities bucket instead of polluting a
// domain cluster. Detected on the DEMANGLED form: the raw mangled name would
// also match the program's own C++ symbols, which we must keep.
bool is_runtime_demangled(std::string_view dm) {
    auto pre = [&](std::string_view p) {
        return dm.size() >= p.size() && dm.compare(0, p.size(), p) == 0;
    };
    return pre("std::") || pre("__gnu_cxx") || pre("__cxxabiv1") ||
           pre("__cxa") || pre("operator new") || pre("operator delete") ||
           pre("non-virtual thunk") || pre("virtual thunk") ||
           pre("typeinfo") || pre("vtable for") || pre("VTT for") ||
           pre("guard variable");
}

// CRT / loader / libm glue that carries no subsystem meaning of its own and
// should fold into the Utilities bucket (matched on the raw symbol name).
bool is_low_level_runtime(std::string_view name) {
    auto has = [&](std::string_view p) {
        return name.find(p) != std::string_view::npos;
    };
    if (has("_ITM_") || has("TMClone") || has("register_tm_clones") ||
        has("deregister_tm") || has("register_frame") || has("frame_dummy") ||
        has("__do_global") || has("__libc_") || has("__gmon") ||
        has("__gthread") || has("__static_initialization"))
        return true;
    static constexpr std::string_view exact[] = {
        "_start", "_init", "_fini", "__init", "__fini", "start",
        "frexp", "frexpf", "frexpl", "ldexp", "ldexpf", "ldexpl",
        "modf", "modff", "scalbn", "bcmp", "qfree",
        "deregister_tm_clones", "register_tm_clones",
    };
    for (std::string_view e : exact) if (name == e) return true;
    return false;
}

// Compose a granular, non-redundant label for every cluster at once, using
// class-based TF-IDF with additive smoothing and a greedy cross-cluster
// dedup so two clusters never share a primary term.
void label_clusters(
    std::vector<SubsystemCluster> &clusters,
    const std::vector<NodeFeatures> &features,
    const std::map<int, std::vector<int>> &members_by_output) {

    const int C = static_cast<int>(clusters.size());
    if (C == 0) return;

    // Per-cluster weighted token doc + distinct-token vocab; global df.
    std::vector<std::map<std::string, double>> tf(C);
    std::vector<double> mass(C, 0.0);
    std::map<std::string, int> df;

    auto cluster_index = [&](int output_id) -> int {
        for (int i = 0; i < C; ++i) if (clusters[i].id == output_id) return i;
        return -1;
    };

    for (const auto &[output_id, members] : members_by_output) {
        int ci = cluster_index(output_id);
        if (ci < 0) continue;
        for (int node : members)
            for (const auto &[tok, w] : features[node].tokens) {
                tf[ci][tok] += w;
                mass[ci] += w;
            }
        for (const auto &[tok, w] : tf[ci]) {
            (void)w;
            ++df[tok];
        }
    }

    constexpr double alpha = 0.5;
    auto idf = [&](const std::string &t) {
        int d = df.count(t) ? df.at(t) : 1;
        return std::log(1.0 + static_cast<double>(C) / static_cast<double>(d));
    };

    // Rank every cluster's tokens once.
    std::vector<std::vector<ScoredToken>> ranked(C);
    for (int ci = 0; ci < C; ++ci) {
        double denom = mass[ci] + alpha * static_cast<double>(tf[ci].size());
        if (denom <= 0.0) continue;
        for (const auto &[tok, f] : tf[ci]) {
            double s = ((f + alpha) / denom) * idf(tok);
            ranked[ci].push_back({tok, s});
        }
        std::sort(ranked[ci].begin(), ranked[ci].end(),
                  [](const ScoredToken &a, const ScoredToken &b) {
                      if (a.score != b.score) return a.score > b.score;
                      return a.token < b.token;
                  });
    }

    // Bigram phrase detection: if the two strongest tokens co-occur within the
    // same member function often enough, join them ("dot-writer").
    auto bigram_phrase = [&](int ci) -> std::string {
        if (ranked[ci].size() < 2) return {};
        const std::string &a = ranked[ci][0].token;
        const std::string &b = ranked[ci][1].token;
        int both = 0, either = 0;
        for (int node : members_by_output.at(clusters[ci].id)) {
            bool ha = features[node].token_set.count(a);
            bool hb = features[node].token_set.count(b);
            if (ha || hb) ++either;
            if (ha && hb) ++both;
        }
        if (either > 0 && static_cast<double>(both) / either >= 0.6)
            return a + "-" + b;
        return {};
    };

    // Process clusters by descending top score so the strongest claim on a
    // term wins; later clusters de-prioritize (never forbid) taken terms.
    std::vector<int> order(C);
    std::iota(order.begin(), order.end(), 0);
    std::sort(order.begin(), order.end(), [&](int a, int b) {
        double sa = ranked[a].empty() ? 0.0 : ranked[a][0].score;
        double sb = ranked[b].empty() ? 0.0 : ranked[b][0].score;
        if (sa != sb) return sa > sb;
        return clusters[a].id < clusters[b].id;
    });

    std::unordered_set<std::string> used_primary;

    auto assign_category = [&](int ci) -> std::string {
        // Category comes only from the cluster's strongest discriminative
        // tokens; sensitive domains require >=2 distinct corroborating tokens
        // so a lone ambiguous hit can't mis-color (the old "network" failure
        // mode, now confined and guarded).
        int looked = 0;
        for (const ScoredToken &st : ranked[ci]) {
            if (looked++ >= 8) break;
            std::string cat = token_category(st.token);
            if (cat.empty()) continue;
            if (is_sensitive_category(cat)) {
                int corroborate = 0;
                for (const ScoredToken &o : ranked[ci])
                    if (token_category(o.token) == cat) ++corroborate;
                bool module_ok = false;
                for (int node : members_by_output.at(clusters[ci].id))
                    for (const std::string &m : features[node].module_hits)
                        if (token_category(import_module_token(m)) == cat)
                            module_ok = true;
                if (corroborate < 2 && !module_ok) continue;
            }
            return cat;
        }
        return {};
    };

    for (int ci : order) {
        SubsystemCluster &cluster = clusters[ci];
        if (cluster.utility) {
            cluster.category = "stl_util";
            continue;
        }

        cluster.category = assign_category(ci);

        // Pick primary term: a bigram phrase if available, else the strongest
        // not-yet-claimed token, else the strongest token (de-prioritized).
        std::string primary = bigram_phrase(ci);
        if (!primary.empty() && used_primary.count(primary)) {
            // try plain tokens before falling back to a shared phrase
            primary.clear();
        }
        std::vector<std::string> secondary;
        if (primary.empty()) {
            for (const ScoredToken &st : ranked[ci]) {
                if (used_primary.count(st.token)) continue;
                primary = st.token;
                break;
            }
        }
        if (primary.empty() && !ranked[ci].empty())
            primary = ranked[ci][0].token;   // everything taken: reuse strongest

        for (const ScoredToken &st : ranked[ci]) {
            if (secondary.size() >= 2) break;
            if (st.token == primary) continue;
            if (primary.find(st.token) != std::string::npos) continue;
            secondary.push_back(st.token);
        }

        if (!primary.empty()) used_primary.insert(primary);

        // Evidence: the most common __FILE__ basename, else top scope token.
        std::map<std::string, int> file_votes;
        for (int node : members_by_output.at(cluster.id))
            for (const std::string &f : features[node].file_basenames)
                ++file_votes[f];
        if (!file_votes.empty()) {
            auto best = std::max_element(
                file_votes.begin(), file_votes.end(),
                [](const auto &a, const auto &b) {
                    if (a.second != b.second) return a.second < b.second;
                    return a.first > b.first;
                });
            cluster.evidence = best->first;
        }

        std::string label = primary;
        for (const std::string &s : secondary) label += " \xC2\xB7 " + s;
        if (label.empty()) {
            // No usable signal anywhere: structural fallback, never bare.
            label = std::format("cluster-{}", cluster.id + 1);
        }
        cluster.label = label;
    }
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

    std::unordered_map<ida::Address, ImportInfo> imports = import_table();
    std::unordered_map<ida::Address, std::optional<std::string>> string_cache;
    std::vector<NodeFeatures> features(n);
    std::vector<std::string> node_module(n);
    std::vector<std::vector<int>> callees(n);
    std::map<std::pair<int, int>, NodeEdgeAccumulator> call_sites;
    std::map<std::pair<int, int>, NodeEdgeAccumulator> structural_edges;
    std::map<std::pair<int, int>, double> weights;

    auto record_structural_edge = [&](int from, int to, RefType type, int count = 1) {
        if (from == to) return;
        auto &acc = structural_edges[std::make_pair(from, to)];
        acc.types.insert(type);
        acc.count += count;
    };

    auto add_call_site = [&](int from, int to, RefType type, double weight) {
        if (from == to) return;
        auto &acc = call_sites[std::make_pair(from, to)];
        acc.types.insert(type);
        ++acc.count;
        record_structural_edge(from, to, type);
        callees[from].push_back(to);
        add_undirected(weights, from, to, weight);
    };

    auto add_tokens = [&](int i, std::string_view raw, double weight) {
        for (std::string &tok : tokenize(raw)) {
            features[i].tokens[tok] += weight;
            features[i].token_set.insert(tok);
        }
    };

    // String literals get a token cap so a single huge blob (a --help/usage
    // string, a serialized template) can't dominate a function's vocabulary.
    auto add_string_tokens = [&](int i, std::string_view raw) {
        double weight = raw.size() > 160 ? 0.5 : 1.0;   // long => likely prose
        int added = 0;
        for (std::string &tok : tokenize(raw)) {
            if (added++ >= 8) break;
            features[i].tokens[tok] += weight;
            features[i].token_set.insert(tok);
        }
    };

    auto note_import = [&](int i, const ImportInfo &info,
                           std::unordered_set<Resource> &import_set,
                           ida::Address addr) {
        import_set.insert(addr);
        add_tokens(i, import_names_module_clean(info.symbol), 1.5);
        std::string mod = import_module_token(info.module);
        if (!mod.empty()) {
            features[i].tokens[mod] += 2.0;
            features[i].token_set.insert(mod);
            features[i].module_hits.push_back(info.module);
        }
    };

    auto string_at = [&](ida::Address ea) -> const std::optional<std::string> & {
        auto it = string_cache.find(ea);
        if (it != string_cache.end()) return it->second;
        std::optional<std::string> value;
        if (ea != ida::BadAddress && ida::address::is_loaded(ea) &&
            ida::address::is_data(ea)) {
            ida::Result<std::string> s = ida::data::read_string(ea, 256);
            if (s && s->size() >= 4) {
                size_t printable = 0;
                for (unsigned char c : *s)
                    if (c == '\t' || (c >= 0x20 && c < 0x7f)) ++printable;
                if (printable * 10 >= s->size() * 9) value = *s;
            }
        }
        return string_cache.emplace(ea, std::move(value)).first->second;
    };

    for (int i = 0; i < n; ++i) {
        bool system = is_system_function(ordered[i]);

        // Scope / name channel: demangle, drop the argument list, tokenize.
        // The demangled prefix also tells us if this is bundled C++ runtime
        // (std::/__gnu_cxx/...) that should be treated as a utility, not a
        // domain function.
        std::string fname;
        if (ida::Result<std::string> dm =
                ida::name::demangled(ordered[i], ida::name::DemangleForm::Short);
            dm && !dm->empty()) {
            fname = *dm;
            if (is_runtime_demangled(fname)) system = true;
        } else if (ida::Result<std::string> nm = ida::function::name_at(ordered[i]);
                   nm) {
            fname = *nm;
        }
        if (!system && is_low_level_runtime(fname)) system = true;
        features[i].system = system;
        node_module[i] = module_key(fname);
        if (size_t paren = fname.find('('); paren != std::string::npos)
            fname.resize(paren);
        add_tokens(i, fname, 3.0);

        ida::Result<ida::function::Function> function = ida::function::at(ordered[i]);
        if (!function) continue;

        std::unordered_set<Resource> globals;
        std::unordered_set<Resource> import_set;
        std::unordered_set<Resource> probed_strings;
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
                        if (imp != imports.end())
                            note_import(i, imp->second, import_set, target);
                        std::optional<ida::Address> callee = function_start(target);
                        if (callee) {
                            auto it = index_by_ea.find(*callee);
                            if (it != index_by_ea.end()) {
                                RefType type = ida::xref::is_jump(xref.type)
                                    ? RefType::TailCallPushRet
                                    : RefType::DirectCall;
                                add_call_site(i, it->second, type, 1.0);
                            }
                        }
                    } else if (ida::xref::is_data(xref.type)) {
                        auto imp = imports.find(xref.to);
                        if (imp != imports.end()) {
                            note_import(i, imp->second, import_set, xref.to);
                        } else if (is_global_data_address(xref.to)) {
                            globals.insert(xref.to);
                            // String channel: cap distinct probed targets to
                            // keep the per-instruction loop bounded.
                            if (probed_strings.size() < 48 &&
                                probed_strings.insert(xref.to).second) {
                                const std::optional<std::string> &lit =
                                    string_at(xref.to);
                                if (lit) {
                                    std::string stem = source_file_stem(*lit);
                                    if (!stem.empty()) {
                                        add_tokens(i, stem, 3.0);
                                        features[i].file_basenames.push_back(
                                            stem + ".cpp");
                                    } else {
                                        add_string_tokens(i, *lit);
                                    }
                                }
                            }
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

    // Indirect/virtual structural edges contribute clustering weight, and mark
    // targets that have no unique structural parent (not collapsible).
    std::unordered_set<int> indirect_targets;
    for (const Edge &edge : edges) {
        auto from = index_by_ea.find(edge.from);
        auto to = index_by_ea.find(edge.to);
        if (from == index_by_ea.end() || to == index_by_ea.end()) continue;
        bool indirectish =
            edge.types.count(RefType::IndirectCall) ||
            edge.types.count(RefType::JumpTable) ||
            edge.types.count(RefType::VirtualCall);
        if (indirectish) indirect_targets.insert(to->second);
        if (edge.types.count(RefType::IndirectCall) || edge.types.count(RefType::JumpTable)) {
            add_undirected(weights, from->second, to->second, 0.5);
            for (RefType type : edge.types)
                record_structural_edge(from->second, to->second, type);
        }
        if (edge.types.count(RefType::VirtualCall)) {
            add_undirected(weights, from->second, to->second, 0.35);
            for (RefType type : edge.types)
                record_structural_edge(from->second, to->second, type);
        }
    }

    // Distinct direct/tail callers per node (from the internally-built call
    // graph, which is complete even when `edges` is empty for the all-funcs CLI).
    std::vector<std::set<int>> direct_callers(n);
    for (const auto &[edge, acc] : call_sites) {
        ++features[edge.second].call_fanin;
        direct_callers[edge.second].insert(edge.first);
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

    // ── Single-caller collapse ───────────────────────────────────────────
    // A function reached from exactly one place is part of that caller's logic;
    // fold it in so it neither forms a noise singleton nor splits off into a
    // different cluster. Union-find with a cycle guard; only structurally-safe
    // (non-utility, non-entry, non-indirect-target) nodes collapse.
    std::vector<int> parent(n);
    std::iota(parent.begin(), parent.end(), 0);
    std::function<int(int)> find = [&](int x) {
        while (parent[x] != x) { parent[x] = parent[parent[x]]; x = parent[x]; }
        return x;
    };

    std::unordered_set<ida::Address> entry_addrs;
    if (ida::Result<std::size_t> ec = ida::entry::count(); ec) {
        for (std::size_t i = 0; i < *ec; ++i)
            if (ida::Result<ida::entry::EntryPoint> ep = ida::entry::by_index(i); ep)
                entry_addrs.insert(ep->address);
    }

    for (int i = 0; i < n; ++i) {
        if (utility[i]) continue;
        if (entry_addrs.count(ordered[i])) continue;
        if (indirect_targets.count(i)) continue;
        if (direct_callers[i].size() != 1) continue;
        int g = *direct_callers[i].begin();
        if (g == i || utility[g]) continue;
        if (find(g) == i) continue;            // would create a cycle
        parent[i] = g;
    }

    // Children (those folded into a representative) are excluded from Louvain
    // and later inherit their representative's cluster.
    std::vector<char> excluded(n, false);
    for (int i = 0; i < n; ++i)
        excluded[i] = utility[i] || (find(i) != i);

    double res0 = std::max(0.05, resolution);
    std::vector<int> cluster = louvain_multilevel(graph, excluded, res0);
    merge_tiny_clusters(cluster, graph, excluded);

    int active_n = 0;
    for (int i = 0; i < n; ++i) if (!excluded[i]) ++active_n;
    subdivide_large_clusters(cluster, graph, node_module, active_n, res0);
    agglomerate_to_target(cluster, graph, active_n);
    merge_tiny_clusters(cluster, graph, excluded);

    // ── Resolve every node to a final output cluster ─────────────────────
    // group(node): the Louvain community of its representative, or a utility
    // sentinel if the representative is a utility hub.
    constexpr int UTIL_GROUP = std::numeric_limits<int>::min();
    auto group_of = [&](int node) -> int {
        int r = find(node);
        if (utility[r]) return UTIL_GROUP;
        return cluster[r];                      // may be -1 if rep unclustered
    };

    std::map<int, int> group_to_output;         // louvain group -> output id
    int next_id = 0;
    for (int i = 0; i < n; ++i) {
        int gp = group_of(i);
        if (gp == UTIL_GROUP || gp < 0) continue;
        if (!group_to_output.count(gp)) group_to_output[gp] = next_id++;
    }
    int util_output = -1;
    bool has_util = false;
    for (int i = 0; i < n; ++i)
        if (group_of(i) == UTIL_GROUP) { has_util = true; break; }
    if (has_util) util_output = next_id++;

    std::vector<int> node_to_output_cluster(n, -1);
    std::map<int, std::vector<int>> members_by_output;
    for (int i = 0; i < n; ++i) {
        int gp = group_of(i);
        int out;
        if (gp == UTIL_GROUP) out = util_output;
        else if (gp < 0) out = -1;              // unclustered orphan
        else out = group_to_output[gp];
        node_to_output_cluster[i] = out;
        if (out >= 0) members_by_output[out].push_back(i);
    }

    // Materialize clusters (members sorted by address for determinism).
    result.clusters.reserve(members_by_output.size());
    for (auto &[out, members] : members_by_output) {
        std::sort(members.begin(), members.end(), [&](int a, int b) {
            return ordered[a] < ordered[b];
        });
        SubsystemCluster sc;
        sc.id = out;
        sc.utility = (out == util_output);
        sc.func_count = static_cast<int>(members.size());
        for (int node : members) {
            sc.functions.push_back(ordered[node]);
            result.cluster_by_function[ordered[node]] = out;
        }
        result.clusters.push_back(std::move(sc));
    }
    std::sort(result.clusters.begin(), result.clusters.end(),
              [](const SubsystemCluster &a, const SubsystemCluster &b) {
                  return a.id < b.id;
              });

    label_clusters(result.clusters, features, members_by_output);

    // Finalize human labels: utilities get a fixed name; everyone gets the
    // "(N funcs)" suffix the renderer strips back out for the size line.
    for (SubsystemCluster &sc : result.clusters) {
        if (sc.utility) {
            sc.label = std::format("Utilities ({} funcs)", sc.func_count);
            sc.category = "stl_util";
        } else {
            sc.label = std::format("{} ({} funcs)", sc.label, sc.func_count);
        }
    }

    // ── Inter-cluster meta-edges (from original-node structural edges) ────
    std::map<std::pair<int, int>, SubsystemClusterEdge> cluster_edge_map;
    for (const auto &[node_edge, acc] : structural_edges) {
        int from_cluster = node_to_output_cluster[node_edge.first];
        int to_cluster = node_to_output_cluster[node_edge.second];
        if (from_cluster < 0 || to_cluster < 0 || from_cluster == to_cluster)
            continue;

        auto &edge = cluster_edge_map[std::make_pair(from_cluster, to_cluster)];
        edge.from = from_cluster;
        edge.to = to_cluster;
        edge.types.insert(acc.types.begin(), acc.types.end());
        edge.count += acc.count;
    }
    for (auto &[_, edge] : cluster_edge_map)
        result.cluster_edges.push_back(std::move(edge));

    return result;
}

} // namespace codedump
