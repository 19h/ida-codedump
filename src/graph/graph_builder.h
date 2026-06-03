#pragma once

#include "common/types.h"
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <unordered_map>
#include <vector>

namespace codedump {

// Progress snapshot dispatched by GraphBuilder during a long walk. The
// callback returns false to request cancellation; the builder will then
// stop work as soon as it sees the next callback boundary.
struct GraphProgress {
    const char *phase = "";   // "callers" | "callees" | "vtables"

    // BFS layer info (callers/callees).
    int depth = 0;            // current layer index, 0-based
    int max_depth = 0;        // total layers we plan to walk
    size_t layer_index = 0;   // function index within the current layer
    size_t layer_total = 0;   // total functions in the current layer

    // Aggregate stats since the phase started.
    size_t processed = 0;     // functions whose body has been walked
    size_t discovered = 0;    // size of the working set right now
    size_t edges = 0;         // total edges added so far

    // Identity of the function currently being processed (callers/callees)
    // OR the segment currently being scanned (vtables).
    ida::Address current_ea = ida::BadAddress;
    const char *current_name = "";

    // vtables-only fields.
    size_t segment_index = 0;
    size_t segment_total = 0;
    size_t vtables_found = 0;
};

using GraphProgressCb = std::function<bool(const GraphProgress &)>;

class GraphBuilder {
public:
    explicit GraphBuilder(const DumpOptions &opts);

    void add_start_function(ida::Address ea);

    // Walk callers up to `depth` layers. Returns false if the callback
    // requested cancellation.
    bool find_callers(int depth, const GraphProgressCb &cb = nullptr);

    // Walk callees up to `depth` layers. Returns false if the callback
    // requested cancellation.
    bool find_callees(int depth, const GraphProgressCb &cb = nullptr);

    // Scan data segments for vtables. Safe to call multiple times — only
    // performs the scan once. Returns false if cancelled mid-scan.
    bool scan_vtables(const GraphProgressCb &cb = nullptr);

    const std::set<ida::Address> &get_functions() const { return functions_; }
    const std::vector<Edge> &get_edges() const { return edges_; }
    const std::set<ida::Address> &get_start_functions() const { return start_functions_; }

private:
    // Collect every outbound edge from `func_ea` (single decode pass).
    void collect_outbound_refs(ida::Address func_ea,
                               std::vector<std::pair<ida::Address, RefType>> &refs);
    // Collect every inbound code edge to `func_ea`.
    void collect_inbound_refs(ida::Address func_ea,
                              std::vector<std::pair<ida::Address, RefType>> &refs);

    std::optional<ida::Address> detect_indirect_target(ida::Address call_ea, ida::Address func_start);
    std::vector<ida::Address> detect_jump_table(ida::Address jmp_ea);

    void add_edge(ida::Address from, ida::Address to, RefType type);
    bool should_follow(RefType type) const;
    bool should_keep_function(ida::Address ea);

    // Memoized start-of-function lookup. function_start is on the hot path
    // (called per-instruction for every enabled ref type), and the underlying
    // idax call fully populates a Function — including name demangling — just
    // to read start_ea. Cache the result keyed by queried address so each
    // address is resolved at most once across the whole crawl.
    std::optional<ida::Address> func_start_cached(ida::Address ea);
    // Database bitness never changes mid-crawl; resolve it once.
    bool is_64bit();

    DumpOptions opts_;
    std::set<ida::Address> start_functions_;
    std::set<ida::Address> functions_;
    std::vector<Edge> edges_;
    // (from,to) -> index in edges_. Hashed (not ordered) — edges_ preserves
    // insertion order; this map is only a dedup index. Hot on large graphs
    // (e.g. virtual-call fan-out), so O(1) lookup beats std::map's O(log n).
    struct EdgeKeyHash {
        std::size_t operator()(const std::pair<ida::Address, ida::Address> &k) const noexcept {
            return std::hash<ida::Address>{}(k.first) * 0x9E3779B97F4A7C15ULL
                 ^ std::hash<ida::Address>{}(k.second);
        }
    };
    std::unordered_map<std::pair<ida::Address, ida::Address>, size_t, EdgeKeyHash> edge_map_;
    std::vector<VTableEntry> vtables_;
    std::multimap<int, ida::Address> vtable_by_offset_;         // O(log n) virtual-call resolution
    bool vtables_scanned_ = false;

    std::unordered_map<ida::Address, std::optional<ida::Address>> func_start_cache_;
    std::unordered_map<ida::Address, bool> function_keep_cache_;
    std::optional<bool> is64_cache_;
};

} // namespace codedump
