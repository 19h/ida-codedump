#pragma once

#include "common/types.h"
#include <map>
#include <vector>
#include <string>
#include <set>
#include <optional>

namespace codedump {

// PTN (Provenance Tracking Notation) generator - matches Python version format
class PTNEmitter {
public:
    explicit PTNEmitter(const std::map<ida::Address, FunctionSummary> &summaries);

    // Generate per-function PTN annotations for embedding in code output
    std::map<ida::Address, std::string> per_function_annotations(int callee_depth);

    // Generate per-instruction hints for assembly output
    std::map<ida::Address, std::map<ida::Address, std::vector<std::string>>> per_instruction_hints(int callee_depth);

    // Emit full PTN format
    std::string emit_ptn(
        const std::set<ida::Address> &start_eas,
        int callee_depth,
        const std::set<ida::Address> *restrict_eas = nullptr
    );

    // Emit PTN as JSON
    std::string emit_ptn_json(
        const std::set<ida::Address> &start_eas,
        int callee_depth,
        const std::set<ida::Address> *restrict_eas = nullptr
    );

private:
    // Function ID management
    void assign_fids();
    std::string fid(ida::Address ea) const;

    // Node formatting (matches Python _fmt_node_* methods)
    static std::string fmt_slice(std::optional<int> off, std::optional<int> length, const std::string &member);
    static std::string fmt_meta(const std::map<std::string, std::string> &meta);

    std::string fmt_node_L(const std::string &fid, int lidx, std::optional<int> off, std::optional<int> length,
                           const std::string &mode, const std::string &cast, const std::string &name,
                           const std::string &member, const std::map<std::string, std::string> &meta);
    std::string fmt_node_P(const std::string &fid, int pidx, std::optional<int> off, std::optional<int> length,
                           const std::string &mode, const std::string &cast, const std::string &name,
                           const std::string &member, const std::map<std::string, std::string> &meta);
    std::string fmt_node_A(const std::string &fid_or_name, int arg_index, const std::map<std::string, std::string> &meta);
    std::string fmt_node_G(ida::Address ea, std::optional<int> off, std::optional<int> length, const std::string &name,
                           const std::string &member, const std::map<std::string, std::string> &meta);
    std::string fmt_node_C(uint64_t val, const std::map<std::string, std::string> &meta);
    std::string fmt_node_R(const std::string &fid, const std::string &name, const std::map<std::string, std::string> &meta);
    std::string fmt_node_F(const std::string &fid, const std::string &name, const std::map<std::string, std::string> &meta);

    // Origin formatting
    std::string fmt_origin(BaseKind kind, ida::Address fea, int idx, const std::string &name,
                          std::optional<int> off, std::optional<int> length, const std::string &mode,
                          const std::string &cast, const std::string &member,
                          const std::map<std::string, std::string> &meta);

    // Dictionary header
    std::string dict_header(const std::set<ida::Address> &restrict_eas);

    // Build dataflow maps
    struct IncomingEntry {
        ida::Address caller_ea;
        BaseKind origin_kind;
        int origin_id;
        std::string origin_name;
        std::optional<int> off;
        std::optional<int> length;
        std::string mode;
        std::string cast;
        std::string conf;
        ida::Address cs_ea;
        std::string member;
    };

    struct ParamForwardEntry {
        ida::Address callee_ea;
        int arg_idx;
        std::map<std::string, std::string> meta;
    };

    std::map<std::pair<ida::Address, int>, std::vector<IncomingEntry>> build_incoming_map();
    std::map<std::pair<ida::Address, int>, std::vector<ParamForwardEntry>> build_param_forward();

    // BFS chain traversal for inter-procedural tracking
    void emit_chains_bfs(
        const std::string &origin,
        ida::Address initial_callee,
        int initial_arg,
        int max_depth,
        const std::map<std::pair<ida::Address, int>, std::vector<ParamForwardEntry>> &param_forward,
        std::vector<std::string> &output_lines
    );

    // Data
    const std::map<ida::Address, FunctionSummary> &summaries_;
    std::map<ida::Address, std::string> fid_by_ea_;
    std::map<std::string, ida::Address> ea_by_fid_;
    std::map<ida::Address, std::string> name_by_ea_;
};

} // namespace codedump
