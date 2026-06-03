#pragma once

#include "common/types.h"
#include <map>
#include <vector>
#include <set>
#include <string>

namespace codedump {

class CodeWriter {
public:
    CodeWriter() = default;

    // Build the full code-dump text. Pure in-memory; the file writer and
    // the clipboard-copy path both feed off this.
    std::string render(
        const std::map<ida::Address, FunctionSummary> &summaries,
        const std::map<ida::Address, std::string> &annotations,
        const std::vector<Edge> &edges,
        const std::set<ida::Address> &start_functions,
        int caller_depth,
        int callee_depth,
        int max_chars = 0,
        const std::string &type_decls = "",
        bool omit_ptn = false,
        FunctionOrder function_order = FunctionOrder::Address
    );

    bool write(
        const std::string &path,
        const std::map<ida::Address, FunctionSummary> &summaries,
        const std::map<ida::Address, std::string> &annotations,
        const std::vector<Edge> &edges,
        const std::set<ida::Address> &start_functions,
        int caller_depth,
        int callee_depth,
        int max_chars = 0,
        const std::string &type_decls = "",
        bool omit_ptn = false,
        FunctionOrder function_order = FunctionOrder::Address
    );

private:
    std::string build_header(
        const std::set<ida::Address> &start_functions,
        int caller_depth,
        int callee_depth,
        const std::map<ida::Address, FunctionSummary> &summaries,
        bool omit_ptn,
        const std::vector<ida::Address> &ordered_functions,
        FunctionOrder function_order
    );

    std::string build_function_block(
        ida::Address func_ea,
        const FunctionSummary &summary,
        const std::string &annots,
        const std::vector<Edge> &edges,
        const std::map<ida::Address, FunctionSummary> &all_summaries,
        bool omit_ptn
    );

    std::string get_incoming_xrefs(
        ida::Address func_ea,
        const std::vector<Edge> &edges,
        const std::map<ida::Address, FunctionSummary> &summaries
    );

    std::string get_outgoing_xrefs(
        ida::Address func_ea,
        const std::vector<Edge> &edges,
        const std::map<ida::Address, FunctionSummary> &summaries
    );
};

} // namespace codedump
