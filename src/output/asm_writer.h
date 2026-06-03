#pragma once

#include "common/types.h"
#include "analysis/ptn_emitter.h"
#include <map>
#include <set>
#include <vector>
#include <string>

namespace codedump {

class AsmWriter {
public:
    AsmWriter() = default;

    // Build the assembly dump text. File writer + clipboard path consume this.
    std::string render(
        const std::map<ida::Address, FunctionSummary> &summaries,
        const std::map<ida::Address, std::string> &annotations,
        PTNEmitter &emitter,
        int callee_depth,
        const std::string &type_decls = "",
        bool omit_ptn = false,
        const std::vector<Edge> &edges = std::vector<Edge>{},
        const std::set<ida::Address> &start_functions = std::set<ida::Address>{},
        FunctionOrder function_order = FunctionOrder::Address
    );

    bool write(
        const std::string &path,
        const std::map<ida::Address, FunctionSummary> &summaries,
        const std::map<ida::Address, std::string> &annotations,
        PTNEmitter &emitter,
        int callee_depth,
        const std::string &type_decls = "",
        bool omit_ptn = false,
        const std::vector<Edge> &edges = std::vector<Edge>{},
        const std::set<ida::Address> &start_functions = std::set<ida::Address>{},
        FunctionOrder function_order = FunctionOrder::Address
    );
};

} // namespace codedump
