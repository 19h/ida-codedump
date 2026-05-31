#pragma once

#include "common/types.h"

#include <ida/decompiler.hpp>

namespace codedump {

// Forward declaration
class ProvCollector;

class CtreeAnalyzer {
public:
    CtreeAnalyzer() = default;

    // Analyze a function's ctree and populate the summary
    bool analyze_function(ida::Address func_ea, FunctionSummary &summary);

    // Expression normalization (public for ProvCollector access)
    struct ExprOrigin {
        BaseKind kind = BaseKind::Unknown;
        std::string id;
        std::string name;
        int offset = 0;
        int length = 0;
        std::string cast_txt;
        std::string mode;  // "&" for address-of, "*" for deref, "" for direct
        std::string member_name;
        std::string confidence = "med";  // "low", "med", "high"
    };

    ExprOrigin normalize_expr(
        ida::decompiler::ExpressionView expr,
        const std::vector<ida::decompiler::LocalVariable> &variables);

    // Resolve alias chains within a function to find ultimate origin
    static AliasChain resolve_alias_chain(
        const std::string &var_name,
        const std::vector<Alias> &aliases,
        int max_depth = 10
    );

    // Type helpers (public for ProvCollector access)
    int get_type_size(ida::decompiler::ExpressionView expr);
};

} // namespace codedump
