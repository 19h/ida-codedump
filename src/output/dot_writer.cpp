#include "dot_writer.h"

#include "common/function_filter.h"

#include <ida/function.hpp>

#include <algorithm>
#include <cctype>
#include <format>
#include <fstream>
#include <sstream>

namespace codedump {

namespace {

std::string normalized_rankdir(const DumpOptions &opts) {
    std::string rankdir = opts.dot_rankdir.empty() ? "TB" : opts.dot_rankdir;
    std::transform(rankdir.begin(), rankdir.end(), rankdir.begin(), [](unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });

    if (rankdir == "TB" || rankdir == "LR" || rankdir == "RL" || rankdir == "BT")
        return rankdir;
    return "TB";
}

} // namespace

std::string DotWriter::get_edge_color(RefType type) {
    switch (type) {
        case RefType::DirectCall:      return "black";
        case RefType::IndirectCall:    return "blue";
        case RefType::DataRef:         return "green";
        case RefType::ImmediateRef:    return "orange";
        case RefType::TailCallPushRet: return "red";
        case RefType::VirtualCall:     return "purple";
        case RefType::JumpTable:       return "brown";
        default:                       return "gray";
    }
}

std::string DotWriter::get_edge_style(const std::set<RefType> &types, bool include_label) {
    if (types.empty()) return "style=solid color=gray";

    // Use the first type for color
    RefType primary = *types.begin();
    std::string color = get_edge_color(primary);

    // Dashed for indirect calls
    std::string style = "solid";
    if (types.count(RefType::IndirectCall) || types.count(RefType::VirtualCall)) {
        style = "dashed";
    }

    // Build label from all types
    std::ostringstream label;
    bool first = true;
    for (RefType rt : types) {
        if (!first) label << ",";
        first = false;
        label << ref_type_name(rt);
    }

    std::ostringstream ss;
    ss << "style=" << style << " color=" << color;
    if (include_label)
        ss << " label=\"" << label.str() << "\"";
    return ss.str();
}

std::string DotWriter::render(
    const std::set<ida::Address> &functions,
    const std::vector<Edge> &edges,
    const std::set<ida::Address> &start_functions,
    const DumpOptions &opts
) {
    std::ostringstream out;
    std::set<ida::Address> rendered_functions;
    for (ida::Address ea : functions) {
        if (opts.tree_shake_stdlib_functions && is_system_function(ea)) continue;
        rendered_functions.insert(ea);
    }

    out << "digraph callgraph {\n";
    out << "    rankdir=" << normalized_rankdir(opts) << ";\n";
    if (opts.dot_ortho)
        out << "    splines=ortho;\n";
    out << "    node [shape=box fontname=\"Courier\" fontsize=10];\n";
    out << "    edge [fontname=\"Courier\" fontsize=8];\n\n";

    // Write nodes
    for (ida::Address ea : rendered_functions) {
        ida::Result<std::string> name = ida::function::name_at(ea);
        std::string label = (name && !name->empty()) ? *name : "?";

        std::string node_id = std::format("f_{:x}", ea);

        std::string style = "";
        if (start_functions.count(ea)) {
            style = " style=filled fillcolor=lightblue";
        }

        out << "    " << node_id << " [label=\"" << label << "\"" << style << "];\n";
    }

    out << "\n";

    // Write edges
    for (const auto &edge : edges) {
        if (!rendered_functions.count(edge.from) || !rendered_functions.count(edge.to))
            continue;

        std::string from_id = std::format("f_{:x}", edge.from);
        std::string to_id = std::format("f_{:x}", edge.to);

        std::string attrs = get_edge_style(edge.types, !opts.dot_omit_edge_labels);

        out << "    " << from_id << " -> " << to_id << " [" << attrs << "];\n";
    }

    out << "}\n";
    return out.str();
}

bool DotWriter::write(
    const std::string &path,
    const std::set<ida::Address> &functions,
    const std::vector<Edge> &edges,
    const std::set<ida::Address> &start_functions,
    const DumpOptions &opts
) {
    std::string text = render(functions, edges, start_functions, opts);
    std::ofstream out(path);
    if (!out) return false;
    out << text;
    return (bool)out;
}

} // namespace codedump
