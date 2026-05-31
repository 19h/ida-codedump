#include "dot_writer.h"

#include <ida/function.hpp>

#include <format>
#include <fstream>
#include <sstream>

namespace codedump {

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

std::string DotWriter::get_edge_style(const std::set<RefType> &types) {
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
    ss << "style=" << style << " color=" << color
       << " label=\"" << label.str() << "\"";
    return ss.str();
}

std::string DotWriter::render(
    const std::set<ida::Address> &functions,
    const std::vector<Edge> &edges,
    const std::set<ida::Address> &start_functions
) {
    std::ostringstream out;
    out << "digraph callgraph {\n";
    out << "    rankdir=TB;\n";
    out << "    node [shape=box fontname=\"Courier\" fontsize=10];\n";
    out << "    edge [fontname=\"Courier\" fontsize=8];\n\n";

    // Write nodes
    for (ida::Address ea : functions) {
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
        std::string from_id = std::format("f_{:x}", edge.from);
        std::string to_id = std::format("f_{:x}", edge.to);

        std::string attrs = get_edge_style(edge.types);

        out << "    " << from_id << " -> " << to_id << " [" << attrs << "];\n";
    }

    out << "}\n";
    return out.str();
}

bool DotWriter::write(
    const std::string &path,
    const std::set<ida::Address> &functions,
    const std::vector<Edge> &edges,
    const std::set<ida::Address> &start_functions
) {
    std::string text = render(functions, edges, start_functions);
    std::ofstream out(path);
    if (!out) return false;
    out << text;
    return (bool)out;
}

} // namespace codedump
