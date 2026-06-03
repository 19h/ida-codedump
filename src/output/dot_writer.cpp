#include "dot_writer.h"

#include "analysis/function_ranker.h"
#include "analysis/subsystem_clusterer.h"
#include "common/function_filter.h"

#include <ida/function.hpp>

#include <algorithm>
#include <cctype>
#include <format>
#include <fstream>
#include <map>
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
    if (opts.dot_cluster_subsystems)
        out << "    compound=true;\n";
    out << "    node [shape=box fontname=\"Courier\" fontsize=10];\n";
    out << "    edge [fontname=\"Courier\" fontsize=8];\n\n";

    std::vector<ida::Address> ordered_functions =
        order_functions(rendered_functions, edges, start_functions,
                        opts.function_order);

    SubsystemClustering clustering;
    std::map<int, ida::Address> cluster_anchor;
    if (opts.dot_cluster_subsystems) {
        clustering = cluster_subsystems(
            rendered_functions, edges, opts.subsystem_cluster_resolution);
    }

    auto write_node = [&](ida::Address ea, const std::string &indent) {
        ida::Result<std::string> name = ida::function::name_at(ea);
        std::string label = (name && !name->empty()) ? *name : "?";

        std::string node_id = std::format("f_{:x}", ea);

        std::string style = "";
        if (start_functions.count(ea)) {
            style = " style=filled fillcolor=lightblue";
        }

        out << indent << node_id << " [label=\"" << label << "\"" << style << "];\n";
    };

    if (opts.dot_cluster_subsystems) {
        std::set<ida::Address> emitted;

        for (const SubsystemCluster &cluster : clustering.clusters) {
            if (cluster.functions.empty()) continue;
            out << "    subgraph cluster_" << cluster.id << " {\n";
            out << "        label=\"" << cluster.label << "\";\n";
            out << "        style=\"" << (cluster.utility ? "dashed,rounded" : "rounded") << "\";\n";
            out << "        color=\"" << (cluster.utility ? "gray60" : "gray35") << "\";\n";
            out << "        fontname=\"Courier\";\n";
            out << "        fontsize=10;\n";

            std::set<ida::Address> cluster_functions(
                cluster.functions.begin(), cluster.functions.end());
            for (ida::Address ea : ordered_functions) {
                if (!cluster_functions.count(ea)) continue;
                if (!cluster_anchor.count(cluster.id))
                    cluster_anchor[cluster.id] = ea;
                write_node(ea, "        ");
                emitted.insert(ea);
            }
            out << "    }\n";
        }

        for (ida::Address ea : ordered_functions) {
            if (emitted.count(ea)) continue;
            write_node(ea, "    ");
        }
    } else {
        // Write nodes
        for (ida::Address ea : ordered_functions) {
            write_node(ea, "    ");
        }
    }

    out << "\n";

    auto write_edge = [&](ida::Address from, ida::Address to,
                          const std::set<RefType> &types,
                          const std::string &extra_attrs = "") {
        std::string from_id = std::format("f_{:x}", from);
        std::string to_id = std::format("f_{:x}", to);
        std::string attrs = get_edge_style(types, !opts.dot_omit_edge_labels);
        out << "    " << from_id << " -> " << to_id << " [" << attrs;
        if (!extra_attrs.empty())
            out << " " << extra_attrs;
        out << "];\n";
    };

    if (opts.dot_cluster_subsystems
        && opts.dot_collapse_subsystems
        && !cluster_anchor.empty()) {
        struct AggregatedEdge {
            ida::Address from = ida::BadAddress;
            ida::Address to = ida::BadAddress;
            std::set<RefType> types;
            int count = 0;
        };
        std::map<std::pair<int, int>, AggregatedEdge> cluster_edges;

        for (const auto &edge : edges) {
            if (!rendered_functions.count(edge.from) || !rendered_functions.count(edge.to))
                continue;

            auto from_cluster = clustering.cluster_by_function.find(edge.from);
            auto to_cluster = clustering.cluster_by_function.find(edge.to);
            if (from_cluster == clustering.cluster_by_function.end()
                || to_cluster == clustering.cluster_by_function.end()) {
                write_edge(edge.from, edge.to, edge.types);
                continue;
            }

            int from_id = from_cluster->second;
            int to_id = to_cluster->second;
            if (from_id == to_id)
                continue;

            auto &aggregated =
                cluster_edges[std::make_pair(from_id, to_id)];
            aggregated.from = cluster_anchor[from_id];
            aggregated.to = cluster_anchor[to_id];
            aggregated.types.insert(edge.types.begin(), edge.types.end());
            ++aggregated.count;
        }

        for (const auto &[cluster_pair, aggregated] : cluster_edges) {
            std::ostringstream extra;
            extra << "ltail=\"cluster_" << cluster_pair.first << "\" "
                  << "lhead=\"cluster_" << cluster_pair.second << "\"";
            if (aggregated.count > 1) {
                double penwidth = std::min(
                    5.0, 1.0 + static_cast<double>(aggregated.count) * 0.35);
                extra << " penwidth=" << penwidth
                      << " weight=" << aggregated.count;
            }
            write_edge(aggregated.from, aggregated.to,
                       aggregated.types, extra.str());
        }
    } else {
        // Write edges
        for (const auto &edge : edges) {
            if (!rendered_functions.count(edge.from) || !rendered_functions.count(edge.to))
                continue;

            write_edge(edge.from, edge.to, edge.types);
        }
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
