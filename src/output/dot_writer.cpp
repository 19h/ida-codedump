#include "dot_writer.h"

#include "analysis/function_ranker.h"
#include "analysis/subsystem_clusterer.h"
#include "common/function_filter.h"

#include <ida/function.hpp>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <format>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

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

// ── Subsystem meta-graph rendering ───────────────────────────────────────

std::string html_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            default: out += c;
        }
    }
    return out;
}

// "dot-writer · graph (47 funcs)" -> "dot-writer · graph"
std::string strip_count_suffix(const std::string &label) {
    if (!label.empty() && label.back() == ')') {
        size_t p = label.rfind(" (");
        if (p != std::string::npos) return label.substr(0, p);
    }
    return label;
}

struct CatStyle { const char *fill; const char *border; const char *name; };

const CatStyle &category_style(const std::string &cat) {
    static const std::map<std::string, CatStyle> table = {
        {"decompiler",  {"#DDEEDD", "#4F9E54", "decompiler"}},
        {"graph",       {"#DCE6F5", "#4577C0", "graph / dot"}},
        {"types",       {"#E7DDF2", "#8B5FBF", "types"}},
        {"output",      {"#FCE9D6", "#D98A2B", "output / writer"}},
        {"xref",        {"#FAD9D6", "#C84B3E", "xref"}},
        {"disasm",      {"#E6E0CF", "#9C8A4E", "disasm"}},
        {"segment",     {"#FBE7C9", "#C9962B", "segment / loader"}},
        {"register",    {"#D9EEF0", "#3F9AA8", "register"}},
        {"io",          {"#F6E3C5", "#BE8A2E", "i/o"}},
        {"cli",         {"#E2E8D5", "#7E9A4E", "cli"}},
        {"provenance",  {"#E9DCF2", "#8E63B5", "provenance / ptn"}},
        {"text",        {"#EADAF0", "#9B59B6", "regex / text"}},
        {"crypto",      {"#F8D7E4", "#C0397B", "crypto"}},
        {"network",     {"#CFE3FF", "#2F6FD0", "network"}},
        {"compression", {"#E0E7D2", "#6B8C3E", "compression"}},
        {"database",    {"#D6EAF8", "#2E86C1", "database"}},
        {"stl_util",    {"#ECECEC", "#9E9E9E", "runtime / STL"}},
        {"other",       {"#E6E6EA", "#8A8A96", "other"}},
    };
    auto it = table.find(cat.empty() ? "other" : cat);
    if (it == table.end()) it = table.find("other");
    return it->second;
}

// Render the subsystem cluster-only meta-graph: one colored, sized node per
// subsystem, a decluttered inter-subsystem backbone, a demoted runtime hub,
// and a category legend. Deliberately ignores splines=ortho (an eyesore on a
// dense meta-graph) and per-edge ref-type labels.
std::string render_cluster_meta(
    const std::set<ida::Address> &funcs,
    const std::vector<Edge> &edges,
    const DumpOptions &opts) {
    SubsystemClustering cl = cluster_subsystems(
        funcs, edges, opts.subsystem_cluster_resolution);

    std::ostringstream out;
    out << "digraph subsystems {\n";
    // Hierarchical (dot) layout shows the call-flow direction between
    // subsystems. --rankdir and --ortho are honoured. `pack=true` tiles the
    // call backbone and the library/leaf subsystems (which only touch the
    // suppressed utility hub, so they are separate components) into a compact
    // image instead of one unreadable wide rank.
    out << "    bgcolor=\"#FAFBFD\";\n";
    out << "    rankdir=" << normalized_rankdir(opts) << ";\n";
    out << "    newrank=true;\n    pack=true;\n    packmode=\"node\";\n";
    out << "    splines=" << (opts.dot_ortho ? "ortho" : "spline") << ";\n";
    out << "    nodesep=0.35;\n    ranksep=0.85;\n    pad=0.35;\n";
    out << "    node [shape=box style=\"rounded,filled\" fontname=\"Helvetica\""
           " margin=0.14 penwidth=1.4];\n";
    out << "    edge [fontname=\"Helvetica\" arrowsize=0.7];\n\n";

    int util_id = -1, max_count = 1;
    for (const SubsystemCluster &c : cl.clusters) {
        if (c.utility) util_id = c.id;
        max_count = std::max(max_count, c.func_count);
    }

    int max_w = 1, max_nonutil_w = 1;
    for (const SubsystemClusterEdge &e : cl.cluster_edges) {
        max_w = std::max(max_w, e.count);
        if (e.from != util_id && e.to != util_id)
            max_nonutil_w = std::max(max_nonutil_w, e.count);
    }
    int tau = std::max(3, max_nonutil_w * 6 / 100);

    std::set<std::string> seen;
    for (const SubsystemCluster &c : cl.clusters) {
        if (c.functions.empty()) continue;
        std::string cat = c.utility ? "stl_util"
                        : (c.category.empty() ? "other" : c.category);
        seen.insert(cat);
        const CatStyle &st = category_style(cat);
        std::string name = strip_count_suffix(c.label);
        int fs = static_cast<int>(std::clamp(
            11.0 + 3.0 * std::log2(static_cast<double>(std::max(1, c.func_count))),
            11.0, 24.0));
        double bw = std::clamp(
            1.2 + 0.10 * std::sqrt(static_cast<double>(c.func_count)), 1.2, 4.2);

        out << "    c_" << c.id << " [label=<<B>" << html_escape(name) << "</B>"
            << "<BR/><FONT POINT-SIZE=\"9\" COLOR=\"#5a6270\">"
            << c.func_count << " funcs</FONT>";
        if (!c.evidence.empty())
            out << "<BR/><FONT POINT-SIZE=\"8\" COLOR=\"#8a94a6\">"
                << html_escape(c.evidence) << "</FONT>";
        out << "> fillcolor=\"" << st.fill << "\" color=\"" << st.border << "\""
            << " fontsize=" << fs << " penwidth=" << bw;
        if (c.utility) out << " style=\"rounded,filled,dashed\"";
        out << "];\n";
    }
    out << "\n";

    // Edge selection: keep the inter-subsystem backbone (>=tau, plus each
    // node's strongest non-utility link so nothing orphans); suppress the
    // utility hub's gravity-well edges down to the three strongest, dotted.
    const std::vector<SubsystemClusterEdge> &E = cl.cluster_edges;
    int m = static_cast<int>(E.size());
    std::vector<char> keep(m, 0);
    std::map<int, int> best_idx;
    for (int i = 0; i < m; ++i) {
        const SubsystemClusterEdge &e = E[i];
        if (e.from == util_id || e.to == util_id) continue;
        if (e.count >= tau) keep[i] = 1;
        for (int nd : {e.from, e.to}) {
            auto it = best_idx.find(nd);
            if (it == best_idx.end() || e.count > E[it->second].count)
                best_idx[nd] = i;
        }
    }
    for (const auto &[nd, idx] : best_idx) { (void)nd; keep[idx] = 1; }

    // Emit only the inter-subsystem call backbone. Utility-hub edges are fully
    // suppressed (the hub touches everything and is a layout gravity well);
    // subsystems that only call into it become their own components, which
    // `pack` tiles compactly rather than stacking in a wide rank.
    for (int i = 0; i < m; ++i) {
        const SubsystemClusterEdge &e = E[i];
        if (e.from == util_id || e.to == util_id) continue;
        if (!keep[i]) continue;
        double pw = std::min(6.0, 0.8 + 0.9 * std::log2(1.0 + e.count));
        double t = std::log2(1.0 + e.count) /
                   std::log2(1.0 + static_cast<double>(max_w));
        int a = static_cast<int>(std::clamp(0x40 + (0xCC - 0x40) * t, 64.0, 204.0));
        char col[16];
        std::snprintf(col, sizeof(col), "#334155%02X", a);
        out << "    c_" << e.from << " -> c_" << e.to
            << " [penwidth=" << pw << " color=\"" << col
            << "\" weight=" << e.count << "];\n";
    }

    // Legend: only the categories actually present. Skip entirely when there
    // are none — a zero-row HTML <TABLE> is a graphviz syntax error that would
    // make the whole .dot unrenderable (e.g. an empty / fully tree-shaken set).
    if (!seen.empty()) {
        out << "\n    subgraph cluster_legend {\n";
        out << "        label=\"subsystems\"; labelloc=t; fontname=\"Helvetica\";"
               " fontsize=10;\n";
        out << "        color=\"#d8dde5\"; style=\"rounded\";\n";
        out << "        legend [shape=plaintext margin=0 label=<"
               "<TABLE BORDER=\"0\" CELLBORDER=\"0\" CELLSPACING=\"3\">\n";
        for (const std::string &cat : seen) {
            const CatStyle &st = category_style(cat);
            out << "          <TR><TD BGCOLOR=\"" << st.fill
                << "\" WIDTH=\"16\"></TD><TD ALIGN=\"LEFT\"><FONT POINT-SIZE=\"9\">"
                << html_escape(st.name) << "</FONT></TD></TR>\n";
        }
        out << "        </TABLE>>];\n    }\n";
    }

    out << "}\n";
    return out.str();
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

    if (opts.dot_cluster_subsystems && opts.dot_cluster_only)
        return render_cluster_meta(rendered_functions, edges, opts);

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
        for (const SubsystemClusterEdge &aggregated : clustering.cluster_edges) {
            auto from_anchor = cluster_anchor.find(aggregated.from);
            auto to_anchor = cluster_anchor.find(aggregated.to);
            if (from_anchor == cluster_anchor.end() || to_anchor == cluster_anchor.end())
                continue;

            std::ostringstream extra;
            extra << "ltail=\"cluster_" << aggregated.from << "\" "
                  << "lhead=\"cluster_" << aggregated.to << "\"";
            if (aggregated.count > 1) {
                double penwidth = std::min(
                    5.0, 1.0 + static_cast<double>(aggregated.count) * 0.35);
                extra << " penwidth=" << penwidth
                      << " weight=" << aggregated.count;
            }
            write_edge(from_anchor->second, to_anchor->second,
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
