#include "ptn_emitter.h"

#include <sstream>
#include <algorithm>
#include <iomanip>

namespace codedump {

PTNEmitter::PTNEmitter(const std::map<ida::Address, FunctionSummary> &summaries)
    : summaries_(summaries)
{
    // Build name map
    for (const auto &[ea, fs] : summaries_) {
        name_by_ea_[ea] = fs.func_name;
    }
    assign_fids();
}

void PTNEmitter::assign_fids() {
    std::vector<ida::Address> sorted_eas;
    for (const auto &[ea, _] : summaries_) {
        sorted_eas.push_back(ea);
    }
    std::sort(sorted_eas.begin(), sorted_eas.end());

    int n = 1;
    for (ida::Address ea : sorted_eas) {
        std::string id = "F" + std::to_string(n++);
        fid_by_ea_[ea] = id;
        ea_by_fid_[id] = ea;
    }
}

std::string PTNEmitter::fid(ida::Address ea) const {
    auto it = fid_by_ea_.find(ea);
    if (it != fid_by_ea_.end()) {
        return it->second;
    }
    return "F?";
}

std::string PTNEmitter::fmt_slice(std::optional<int> off, std::optional<int> length, const std::string &member) {
    if (!member.empty()) {
        return "." + member;
    }
    if (!off.has_value() && !length.has_value()) {
        return "";
    }
    std::ostringstream ss;
    ss << "@[";
    if (off.has_value()) {
        ss << "0x" << std::hex << std::uppercase << off.value();
    } else {
        ss << "?";
    }
    ss << ":";
    if (length.has_value()) {
        ss << "0x" << std::hex << std::uppercase << length.value();
    } else {
        ss << "?";
    }
    ss << "]";
    return ss.str();
}

std::string PTNEmitter::fmt_meta(const std::map<std::string, std::string> &meta) {
    if (meta.empty()) {
        return "";
    }
    std::ostringstream ss;
    ss << " {";
    bool first = true;
    for (const auto &[k, v] : meta) {
        if (!first) ss << ",";
        first = false;
        ss << k << "=" << v;
    }
    ss << "}";
    return ss.str();
}

std::string PTNEmitter::fmt_node_L(const std::string &fid_str, int lidx, std::optional<int> off, std::optional<int> length,
                                   const std::string &mode, const std::string &cast, const std::string &name,
                                   const std::string &member, const std::map<std::string, std::string> &meta) {
    std::string ident = !name.empty() ? name : (fid_str + "," + std::to_string(lidx));
    std::string s = "L(" + ident + ")" + fmt_slice(off, length, member) + mode;
    if (!cast.empty()) {
        s += ":(" + cast + ")";
    }
    s += fmt_meta(meta);
    return s;
}

std::string PTNEmitter::fmt_node_P(const std::string &fid_str, int pidx, std::optional<int> off, std::optional<int> length,
                                   const std::string &mode, const std::string &cast, const std::string &name,
                                   const std::string &member, const std::map<std::string, std::string> &meta) {
    std::string ident = !name.empty() ? name : (fid_str + "," + std::to_string(pidx));
    std::string s = "P(" + ident + ")" + fmt_slice(off, length, member) + mode;
    if (!cast.empty()) {
        s += ":(" + cast + ")";
    }
    s += fmt_meta(meta);
    return s;
}

std::string PTNEmitter::fmt_node_A(const std::string &fid_or_name, int arg_index, const std::map<std::string, std::string> &meta) {
    std::string s = "A(" + fid_or_name + "," + std::to_string(arg_index) + ")";
    s += fmt_meta(meta);
    return s;
}

std::string PTNEmitter::fmt_node_G(ida::Address ea, std::optional<int> off, std::optional<int> length, const std::string &name,
                                   const std::string &member, const std::map<std::string, std::string> &meta) {
    std::ostringstream ss;
    if (!name.empty()) {
        ss << "G(" << name << ")";
    } else {
        ss << "G(0x" << std::hex << std::uppercase << ea << ")";
    }
    ss << fmt_slice(off, length, member);
    ss << fmt_meta(meta);
    return ss.str();
}

std::string PTNEmitter::fmt_node_C(uint64_t val, const std::map<std::string, std::string> &meta) {
    std::ostringstream ss;
    ss << "C(0x" << std::hex << std::uppercase << val << ")";
    ss << fmt_meta(meta);
    return ss.str();
}

std::string PTNEmitter::fmt_node_R(const std::string &fid_str, const std::string &name, const std::map<std::string, std::string> &meta) {
    std::string ident = !name.empty() ? name : fid_str;
    std::string s = "R(" + ident + ")";
    s += fmt_meta(meta);
    return s;
}

std::string PTNEmitter::fmt_node_F(const std::string &fid_str, const std::string &name, const std::map<std::string, std::string> &meta) {
    std::string ident = !name.empty() ? name : fid_str;
    std::string s = "F(" + ident + ")";
    s += fmt_meta(meta);
    return s;
}

std::string PTNEmitter::fmt_origin(BaseKind kind, ida::Address fea, int idx, const std::string &name,
                                   std::optional<int> off, std::optional<int> length, const std::string &mode,
                                   const std::string &cast, const std::string &member,
                                   const std::map<std::string, std::string> &meta) {
    std::string fid_str = fid(fea);
    switch (kind) {
        case BaseKind::Local:
            return fmt_node_L(fid_str, std::max(idx, -1), off, length, mode, cast, name, member, meta);
        case BaseKind::Param:
            return fmt_node_P(fid_str, std::max(idx, -1), off, length, mode, cast, name, member, meta);
        case BaseKind::Global:
            return fmt_node_G(idx, off, length, name, member, meta);
        case BaseKind::Constant:
            return fmt_node_C(idx, meta);
        case BaseKind::Return:
            return fmt_node_R(fid_str, name, meta);
        default:
            return "U()" + fmt_meta(meta);
    }
}

std::string PTNEmitter::dict_header(const std::set<ida::Address> &restrict_eas) {
    std::vector<ida::Address> eas(restrict_eas.begin(), restrict_eas.end());
    std::sort(eas.begin(), eas.end());

    std::ostringstream ss;
    ss << "D:";
    bool first = true;
    for (ida::Address ea : eas) {
        if (!first) ss << ";";
        first = false;
        std::string fid_str = fid(ea);
        auto it = name_by_ea_.find(ea);
        std::string name = (it != name_by_ea_.end()) ? it->second : "";
        ss << fid_str << "=0x" << std::hex << std::uppercase << ea;
        if (!name.empty()) {
            ss << "," << name;
        }
    }
    return ss.str();
}

std::map<std::pair<ida::Address, int>, std::vector<PTNEmitter::IncomingEntry>> PTNEmitter::build_incoming_map() {
    std::map<std::pair<ida::Address, int>, std::vector<IncomingEntry>> result;

    for (const auto &[caller_ea, fs] : summaries_) {
        for (const auto &au : fs.arg_uses) {
            if (au.callee_ea == ida::BadAddress) continue;

            auto key = std::make_pair(au.callee_ea, au.arg_idx);
            IncomingEntry entry;
            entry.caller_ea = caller_ea;
            entry.origin_kind = au.origin_kind;
            entry.origin_id = 0;  // Will use origin_name instead
            entry.origin_name = au.origin_name;
            entry.off = au.offset != 0 ? std::optional<int>(au.offset) : std::nullopt;
            entry.length = std::nullopt;
            entry.mode = au.mode;
            entry.cast = "";
            entry.conf = "med";
            entry.cs_ea = au.call_ea;
            entry.member = "";
            result[key].push_back(entry);
        }
    }
    return result;
}

std::map<std::pair<ida::Address, int>, std::vector<PTNEmitter::ParamForwardEntry>> PTNEmitter::build_param_forward() {
    std::map<std::pair<ida::Address, int>, std::vector<ParamForwardEntry>> result;

    for (const auto &[fea, fs] : summaries_) {
        for (const auto &au : fs.arg_uses) {
            if (au.origin_kind == BaseKind::Param && au.callee_ea != ida::BadAddress) {
                // Find parameter index from name
                int pidx = -1;
                for (size_t i = 0; i < fs.params.size(); i++) {
                    if (fs.params[i] == au.origin_name) {
                        pidx = (int)i;
                        break;
                    }
                }
                if (pidx >= 0) {
                    auto key = std::make_pair(fea, pidx);
                    ParamForwardEntry pfe;
                    pfe.callee_ea = au.callee_ea;
                    pfe.arg_idx = au.arg_idx;
                    if (au.offset != 0) {
                        pfe.meta["off"] = std::to_string(au.offset);
                    }
                    if (!au.mode.empty()) {
                        pfe.meta["mode"] = au.mode;
                    }
                    pfe.meta["conf"] = au.confidence;
                    result[key].push_back(pfe);
                }
            }
        }
    }
    return result;
}

void PTNEmitter::emit_chains_bfs(
    const std::string &origin,
    ida::Address initial_callee,
    int initial_arg,
    int max_depth,
    const std::map<std::pair<ida::Address, int>, std::vector<ParamForwardEntry>> &param_forward,
    std::vector<std::string> &output_lines
) {
    // BFS frontier: (callee_ea, arg_idx, depth, chain_so_far, accumulated_offset)
    struct BfsEntry {
        ida::Address callee_ea;
        int arg_idx;
        int depth;
        std::string chain;
        int accumulated_offset;
    };

    std::vector<BfsEntry> frontier;
    std::set<std::pair<ida::Address, int>> visited;

    // Initial entry
    std::string initial_chain = "A(" + fid(initial_callee) + "," + std::to_string(initial_arg) + ")";
    frontier.push_back({initial_callee, initial_arg, 1, initial_chain, 0});

    while (!frontier.empty()) {
        BfsEntry current = frontier.back();
        frontier.pop_back();

        if (current.depth > max_depth) continue;

        auto key = std::make_pair(current.callee_ea, current.arg_idx);
        if (visited.count(key)) continue;
        visited.insert(key);

        auto it = param_forward.find(key);
        if (it != param_forward.end()) {
            for (const auto &pfe : it->second) {
                // Calculate new offset
                int new_offset = current.accumulated_offset;
                auto off_it = pfe.meta.find("off");
                if (off_it != pfe.meta.end()) {
                    new_offset += std::stoi(off_it->second);
                }

                // Build the new chain segment
                std::ostringstream next_link;
                next_link << " -> A(" << fid(pfe.callee_ea) << "," << pfe.arg_idx << ")";

                std::string new_chain = current.chain + next_link.str();

                // Emit the chain
                std::ostringstream line;
                line << "// @PTN E:" << origin << " -> " << new_chain;

                // Add offset info if accumulated
                if (new_offset != 0) {
                    line << " @[0x" << std::hex << std::uppercase << new_offset << ":?]";
                }

                output_lines.push_back(line.str());

                // Continue BFS
                frontier.push_back({pfe.callee_ea, pfe.arg_idx, current.depth + 1, new_chain, new_offset});
            }
        }
    }
}

std::map<ida::Address, std::string> PTNEmitter::per_function_annotations(int callee_depth) {
    auto incoming_map = build_incoming_map();
    auto param_forward = build_param_forward();
    std::map<ida::Address, std::string> result;

    for (const auto &[fea, fs] : summaries_) {
        std::string fid_str = fid(fea);
        std::vector<std::string> lines;

        // Dictionary line
        std::ostringstream dict_line;
        dict_line << "// @PTN D:" << fid_str << "=0x" << std::hex << std::uppercase << fea << "," << fs.func_name;
        lines.push_back(dict_line.str());

        // Aliases
        for (const auto &alias : fs.aliases) {
            std::ostringstream ss;
            ss << "// @PTN A:" << (alias.lhs_kind == BaseKind::Local ? "L" : "P") << "(" << alias.lhs_name << ")";
            ss << ":=";

            std::map<std::string, std::string> meta;
            meta["conf"] = "med";

            std::optional<int> off = alias.offset != 0 ? std::optional<int>(alias.offset) : std::nullopt;
            ss << fmt_origin(alias.rhs_kind, fea, 0, alias.rhs_name, off, std::nullopt, "", "", "", meta);
            lines.push_back(ss.str());
        }

        // Incoming parameter annotations (I:)
        for (size_t pidx = 0; pidx < fs.params.size(); pidx++) {
            auto key = std::make_pair(fea, (int)pidx);
            auto it = incoming_map.find(key);
            if (it != incoming_map.end()) {
                for (const auto &ent : it->second) {
                    std::map<std::string, std::string> meta;
                    meta["conf"] = ent.conf;
                    if (ent.cs_ea != 0) {
                        std::ostringstream cs_ss;
                        cs_ss << "0x" << std::hex << std::uppercase << ent.cs_ea;
                        meta["cs"] = cs_ss.str();
                    }
                    meta["caller"] = fid(ent.caller_ea);

                    std::string origin = fmt_origin(ent.origin_kind, ent.caller_ea, ent.origin_id, ent.origin_name,
                                                    ent.off, ent.length, ent.mode, ent.cast, ent.member, meta);
                    std::string dst = fmt_node_P(fid_str, (int)pidx, std::nullopt, std::nullopt, "", "", fs.params[pidx], "", {});

                    std::ostringstream ss;
                    ss << "// @PTN I:" << origin << " -> " << dst;
                    lines.push_back(ss.str());
                }
            }
        }

        // Outgoing argument annotations (E:)
        for (const auto &au : fs.arg_uses) {
            if (au.callee_ea == ida::BadAddress) continue;

            std::map<std::string, std::string> meta;
            meta["conf"] = "med";
            if (au.call_ea != 0) {
                std::ostringstream cs_ss;
                cs_ss << "0x" << std::hex << std::uppercase << au.call_ea;
                meta["cs"] = cs_ss.str();
            }

            std::optional<int> off = au.offset != 0 ? std::optional<int>(au.offset) : std::nullopt;
            std::string origin = fmt_origin(au.origin_kind, fea, 0, au.origin_name, off, std::nullopt, au.mode, "", "", meta);

            // Get callee name
            std::string callee_name;
            auto callee_it = name_by_ea_.find(au.callee_ea);
            if (callee_it != name_by_ea_.end()) {
                callee_name = callee_it->second;
            } else {
                callee_name = fid(au.callee_ea);
            }

            std::ostringstream ss;
            ss << "// @PTN E:" << origin << " -> " << fmt_node_A(callee_name, au.arg_idx, {});
            lines.push_back(ss.str());

            // Use BFS for multi-level parameter forwarding
            if (callee_depth > 1 && (au.origin_kind == BaseKind::Local || au.origin_kind == BaseKind::Param)) {
                emit_chains_bfs(origin, au.callee_ea, au.arg_idx, callee_depth, param_forward, lines);
            }
        }

        // Global access annotations (G:)
        for (const auto &ga : fs.global_accesses) {
            std::ostringstream ss;
            if (ga.is_write) {
                ss << "// @PTN G:" << fmt_node_F(fid_str, fs.func_name, {}) << " -> "
                   << fmt_node_G(ga.global_ea, std::nullopt, std::nullopt, ga.global_name, "", {});
            } else {
                ss << "// @PTN G:" << fmt_node_G(ga.global_ea, std::nullopt, std::nullopt, ga.global_name, "", {})
                   << " -> " << fmt_node_F(fid_str, fs.func_name, {});
            }
            lines.push_back(ss.str());
        }

        // Join lines
        std::ostringstream result_ss;
        for (const auto &line : lines) {
            result_ss << line << "\n";
        }
        result[fea] = result_ss.str();
    }

    return result;
}

std::map<ida::Address, std::map<ida::Address, std::vector<std::string>>> PTNEmitter::per_instruction_hints(int callee_depth) {
    std::map<ida::Address, std::map<ida::Address, std::vector<std::string>>> hints;
    auto param_forward = build_param_forward();

    for (const auto &[fea, fs] : summaries_) {
        for (const auto &au : fs.arg_uses) {
            if (au.call_ea == 0 || au.callee_ea == ida::BadAddress) continue;

            std::map<std::string, std::string> meta;
            meta["conf"] = "med";

            std::optional<int> off = au.offset != 0 ? std::optional<int>(au.offset) : std::nullopt;
            std::string origin = fmt_origin(au.origin_kind, fea, 0, au.origin_name, off, std::nullopt, au.mode, "", "", meta);

            std::string callee_name;
            auto callee_it = name_by_ea_.find(au.callee_ea);
            if (callee_it != name_by_ea_.end()) {
                callee_name = callee_it->second;
            } else {
                callee_name = fid(au.callee_ea);
            }

            std::ostringstream ss;
            ss << "@PTN E:" << origin << " -> " << fmt_node_A(callee_name, au.arg_idx, {});
            hints[fea][au.call_ea].push_back(ss.str());

            // Use BFS for multi-level parameter forwarding in hints
            if (callee_depth > 1 && (au.origin_kind == BaseKind::Local || au.origin_kind == BaseKind::Param)) {
                std::vector<std::string> chain_lines;
                emit_chains_bfs(origin, au.callee_ea, au.arg_idx, callee_depth, param_forward, chain_lines);
                for (const auto &line : chain_lines) {
                    // Remove "// " prefix for assembly hints
                    std::string hint = line;
                    if (hint.substr(0, 3) == "// ") {
                        hint = hint.substr(3);
                    }
                    hints[fea][au.call_ea].push_back(hint);
                }
            }
        }

        // Global access hints
        for (const auto &ga : fs.global_accesses) {
            if (ga.access_ea == 0) continue;

            std::ostringstream ss;
            std::string fid_str = fid(fea);
            if (ga.is_write) {
                ss << "@PTN G:" << fmt_node_F(fid_str, fs.func_name, {}) << " -> "
                   << fmt_node_G(ga.global_ea, std::nullopt, std::nullopt, ga.global_name, "", {});
            } else {
                ss << "@PTN G:" << fmt_node_G(ga.global_ea, std::nullopt, std::nullopt, ga.global_name, "", {})
                   << " -> " << fmt_node_F(fid_str, fs.func_name, {});
            }
            hints[fea][ga.access_ea].push_back(ss.str());
        }
    }

    return hints;
}

std::string PTNEmitter::emit_ptn(
    const std::set<ida::Address> &start_eas,
    int callee_depth,
    const std::set<ida::Address> *restrict_eas
) {
    std::set<ida::Address> target_set;
    if (restrict_eas) {
        target_set = *restrict_eas;
    } else if (!start_eas.empty()) {
        target_set = start_eas;
    } else {
        for (const auto &[ea, _] : summaries_) {
            target_set.insert(ea);
        }
    }

    std::vector<std::string> lines;
    std::set<std::string> visited_lines;

    auto add_line = [&](const std::string &s) {
        if (visited_lines.find(s) == visited_lines.end()) {
            visited_lines.insert(s);
            lines.push_back(s);
        }
    };

    add_line("#PTN v1");
    add_line(dict_header(target_set));

    auto incoming_map = build_incoming_map();
    auto param_forward = build_param_forward();

    // Per-function annotations
    for (ida::Address fea : target_set) {
        auto it = summaries_.find(fea);
        if (it == summaries_.end()) continue;
        const auto &fs = it->second;
        std::string fid_str = fid(fea);

        // Dictionary entry
        std::ostringstream dict_ss;
        dict_ss << "D:" << fid_str << "=0x" << std::hex << std::uppercase << fea << "," << fs.func_name;
        add_line(dict_ss.str());

        // Aliases
        for (const auto &al : fs.aliases) {
            std::ostringstream ss;
            ss << "A:" << (al.lhs_kind == BaseKind::Local ? "L" : "P") << "(" << al.lhs_name << "):=";

            std::map<std::string, std::string> meta;
            meta["conf"] = "med";

            std::optional<int> off = al.offset != 0 ? std::optional<int>(al.offset) : std::nullopt;
            ss << fmt_origin(al.rhs_kind, fea, 0, al.rhs_name, off, std::nullopt, "", "", "", meta);
            add_line(ss.str());
        }
    }

    // Incoming parameter edges (I:)
    for (const auto &[key, entries] : incoming_map) {
        ida::Address callee_ea = key.first;
        int pidx = key.second;
        if (target_set.find(callee_ea) == target_set.end()) continue;

        auto callee_it = summaries_.find(callee_ea);
        std::string pname;
        if (callee_it != summaries_.end() && pidx < (int)callee_it->second.params.size()) {
            pname = callee_it->second.params[pidx];
        }
        std::string callee_fid = fid(callee_ea);

        for (const auto &ent : entries) {
            std::map<std::string, std::string> meta;
            meta["conf"] = ent.conf;
            if (ent.cs_ea != 0) {
                std::ostringstream cs_ss;
                cs_ss << "0x" << std::hex << std::uppercase << ent.cs_ea;
                meta["cs"] = cs_ss.str();
            }
            meta["caller"] = fid(ent.caller_ea);

            std::string origin = fmt_origin(ent.origin_kind, ent.caller_ea, ent.origin_id, ent.origin_name,
                                            ent.off, ent.length, ent.mode, ent.cast, ent.member, meta);
            std::string dst = fmt_node_P(callee_fid, pidx, std::nullopt, std::nullopt, "", "", pname, "", {});

            std::ostringstream ss;
            ss << "I:" << origin << " -> " << dst;
            add_line(ss.str());
        }
    }

    // Outgoing argument edges (E:) with BFS chain traversal
    for (ida::Address fea : target_set) {
        auto it = summaries_.find(fea);
        if (it == summaries_.end()) continue;

        for (const auto &au : it->second.arg_uses) {
            if (au.callee_ea == ida::BadAddress) continue;

            std::map<std::string, std::string> meta;
            meta["conf"] = au.confidence;
            if (au.call_ea != 0) {
                std::ostringstream cs_ss;
                cs_ss << "0x" << std::hex << std::uppercase << au.call_ea;
                meta["cs"] = cs_ss.str();
            }

            std::optional<int> off = au.offset != 0 ? std::optional<int>(au.offset) : std::nullopt;
            std::string origin = fmt_origin(au.origin_kind, fea, 0, au.origin_name, off, std::nullopt, au.mode, "", au.member_name, meta);

            std::string callee_name;
            auto callee_it = name_by_ea_.find(au.callee_ea);
            if (callee_it != name_by_ea_.end()) {
                callee_name = callee_it->second;
            } else {
                callee_name = fid(au.callee_ea);
            }

            std::ostringstream ss;
            ss << "E:" << origin << " -> " << fmt_node_A(callee_name, au.arg_idx, {});
            add_line(ss.str());

            // Use BFS for multi-level parameter forwarding
            if (callee_depth > 1 && (au.origin_kind == BaseKind::Local || au.origin_kind == BaseKind::Param)) {
                std::vector<std::string> chain_lines;
                emit_chains_bfs(origin, au.callee_ea, au.arg_idx, callee_depth, param_forward, chain_lines);
                for (const auto &line : chain_lines) {
                    // Remove "// " prefix for PTN format
                    std::string ptn_line = line;
                    if (ptn_line.substr(0, 3) == "// ") {
                        ptn_line = ptn_line.substr(3);
                    }
                    // Also remove "@PTN " prefix
                    if (ptn_line.substr(0, 5) == "@PTN ") {
                        ptn_line = ptn_line.substr(5);
                    }
                    add_line(ptn_line);
                }
            }
        }
    }

    // Global access edges (G:)
    std::map<ida::Address, std::set<ida::Address>> writers, readers;
    for (const auto &[fea, fs] : summaries_) {
        for (const auto &ga : fs.global_accesses) {
            if (ga.is_write) {
                writers[ga.global_ea].insert(fea);
            } else {
                readers[ga.global_ea].insert(fea);
            }
        }
    }

    for (const auto &[gea, ws] : writers) {
        auto rs_it = readers.find(gea);
        if (rs_it == readers.end()) continue;

        std::string gname;
        for (const auto &[_, fs] : summaries_) {
            for (const auto &ga : fs.global_accesses) {
                if (ga.global_ea == gea && !ga.global_name.empty()) {
                    gname = ga.global_name;
                    break;
                }
            }
            if (!gname.empty()) break;
        }

        for (ida::Address fw : ws) {
            for (ida::Address fr : rs_it->second) {
                if (target_set.find(fw) != target_set.end() || target_set.find(fr) != target_set.end()) {
                    std::ostringstream ss;
                    ss << "G:" << fmt_node_F(fid(fw), name_by_ea_[fw], {}) << " -> "
                       << fmt_node_G(gea, std::nullopt, std::nullopt, gname, "", {}) << " -> "
                       << fmt_node_F(fid(fr), name_by_ea_[fr], {});
                    add_line(ss.str());
                }
            }
        }
    }

    std::ostringstream result;
    for (const auto &line : lines) {
        result << line << "\n";
    }
    return result.str();
}

std::string PTNEmitter::emit_ptn_json(
    const std::set<ida::Address> &start_eas,
    int callee_depth,
    const std::set<ida::Address> *restrict_eas
) {
    std::set<ida::Address> target_set;
    if (restrict_eas) {
        target_set = *restrict_eas;
    } else if (!start_eas.empty()) {
        target_set = start_eas;
    } else {
        for (const auto &[ea, _] : summaries_) {
            target_set.insert(ea);
        }
    }

    auto incoming_map = build_incoming_map();

    std::ostringstream ss;
    ss << "{\n";
    ss << "  \"version\": \"1\",\n";

    // Dict
    ss << "  \"dict\": [";
    bool first = true;
    for (ida::Address ea : target_set) {
        if (!first) ss << ", ";
        first = false;
        ss << "{\"fid\": \"" << fid(ea) << "\", \"ea\": \"0x" << std::hex << ea << "\", \"name\": \"" << name_by_ea_[ea] << "\"}";
    }
    ss << "],\n";

    // Aliases
    ss << "  \"aliases\": [";
    first = true;
    for (ida::Address fea : target_set) {
        auto it = summaries_.find(fea);
        if (it == summaries_.end()) continue;
        const auto &fs = it->second;
        for (const auto &al : fs.aliases) {
            if (!first) ss << ", ";
            first = false;
            ss << "{\"func\": {\"fid\": \"" << fid(fea) << "\"}, ";
            ss << "\"dst\": {\"kind\": \"" << (al.lhs_kind == BaseKind::Local ? "L" : "P") << "\", \"name\": \"" << al.lhs_name << "\"}, ";
            ss << "\"src\": {\"kind\": \"";
            switch (al.rhs_kind) {
                case BaseKind::Local: ss << "L"; break;
                case BaseKind::Param: ss << "P"; break;
                case BaseKind::Global: ss << "G"; break;
                case BaseKind::Constant: ss << "C"; break;
                default: ss << "U"; break;
            }
            ss << "\", \"name\": \"" << al.rhs_name << "\"}}";
        }
    }
    ss << "],\n";

    // Calls
    ss << "  \"calls\": [";
    first = true;
    for (ida::Address fea : target_set) {
        auto it = summaries_.find(fea);
        if (it == summaries_.end()) continue;
        const auto &fs = it->second;
        for (const auto &au : fs.arg_uses) {
            if (au.callee_ea == ida::BadAddress) continue;
            if (!first) ss << ", ";
            first = false;
            ss << "{\"caller\": {\"fid\": \"" << fid(fea) << "\"}, ";
            ss << "\"callee\": {\"fid\": \"" << fid(au.callee_ea) << "\"}, ";
            ss << "\"arg_index\": " << std::dec << au.arg_idx << "}";
        }
    }
    ss << "],\n";

    // Globals
    ss << "  \"globals\": [";
    first = true;
    for (ida::Address fea : target_set) {
        auto it = summaries_.find(fea);
        if (it == summaries_.end()) continue;
        const auto &fs = it->second;
        for (const auto &ga : fs.global_accesses) {
            if (!first) ss << ", ";
            first = false;
            ss << "{\"func\": {\"fid\": \"" << fid(fea) << "\"}, ";
            ss << "\"op\": \"" << (ga.is_write ? "W" : "R") << "\", ";
            ss << "\"global_ea\": \"0x" << std::hex << ga.global_ea << "\", ";
            ss << "\"global_name\": \"" << ga.global_name << "\"}";
        }
    }
    ss << "],\n";

    // Inbound
    ss << "  \"inbound\": [";
    first = true;
    for (const auto &[key, entries] : incoming_map) {
        ida::Address callee_ea = key.first;
        int pidx = key.second;
        if (target_set.find(callee_ea) == target_set.end()) continue;

        for (const auto &ent : entries) {
            if (!first) ss << ", ";
            first = false;
            ss << "{\"to\": {\"fid\": \"" << fid(callee_ea) << "\", \"param\": " << std::dec << pidx << "}, ";
            ss << "\"from\": {\"fid\": \"" << fid(ent.caller_ea) << "\"}}";
        }
    }
    ss << "]\n";

    ss << "}\n";
    return ss.str();
}

} // namespace codedump
