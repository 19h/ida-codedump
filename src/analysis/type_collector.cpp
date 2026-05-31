#include "type_collector.h"

#include <ida/decompiler.hpp>
#include <ida/function.hpp>
#include <ida/name.hpp>
#include <ida/type.hpp>

#include <algorithm>
#include <format>
#include <sstream>

namespace codedump {

void TypeCollector::collect_from_function(ida::Address func_ea) {
    ida::Result<ida::decompiler::ReferencedTypeCollection> collected =
        ida::decompiler::collect_referenced_types(func_ea);
    if (!collected) return;

    ordinals_.insert(collected->ordinals.begin(), collected->ordinals.end());
    for (const auto &entry : collected->used_offsets) {
        auto &offsets = used_offsets_[entry.type_name];
        offsets.insert(entry.byte_offsets.begin(), entry.byte_offsets.end());
    }
}

void TypeCollector::add_vtables(const std::vector<VTableEntry> &vtables) {
    vtables_.insert(vtables_.end(), vtables.begin(), vtables.end());
}

std::string TypeCollector::emit(bool size_comments, bool trim_unreferenced) const {
    std::ostringstream ss;

    if (!ordinals_.empty()) {
        ss << "// ============================================================\n";
        ss << "// Referenced types (" << ordinals_.size()
           << " ordinals, recursively resolved";
        if (trim_unreferenced) ss << ", trimmed to accessed fields";
        ss << ")\n";
        ss << "// ============================================================\n";

        ida::type::TypeRenderOptions options;
        options.size_comments = size_comments;
        options.trim_unreferenced = trim_unreferenced;
        options.used_offsets.reserve(used_offsets_.size());
        for (const auto &[name, offsets] : used_offsets_) {
            ida::type::UsedMemberOffsets entry;
            entry.type_name = name;
            entry.byte_offsets.assign(offsets.begin(), offsets.end());
            options.used_offsets.push_back(std::move(entry));
        }

        std::vector<std::uint32_t> seeds;
        if (trim_unreferenced) {
            for (std::uint32_t ordinal : ordinals_) {
                ida::Result<std::string> name = ida::type::local_type_name(ordinal);
                if (!name) continue;
                auto it = used_offsets_.find(*name);
                if (it != used_offsets_.end() && !it->second.empty())
                    seeds.push_back(ordinal);
            }
        } else {
            seeds.assign(ordinals_.begin(), ordinals_.end());
        }

        ida::Result<std::string> body =
            ida::type::render_ordinal_declarations(seeds, options);
        if (!body || body->empty())
            ss << "// (type renderer produced no output)\n";
        else
            ss << *body;
        ss << "// ============================================================\n\n";
    }

    if (!vtables_.empty()) {
        std::map<ida::Address, std::vector<const VTableEntry*>> by_vt;
        for (const auto &e : vtables_)
            by_vt[e.vtable_ea].push_back(&e);

        ss << "// ============================================================\n";
        ss << "// VTables (" << by_vt.size() << ")\n";
        ss << "// ============================================================\n";
        for (auto &[vt_ea, entries] : by_vt) {
            ida::Result<std::string> vt_name = ida::name::get(vt_ea);
            std::string vt_label = (vt_name && !vt_name->empty()) ? *vt_name : "(unnamed)";
            ss << "// vtable " << vt_label << " @ "
               << std::format("0x{:X}", vt_ea) << "\n";

            std::sort(entries.begin(), entries.end(),
                      [](const VTableEntry *a, const VTableEntry *b) {
                          return a->offset < b->offset;
                      });

            for (const VTableEntry *e : entries) {
                ida::Result<std::string> fname = ida::function::name_at(e->func_ea);
                std::string function_label = (fname && !fname->empty()) ? *fname : "?";
                ss << "//   [+0x" << std::hex << e->offset << std::dec << "] "
                   << function_label << " @ "
                   << std::format("0x{:X}", e->func_ea) << "\n";
            }
            ss << "\n";
        }
        ss << "// ============================================================\n\n";
    }

    return ss.str();
}

} // namespace codedump
