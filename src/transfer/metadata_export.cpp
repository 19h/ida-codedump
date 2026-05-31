#include "metadata_export.h"

#include <ida/address.hpp>
#include <ida/comment.hpp>
#include <ida/database.hpp>
#include <ida/decompiler.hpp>
#include <ida/function.hpp>
#include <ida/instruction.hpp>
#include <ida/type.hpp>

#include <cstdio>
#include <ctime>
#include <optional>
#include <queue>
#include <set>

namespace codedump {

namespace {

// Map an absolute ea to a FunctionMeta id, allocating one if needed.
struct IdAllocator {
    std::map<ida::Address, uint32_t> ea_to_id;
    uint32_t next_id = 1;

    uint32_t intern(ida::Address ea) {
        auto it = ea_to_id.find(ea);
        if (it != ea_to_id.end()) return it->second;
        uint32_t id = next_id++;
        ea_to_id[ea] = id;
        return id;
    }
};

inline bool tick(const MetadataExportCb &cb, const MetadataExportProgress &p) {
    if (!cb) return true;
    return cb(p);
}

std::string function_name_or_unknown(ida::Address ea) {
    ida::Result<std::string> name = ida::function::name_at(ea);
    if (name && !name->empty()) return *name;
    return "?";
}

std::optional<ida::Address> function_start(ida::Address ea) {
    ida::Result<ida::function::Function> function = ida::function::at(ea);
    if (!function) return std::nullopt;
    return static_cast<ida::Address>(function->start());
}

std::optional<std::pair<ida::Address, ida::AddressSize>> direct_call_target(ida::Address ea) {
    ida::Result<ida::instruction::Instruction> instruction =
        ida::instruction::decode(ea);
    if (!instruction) return std::nullopt;

    ida::Result<ida::instruction::Operand> operand = instruction->operand(0);
    if (!operand) return std::make_pair(ida::BadAddress, instruction->size());

    ida::instruction::OperandType type = operand->type();
    if (type != ida::instruction::OperandType::NearAddress
        && type != ida::instruction::OperandType::FarAddress) {
        return std::make_pair(ida::BadAddress, instruction->size());
    }

    return std::make_pair(static_cast<ida::Address>(operand->target_address()),
                          instruction->size());
}

std::string read_arch_name() {
    ida::Result<std::string> processor = ida::database::processor_name();
    if (processor && !processor->empty()) return *processor;
    return std::string("unknown");
}

std::string iso_now() {
    time_t t = time(nullptr);
    struct tm tmv;
#ifdef _WIN32
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif
    char b[40];
    std::snprintf(b, sizeof(b), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                  tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
                  tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    return b;
}

// Collect comments on every head within the function's range.
void collect_comments(ida::Address start_ea, ida::Address end_ea, FunctionMeta *fm) {
    for (ida::Address ea = start_ea; ea != ida::BadAddress && ea < end_ea; ) {
        ida::Result<std::string> c = ida::comment::get(ea, false);
        if (c && !c->empty()) {
            CommentMeta cm;
            cm.rva = (uint64_t)(ea - start_ea);
            cm.repeatable = false;
            cm.text = *c;
            fm->comments.push_back(std::move(cm));
        }
        c = ida::comment::get(ea, true);
        if (c && !c->empty()) {
            CommentMeta cm;
            cm.rva = (uint64_t)(ea - start_ea);
            cm.repeatable = true;
            cm.text = *c;
            fm->comments.push_back(std::move(cm));
        }

        ida::Result<ida::Address> next = ida::address::next_head(ea, end_ea);
        if (!next) break;
        ea = *next;
    }
}

// Collect function-level comments + prototype.
void collect_func_header(ida::Address start_ea, FunctionMeta *fm) {
    ida::Result<std::string> c = ida::function::comment(start_ea, false);
    if (c) fm->func_cmt = *c;
    c = ida::function::comment(start_ea, true);
    if (c) fm->func_cmt_rpt = *c;

    ida::Result<std::string> prototype =
        ida::function::declaration(start_ea, fm->name);
    if (prototype) fm->prototype = *prototype;
}

// Collect outgoing call sites that target other functions in our id pool.
void collect_callees(ida::Address start_ea, ida::Address end_ea, IdAllocator &ids, FunctionMeta *fm,
                     std::set<ida::Address> &discovered) {
    for (ida::Address ea = start_ea; ea < end_ea; ) {
        std::optional<std::pair<ida::Address, ida::AddressSize>> decoded =
            direct_call_target(ea);
        if (!decoded) { ea++; continue; }

        ida::Address target = decoded->first;
        if (target != ida::BadAddress) {
            std::optional<ida::Address> tf = function_start(target);
            if (tf && *tf == target) {
                CalleeRef cr;
                cr.call_rva = (uint64_t)(ea - start_ea);
                cr.callee_id = ids.intern(target);
                fm->callees.push_back(cr);
                discovered.insert(target);
            }
        }
        ea += static_cast<ida::Address>(decoded->second);
    }
}

// Collect user lvar settings via hexrays.
void collect_lvars(ida::Address func_ea, FunctionMeta *fm) {
    ida::Result<std::vector<ida::decompiler::LocalVariableUserSetting>> settings =
        ida::decompiler::saved_user_lvar_settings(func_ea);
    if (!settings) return;

    for (const auto &setting : *settings) {
        LvarMeta lv;
        lv.name = setting.name;
        // Skip entries that have no user-set name AND no user-set type;
        // empty entries clutter the dump.
        if (lv.name.empty() && setting.type_declaration.empty()) continue;

        if (setting.locator.kind == ida::decompiler::LocalVariableLocationKind::Register)
            { lv.loc_kind = LvarMeta::LK_REG; lv.loc_reg = setting.locator.register_id; }
        else if (setting.locator.kind == ida::decompiler::LocalVariableLocationKind::Stack)
            { lv.loc_kind = LvarMeta::LK_STK; lv.loc_stk = setting.locator.stack_offset; }
        else
            lv.loc_kind = LvarMeta::LK_NONE;

        lv.defea_rva = (setting.locator.definition_address == ida::BadAddress) ? 0
                       : (uint64_t)(setting.locator.definition_address - func_ea);
        lv.type = setting.type_declaration;
        fm->lvars.push_back(std::move(lv));
    }
}

// Collect all named user types referenced by the function set. Reuses the
// same approach as TypeCollector but inline (we have cfunc here).
void collect_types(const std::set<ida::Address> &funcs,
                   MetadataDocument *doc,
                   const MetadataExportCb &cb)
{
    std::set<std::string> seen;
    uint32_t next_tid = 1;

    size_t total = funcs.size();
    size_t i = 0;
    for (ida::Address fea : funcs) {
        ++i;
        if (cb) {
            std::string fname = function_name_or_unknown(fea);
            MetadataExportProgress p;
            p.phase = "types";
            p.processed = i;
            p.total = total;
            p.current_ea = (uint64_t)fea;
            p.current_name = fname.c_str();
            p.types_collected = doc->types.size();
            if (!cb(p)) return;
        }

        ida::Result<ida::decompiler::ReferencedTypeCollection> collected =
            ida::decompiler::collect_referenced_types(fea);
        if (!collected) continue;

        ida::Result<std::vector<ida::type::TypeDeclaration>> declarations =
            ida::type::declarations_for_ordinals(collected->ordinals);
        if (!declarations) continue;

        for (const auto &declaration : *declarations) {
            if (declaration.name.empty() || !seen.insert(declaration.name).second)
                continue;

            TypeMeta tm;
            tm.id = next_tid++;
            tm.name = declaration.name;
            tm.decl = declaration.declaration;
            doc->types.push_back(std::move(tm));
        }
    }
}

} // namespace

bool export_metadata(
    ida::Address root_ea, const MetadataExportOptions &opts,
    MetadataDocument *out, const MetadataExportCb &cb)
{
    ida::Result<ida::function::Function> root = ida::function::at(root_ea);
    if (!root) return false;
    root_ea = static_cast<ida::Address>(root->start());

    out->schema_version = 1;
    ida::Result<ida::Address> image_base = ida::database::image_base();
    out->source_image_base = image_base ? static_cast<uint64_t>(*image_base) : 0;
    out->source_root_ea = (uint64_t)root_ea;
    out->source_arch = read_arch_name();
    out->created_at = iso_now();

    IdAllocator ids;
    ids.intern(root_ea);

    // BFS over callees up to `callee_depth` layers.
    std::set<ida::Address> visited;
    std::set<ida::Address> all_funcs = { root_ea };
    std::vector<ida::Address> layer = { root_ea };

    MetadataExportProgress p;
    p.phase = "graph";

    for (int d = 0; d < opts.callee_depth && !layer.empty(); d++) {
        std::vector<ida::Address> next;
        for (size_t li = 0; li < layer.size(); li++) {
            ida::Address ea = layer[li];
            if (!visited.insert(ea).second) continue;

            std::string fname = function_name_or_unknown(ea);
            p.processed = visited.size();
            p.total = all_funcs.size();
            p.current_ea = (uint64_t)ea;
            p.current_name = fname.c_str();
            if (!tick(cb, p)) return false;

            // Discover callees for the BFS frontier.
            ida::Result<ida::function::Function> function = ida::function::at(ea);
            if (!function) continue;
            ida::Address function_end = static_cast<ida::Address>(function->end());
            for (ida::Address a = static_cast<ida::Address>(function->start()); a < function_end; ) {
                std::optional<std::pair<ida::Address, ida::AddressSize>> decoded =
                    direct_call_target(a);
                if (!decoded) { a++; continue; }

                ida::Address target = decoded->first;
                if (target != ida::BadAddress) {
                    std::optional<ida::Address> tf = function_start(target);
                    if (tf && *tf == target) {
                        ids.intern(target);
                        if (all_funcs.insert(target).second &&
                            !visited.count(target))
                            next.push_back(target);
                    }
                }
                a += static_cast<ida::Address>(decoded->second);
            }
        }
        layer = std::move(next);
    }

    // Pass 2: per-function metadata.
    {
        size_t total = all_funcs.size();
        size_t i = 0;
        for (ida::Address fea : all_funcs) {
            ++i;
            std::string fname = function_name_or_unknown(fea);

            MetadataExportProgress pp;
            pp.phase = "metadata";
            pp.processed = i;
            pp.total = total;
            pp.current_ea = (uint64_t)fea;
            pp.current_name = fname.c_str();
            if (!tick(cb, pp)) return false;

            ida::Result<ida::function::Function> function = ida::function::at(fea);
            if (!function) continue;
            ida::Address function_start = static_cast<ida::Address>(function->start());
            ida::Address function_end = static_cast<ida::Address>(function->end());

            FunctionMeta fm;
            fm.id = ids.intern(fea);
            fm.ea = (uint64_t)fea;
            fm.rva = (uint64_t)(fea - out->source_image_base);
            fm.name = fname;
            fm.fingerprint = compute_fingerprint(fea);
            collect_func_header(function_start, &fm);
            collect_comments(function_start, function_end, &fm);
            collect_lvars(fea, &fm);
            std::set<ida::Address> dummy;
            collect_callees(function_start, function_end, ids, &fm, dummy);

            pp.comments_collected += fm.comments.size();
            pp.lvars_collected    += fm.lvars.size();
            (void)tick(cb, pp);

            out->functions.push_back(std::move(fm));
        }
    }

    // Pass 3: types.
    if (opts.include_types)
        collect_types(all_funcs, out, cb);

    // Final tick so callers see the totals.
    p.phase = "serialize";
    p.processed = out->functions.size();
    p.total = out->functions.size();
    p.types_collected = out->types.size();
    (void)tick(cb, p);

    return true;
}

} // namespace codedump
