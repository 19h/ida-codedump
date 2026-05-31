#include "metadata_apply.h"

#include <ida/comment.hpp>
#include <ida/decompiler.hpp>
#include <ida/function.hpp>
#include <ida/instruction.hpp>
#include <ida/name.hpp>
#include <ida/type.hpp>

#include <format>
#include <optional>
#include <sstream>

namespace codedump {

namespace {

inline bool tick(const MetadataApplyCb &cb, const MetadataApplyProgress &p) {
    if (!cb) return true;
    return cb(p);
}

std::optional<ida::Address> function_start(ida::Address ea) {
    ida::Result<ida::function::Function> function = ida::function::at(ea);
    if (!function) return std::nullopt;
    return static_cast<ida::Address>(function->start());
}

// Decode the call instruction at the given ea and return its direct call
// target, or ida::BadAddress if it isn't a direct call.
ida::Address resolve_direct_call(ida::Address at) {
    ida::Result<ida::instruction::Instruction> instruction =
        ida::instruction::decode(at);
    if (!instruction) return ida::BadAddress;

    ida::Result<ida::instruction::Operand> operand = instruction->operand(0);
    if (!operand) return ida::BadAddress;

    ida::instruction::OperandType type = operand->type();
    if (type != ida::instruction::OperandType::NearAddress
        && type != ida::instruction::OperandType::FarAddress) {
        return ida::BadAddress;
    }
    return static_cast<ida::Address>(operand->target_address());
}

// Apply per-function metadata once the fingerprint has been verified.
void apply_one_function(
    const FunctionMeta &fm, ida::Address target_ea,
    const MetadataApplyOptions &opts,
    MetadataApplyReport *rep)
{
    ida::Result<ida::function::Function> function = ida::function::at(target_ea);
    if (!function) return;

    // Function name.
    if (!fm.name.empty()) {
        ida::Status renamed = opts.overwrite_existing
            ? ida::name::force_set(target_ea, fm.name)
            : ida::name::set(target_ea, fm.name);
        if (renamed) {
            ++rep->names_applied;
        }
    }

    // Prototype.
    if (!fm.prototype.empty()) {
        std::string proto = fm.prototype;
        // IDA's declaration parser needs a trailing semicolon.
        if (!proto.empty() && proto.back() != ';') proto.push_back(';');
        if (ida::function::apply_decl(target_ea, proto))
            ++rep->prototypes_applied;
    }

    // Function-level comments.
    if (!fm.func_cmt.empty())
        if (ida::function::set_comment(target_ea, fm.func_cmt, false))
            ++rep->comments_applied;
    if (!fm.func_cmt_rpt.empty())
        if (ida::function::set_comment(target_ea, fm.func_cmt_rpt, true))
            ++rep->comments_applied;

    // Per-address comments.
    for (const auto &c : fm.comments) {
        ida::Address ea = target_ea + (ida::Address)c.rva;
        if (ea >= static_cast<ida::Address>(function->end())) continue;
        if (ida::comment::set(ea, c.text, c.repeatable))
            ++rep->comments_applied;
    }

    // Local variables (hex-rays user lvar settings).
    if (!fm.lvars.empty()) {
        for (const auto &lv : fm.lvars) {
            ida::decompiler::LocalVariableUserSetting setting;

            // Locator
            if (lv.loc_kind == LvarMeta::LK_REG) {
                setting.locator.kind = ida::decompiler::LocalVariableLocationKind::Register;
                setting.locator.register_id = lv.loc_reg;
            } else if (lv.loc_kind == LvarMeta::LK_STK) {
                setting.locator.kind = ida::decompiler::LocalVariableLocationKind::Stack;
                setting.locator.stack_offset = lv.loc_stk;
            }

            setting.locator.definition_address =
                (lv.defea_rva == 0 && lv.loc_kind == LvarMeta::LK_NONE)
                    ? ida::BadAddress
                    : static_cast<ida::Address>(target_ea + lv.defea_rva);
            setting.name = lv.name;
            setting.type_declaration = lv.type;

            if ((!setting.name.empty() || !setting.type_declaration.empty())
                && ida::decompiler::apply_user_lvar_setting(target_ea, setting))
                ++rep->lvars_applied;
        }
    }
}

// Verify the fingerprint of the function at target_ea against expected.
// Returns true on match. On mismatch, appends a one-line diagnosis to rep.
bool verify_fingerprint(
    const FunctionMeta &fm, ida::Address target_ea, MetadataApplyReport *rep)
{
    ida::Result<ida::function::Function> function = ida::function::at(target_ea);
    if (!function) {
        rep->mismatch_details.emplace_back(std::format(
            "function id={} name='{}': no function at target ea 0x{:X}",
            fm.id,
            fm.name,
            target_ea));
        return false;
    }
    FunctionFingerprint actual = compute_fingerprint(target_ea);
    if (actual == fm.fingerprint) return true;

    std::string detail = std::format(
        "id={} src='{}' src_ea=0x{:X} target_ea=0x{:X} fingerprint mismatch:",
        fm.id,
        fm.name,
        fm.ea,
        target_ea);
    detail += "\n";
    detail += fingerprint_mismatch_reason(fm.fingerprint, actual);
    rep->mismatch_details.push_back(std::move(detail));
    return false;
}

} // namespace

bool apply_metadata(
    const MetadataDocument &doc, ida::Address target_root_ea,
    const MetadataApplyOptions &opts, MetadataApplyReport *report,
    const MetadataApplyCb &cb)
{
    report->ok = false;

    if (doc.functions.empty()) {
        report->fatal_error = "metadata document has no functions";
        return false;
    }

    // Build id -> FunctionMeta lookup.
    std::map<uint32_t, const FunctionMeta *> by_id;
    const FunctionMeta *root_meta = nullptr;
    for (const auto &fm : doc.functions) {
        by_id[fm.id] = &fm;
        if (fm.ea == doc.source_root_ea) root_meta = &fm;
    }
    if (!root_meta) root_meta = &doc.functions.front();

    // ------------------------------------------------------------------
    // Phase 1: walk callees from the root via call-rva resolution to build
    // a (id -> target_ea) mapping AND verify fingerprints along the way.
    // ------------------------------------------------------------------
    std::map<uint32_t, ida::Address> id_to_target_ea;
    id_to_target_ea[root_meta->id] = target_root_ea;

    std::vector<uint32_t> layer = { root_meta->id };
    std::set<uint32_t> resolved;

    MetadataApplyProgress p;
    p.phase = "verify";
    p.total = doc.functions.size();

    while (!layer.empty()) {
        std::vector<uint32_t> next;
        for (uint32_t id : layer) {
            if (!resolved.insert(id).second) continue;

            ida::Address tgt = id_to_target_ea[id];
            const FunctionMeta *fm = by_id[id];
            if (!fm) continue;

            p.processed = resolved.size();
            p.current_source_ea = fm->ea;
            p.current_target_ea = tgt;
            p.current_name = fm->name.c_str();
            p.mismatches = report->functions_mismatched;
            if (!tick(cb, p)) return false;

            if (verify_fingerprint(*fm, tgt, report)) {
                ++report->functions_matched;
            } else {
                ++report->functions_mismatched;
                if (!opts.continue_on_mismatch) {
                    report->fatal_error =
                        "fingerprint mismatch (continue_on_mismatch=false)";
                    return false;
                }
                // Drop this subtree: don't try to resolve its callees.
                continue;
            }

            // Resolve callees by following the recorded call sites.
            for (const CalleeRef &cr : fm->callees) {
                if (id_to_target_ea.count(cr.callee_id)) {
                    // Already resolved (could be in the next layer already).
                    continue;
                }
                ida::Address call_at = tgt + (ida::Address)cr.call_rva;
                ida::Address cal_target = resolve_direct_call(call_at);
                if (cal_target == ida::BadAddress) {
                    report->mismatch_details.emplace_back(std::format(
                        "id={} src='{}': could not resolve callee id={} "
                        "via call at target 0x{:X} (+rva 0x{:X})",
                        fm->id,
                        fm->name,
                        cr.callee_id,
                        call_at,
                        cr.call_rva));
                    continue;
                }
                std::optional<ida::Address> tf = function_start(cal_target);
                if (!tf) continue;
                id_to_target_ea[cr.callee_id] = *tf;
                next.push_back(cr.callee_id);
            }
        }
        layer = std::move(next);
    }

    // ------------------------------------------------------------------
    // Phase 2: apply types (the type tree comes first so functions can
    // reference them).
    // ------------------------------------------------------------------
    if (!doc.types.empty()) {
        // Concatenate every type decl into one buffer and parse it in bulk.
        // IDA's declaration parser processes the ordered dependency list,
        // which is why we exported them in dependency order during the walk.
        std::string blob;
        for (const auto &t : doc.types) {
            blob += t.decl;
            if (!blob.empty() && blob.back() != '\n') blob += "\n";
        }

        MetadataApplyProgress pp = p;
        pp.phase = "types";
        pp.total = doc.types.size();
        pp.processed = 0;
        if (!tick(cb, pp)) return false;

        ida::Result<ida::type::ParseDeclarationsReport> parse_report =
            ida::type::parse_declarations(blob);
        if (parse_report) {
            std::size_t error_count = parse_report->error_count;
            report->types_applied =
                error_count >= doc.types.size() ? 0 : doc.types.size() - error_count;
        }
        pp.processed = report->types_applied;
        pp.applied_types = report->types_applied;
        if (!tick(cb, pp)) return false;
    }

    // ------------------------------------------------------------------
    // Phase 3: apply per-function metadata for everything that verified.
    // ------------------------------------------------------------------
    {
        MetadataApplyProgress pp;
        pp.phase = "apply";
        pp.total = id_to_target_ea.size();
        size_t i = 0;
        for (const auto &[id, tgt] : id_to_target_ea) {
            const FunctionMeta *fm = by_id[id];
            if (!fm) { ++i; continue; }
            // Skip functions that mismatched.
            // (We marked successful matches in functions_matched; here we
            // re-verify quickly by checking that the fingerprint still holds.)
            if (verify_fingerprint(*fm, tgt, report)) {
                apply_one_function(*fm, tgt, opts, report);
            }
            ++i;
            pp.processed = i;
            pp.current_source_ea = fm->ea;
            pp.current_target_ea = tgt;
            pp.current_name = fm->name.c_str();
            pp.applied_names = report->names_applied;
            pp.applied_protos = report->prototypes_applied;
            pp.applied_cmts = report->comments_applied;
            pp.applied_lvars = report->lvars_applied;
            pp.applied_types = report->types_applied;
            if (!tick(cb, pp)) return false;
        }
    }

    report->ok = true;
    return true;
}

} // namespace codedump
