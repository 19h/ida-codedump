#include "graph_builder.h"

#include "common/function_filter.h"

#include <ida/address.hpp>
#include <ida/data.hpp>
#include <ida/database.hpp>
#include <ida/function.hpp>
#include <ida/graph.hpp>
#include <ida/segment.hpp>
#include <ida/xref.hpp>

// Raw SDK instruction decoding. idax's ida::instruction::decode builds a
// formatted mnemonic (print_insn_mnem) and per-operand register-name strings
// on every call — ~1840 ns/insn. The graph walk only needs opcode class and
// operand types/values, so we decode with raw decode_insn + get_canon_mnem
// (~452 ns/insn, a ~4x reduction) which the per-feature profiling proved is
// the dominant cost of every decode-requiring ref type. idax's public headers
// don't expose the SDK base types, so pull <pro.h> in first (guarded).
#include "common/warn_off.h"
#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <ua.hpp>
#include <funcs.hpp>
#include <xref.hpp>
#include "common/warn_on.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <unordered_set>

namespace codedump {

namespace {

inline bool tick(const GraphProgressCb &cb, const GraphProgress &p) {
    if (!cb) return true;
    return cb(p);
}

std::string function_name_or_unknown(ida::Address ea) {
    ida::Result<std::string> name = ida::function::name_at(ea);
    if (name && !name->empty()) return *name;
    return "?";
}

std::optional<ida::Address> function_start(ida::Address ea) {
    // Raw get_func — we only need start_ea. idax's ida::function::at fully
    // populates a Function (incl. get_func_name + demangling) on every call,
    // which is pure overhead on this hot path (called per cref/dref/imm target).
    func_t *f = get_func(ea);
    if (f == nullptr) return std::nullopt;
    return static_cast<ida::Address>(f->start_ea);
}

bool database_is_64bit() {
    ida::Result<int> bits = ida::database::address_bitness();
    return bits && *bits == 64;
}

std::optional<ida::Address> next_idax_item(ida::Address ea, ida::Address end) {
    ida::Result<ida::Address> next = ida::address::next_head(ea, end);
    if (!next || *next == ida::BadAddress || *next <= ea) return std::nullopt;
    return static_cast<ida::Address>(*next);
}

std::optional<ida::Address> prev_idax_item(ida::Address ea, ida::Address start) {
    ida::Result<ida::Address> prev = ida::address::prev_head(ea, start);
    if (!prev || *prev == ida::BadAddress || *prev >= ea) return std::nullopt;
    return static_cast<ida::Address>(*prev);
}

std::optional<ida::Address> read_pointer(ida::Address ea, bool is64) {
    if (is64) {
        ida::Result<std::uint64_t> value = ida::data::read_qword(ea);
        if (!value) return std::nullopt;
        ida::Address target = static_cast<ida::Address>(*value);
        if (target == ida::BadAddress || target == 0) return std::nullopt;
        return target;
    }

    ida::Result<std::uint32_t> value = ida::data::read_dword(ea);
    if (!value) return std::nullopt;
    ida::Address target = static_cast<ida::Address>(*value);
    if (target == ida::BadAddress || target == 0) return std::nullopt;
    return target;
}

bool is_executable_address(ida::Address ea) {
    ida::Result<ida::segment::Segment> seg = ida::segment::at(ea);
    return seg && seg->permissions().execute;
}

// Portable ASCII case-insensitive compare (strcasecmp is POSIX-only; MSVC
// has _stricmp — avoid the platform split with a tiny inline helper).
inline bool ascii_ieq(const char *a, const char *b) {
    for (; *a && *b; ++a, ++b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = static_cast<char>(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = static_cast<char>(cb + 32);
        if (ca != cb) return false;
    }
    return *a == *b;
}

// Canonical mnemonic via table lookup — no string formatting, ~free.
const char *canon_mnemonic(const insn_t &insn) {
    const char *m = insn.get_canon_mnem(*get_ph());
    return m ? m : "";
}

bool mnemonic_is_any(const insn_t &insn,
                     std::initializer_list<const char *> names) {
    const char *mnemonic = canon_mnemonic(insn);
    for (const char *n : names)
        if (ascii_ieq(mnemonic, n)) return true;
    return false;
}

bool is_jump_opcode(const insn_t &insn) {
    return mnemonic_is_any(insn, {"jmp", "jmpni", "jmpfi"});
}

bool is_return_opcode(const insn_t &insn) {
    return mnemonic_is_any(insn, {"ret", "retn", "retf"});
}

bool is_operand_type(const op_t &operand, optype_t type) {
    return operand.type == type;
}

const op_t *operand_at(const insn_t &insn, std::size_t index) {
    if (index >= UA_MAXOP) return nullptr;
    const op_t &op = insn.ops[index];
    return op.type == o_void ? nullptr : &op;
}

// Decode an instruction; returns false on failure (mirrors idax semantics).
bool decode_raw(ida::Address ea, insn_t &out) {
    return decode_insn(&out, ea) > 0;
}

} // namespace

GraphBuilder::GraphBuilder(const DumpOptions &opts) : opts_(opts) {}

std::optional<ida::Address> GraphBuilder::func_start_cached(ida::Address ea) {
    auto it = func_start_cache_.find(ea);
    if (it != func_start_cache_.end()) return it->second;
    std::optional<ida::Address> start = function_start(ea);
    func_start_cache_.emplace(ea, start);
    return start;
}

bool GraphBuilder::is_64bit() {
    if (!is64_cache_) is64_cache_ = database_is_64bit();
    return *is64_cache_;
}

void GraphBuilder::add_start_function(ida::Address ea) {
    if (!should_keep_function(ea)) return;
    start_functions_.insert(ea);
    functions_.insert(ea);
}

bool GraphBuilder::should_follow(RefType type) const {
    switch (type) {
        case RefType::DirectCall:      return opts_.include_direct_calls;
        case RefType::IndirectCall:    return opts_.include_indirect_calls;
        case RefType::DataRef:         return opts_.include_data_refs;
        case RefType::ImmediateRef:    return opts_.include_immediate_refs;
        case RefType::TailCallPushRet: return opts_.include_tail_calls;
        case RefType::VirtualCall:     return opts_.include_virtual_calls;
        case RefType::JumpTable:       return opts_.include_jump_tables;
        default: return false;
    }
}

bool GraphBuilder::should_keep_function(ida::Address ea) {
    if (!opts_.tree_shake_stdlib_functions) return true;

    auto it = function_keep_cache_.find(ea);
    if (it != function_keep_cache_.end()) return it->second;

    bool keep = !is_system_function(ea);
    function_keep_cache_.emplace(ea, keep);
    return keep;
}

void GraphBuilder::add_edge(ida::Address from, ida::Address to, RefType type) {
    auto key = std::make_pair(from, to);
    auto it = edge_map_.find(key);
    if (it != edge_map_.end()) {
        edges_[it->second].types.insert(type);
    } else {
        edge_map_[key] = edges_.size();
        edges_.emplace_back(from, to, type);
    }
}

//--------------------------------------------------------------------------
// BFS over callers
//--------------------------------------------------------------------------

bool GraphBuilder::find_callers(int depth, const GraphProgressCb &cb) {
    std::set<ida::Address> visited;
    // Layer 0 = start functions. Each layer is the set of newly-discovered
    // callers from the previous layer.
    std::vector<ida::Address> layer(start_functions_.begin(), start_functions_.end());

    size_t processed_total = 0;

    for (int d = 0; d < depth && !layer.empty(); d++) {
        std::vector<ida::Address> next_layer;

        for (size_t li = 0; li < layer.size(); li++) {
            ida::Address ea = layer[li];
            if (!visited.insert(ea).second) continue;

            std::string fname = function_name_or_unknown(ea);

            GraphProgress p;
            p.phase = "callers";
            p.depth = d;
            p.max_depth = depth;
            p.layer_index = li;
            p.layer_total = layer.size();
            p.processed = processed_total;
            p.discovered = functions_.size();
            p.edges = edges_.size();
            p.current_ea = ea;
            p.current_name = fname.c_str();
            if (!tick(cb, p)) return false;

            std::vector<std::pair<ida::Address, RefType>> refs;
            collect_inbound_refs(ea, refs);

            for (const auto &[caller_ea, rt] : refs) {
                if (caller_ea == ida::BadAddress || caller_ea == ea) continue;
                if (!should_follow(rt)) continue;
                if (!should_keep_function(caller_ea)) continue;

                bool fresh_to_set = functions_.insert(caller_ea).second;
                add_edge(caller_ea, ea, rt);

                if (fresh_to_set && !visited.count(caller_ea))
                    next_layer.push_back(caller_ea);
            }

            ++processed_total;
        }

        layer = std::move(next_layer);
    }

    return true;
}

//--------------------------------------------------------------------------
// BFS over callees
//--------------------------------------------------------------------------

bool GraphBuilder::find_callees(int depth, const GraphProgressCb &cb) {
    // VTable scan is expensive — run it once up front (with its own
    // progress phase) but only when virtual calls are actually enabled.
    if (opts_.include_virtual_calls) {
        if (!scan_vtables(cb)) return false;
    }

    std::set<ida::Address> visited;
    // Layer 0 = everything we know so far (start funcs + callers).
    std::vector<ida::Address> layer(functions_.begin(), functions_.end());

    size_t processed_total = 0;

    for (int d = 0; d < depth && !layer.empty(); d++) {
        std::vector<ida::Address> next_layer;

        for (size_t li = 0; li < layer.size(); li++) {
            ida::Address ea = layer[li];
            if (!visited.insert(ea).second) continue;

            std::string fname = function_name_or_unknown(ea);

            GraphProgress p;
            p.phase = "callees";
            p.depth = d;
            p.max_depth = depth;
            p.layer_index = li;
            p.layer_total = layer.size();
            p.processed = processed_total;
            p.discovered = functions_.size();
            p.edges = edges_.size();
            p.current_ea = ea;
            p.current_name = fname.c_str();
            if (!tick(cb, p)) return false;

            std::vector<std::pair<ida::Address, RefType>> refs;
            collect_outbound_refs(ea, refs);

            for (const auto &[callee_ea, rt] : refs) {
                if (callee_ea == ida::BadAddress || callee_ea == ea) continue;
                if (!should_follow(rt)) continue;
                if (!should_keep_function(callee_ea)) continue;

                bool fresh_to_set = functions_.insert(callee_ea).second;
                add_edge(ea, callee_ea, rt);

                if (fresh_to_set && !visited.count(callee_ea))
                    next_layer.push_back(callee_ea);
            }

            ++processed_total;
        }

        layer = std::move(next_layer);
    }

    return true;
}

//--------------------------------------------------------------------------
// Inbound (caller-side) edges
//--------------------------------------------------------------------------

void GraphBuilder::collect_inbound_refs(
    ida::Address func_ea, std::vector<std::pair<ida::Address, RefType>> &refs
) {
    ida::Result<std::vector<ida::xref::Reference>> xrefs =
        ida::xref::code_refs_to(func_ea);
    if (!xrefs) return;

    for (const ida::xref::Reference &xref : *xrefs) {
        std::optional<ida::Address> caller = func_start_cached(static_cast<ida::Address>(xref.from));
        if (!caller || *caller == func_ea) continue;

        RefType rt = RefType::DirectCall;
        insn_t insn;
        if (decode_raw(static_cast<ida::Address>(xref.from), insn)
            && is_jump_opcode(insn)) {
            rt = RefType::TailCallPushRet;
        }
        refs.emplace_back(*caller, rt);
    }
}

//--------------------------------------------------------------------------
// Outbound (callee-side) edges — one walk over the function, dispatching
// to every enabled ref type from a single decode loop.
//--------------------------------------------------------------------------

void GraphBuilder::collect_outbound_refs(
    ida::Address func_ea, std::vector<std::pair<ida::Address, RefType>> &refs
) {
    ida::Result<ida::function::Function> function = ida::function::at(func_ea);
    if (!function) return;

    const ida::Address start = static_cast<ida::Address>(function->start());
    const ida::Address end = static_cast<ida::Address>(function->end());
    const bool is64 = is_64bit();
    const int ptr_size = is64 ? 8 : 4;

    const bool want_direct   = opts_.include_direct_calls;
    const bool want_data     = opts_.include_data_refs;
    const bool want_indirect = opts_.include_indirect_calls;
    const bool want_imm      = opts_.include_immediate_refs;
    const bool want_tail     = opts_.include_tail_calls;
    const bool want_virtual  = opts_.include_virtual_calls && !vtable_by_offset_.empty();
    const bool want_jmptab   = opts_.include_jump_tables;

    // Single instruction walk — uses IDA's cref/dref iterators for direct
    // calls and data refs (cheap, no decode needed) and idax instruction
    // decoding at most once per address for everything else.
    std::set<ida::Address> seen_direct, seen_data;
    // Virtual-call fan-out can repeat the same callee across many call sites
    // and offsets within one function; dedup emitted callees so we don't push
    // (and later re-insert/re-add_edge) the same func_ea->callee thousands of
    // times. The final graph is unchanged (add_edge dedups globally anyway).
    std::unordered_set<ida::Address> seen_virtual;

    bool need_decode = want_indirect || want_imm || want_tail ||
                       want_virtual || want_jmptab;

    for (ida::Address addr = start; addr < end && addr != ida::BadAddress; ) {
        // A single raw xrefblk pass covers both direct-call (code) and data
        // refs — splitting by xb.iscode exactly mirrors idax code_refs_from /
        // data_refs_from, but with zero per-instruction vector allocation
        // (the old idax calls allocated two vectors for every instruction).
        if (want_direct || want_data) {
            xrefblk_t xb;
            for (bool ok = xb.first_from(addr, XREF_ALL); ok; ok = xb.next_from()) {
                ida::Address target = static_cast<ida::Address>(xb.to);
                // Interior targets (strictly inside this function's body) can
                // never be a *separate* function start, so func_start would
                // always reject them — skip the lookup. This elides the
                // per-instruction fall-through/loop checks (the bulk of code
                // refs) while preserving boundary edges (target == start for
                // recursion, target >= end for fall-through into the next fn).
                if (target > start && target < end) continue;
                if (xb.iscode) {
                    if (!want_direct) continue;
                    std::optional<ida::Address> rf = func_start_cached(target);
                    if (rf && *rf == target && seen_direct.insert(target).second)
                        refs.emplace_back(target, RefType::DirectCall);
                } else {
                    if (!want_data) continue;
                    std::optional<ida::Address> rf = func_start_cached(target);
                    if (rf && *rf == target && seen_data.insert(target).second)
                        refs.emplace_back(target, RefType::DataRef);
                }
            }
        }

        if (!need_decode) {
            std::optional<ida::Address> next = next_idax_item(addr, end);
            if (!next) break;
            addr = *next;
            continue;
        }

        insn_t insn;
        if (!decode_raw(addr, insn)) {
            std::optional<ida::Address> next = next_idax_item(addr, end);
            if (!next) break;
            addr = *next;
            continue;
        }
        const op_t *op1 = operand_at(insn, 0);

        // Classify the opcode once. canon_mnemonic is cheap but not free, and
        // the per-feature blocks previously re-derived call/jump up to 5x per
        // instruction — fetch the mnemonic once and reuse the booleans.
        const bool need_call = want_indirect || want_virtual;
        const bool need_jmp  = want_tail || want_jmptab;
        const char *mnem = (need_call || need_jmp) ? canon_mnemonic(insn) : "";
        auto mnem_eq = [&](const char *n) { return ascii_ieq(mnem, n); };
        const bool is_call = need_call &&
            (mnem_eq("call") || mnem_eq("callni"));
        const bool is_jmp = need_jmp &&
            (mnem_eq("jmp") || mnem_eq("jmpni") || mnem_eq("jmpfi"));

        // Indirect call (call reg / call [mem] / call [reg+disp])
        if (want_indirect && op1 && is_call &&
            (is_operand_type(*op1, o_reg) ||
             is_operand_type(*op1, o_phrase) ||
             is_operand_type(*op1, o_displ) ||
             is_operand_type(*op1, o_mem)))
        {
            if (auto t = detect_indirect_target(addr, start))
                refs.emplace_back(*t, RefType::IndirectCall);
        }

        // Virtual call (call [reg+offset]) — dispatch via vtable index
        if (want_virtual && op1 && is_call &&
            is_operand_type(*op1, o_displ))
        {
            int vt_off = static_cast<int>(op1->addr);
            auto range = vtable_by_offset_.equal_range(vt_off);
            for (auto it = range.first; it != range.second; ++it)
                if (seen_virtual.insert(it->second).second)
                    refs.emplace_back(it->second, RefType::VirtualCall);
        }

        // Immediate operands that happen to be function starts
        if (want_imm) {
            for (int oi = 0; oi < UA_MAXOP; oi++) {
                const op_t &op = insn.ops[oi];
                if (op.type == o_void) break;
                if (op.type != o_imm) continue;
                ida::Address v = static_cast<ida::Address>(op.value);
                std::optional<ida::Address> tf = func_start_cached(v);
                if (tf && *tf == v)
                    refs.emplace_back(v, RefType::ImmediateRef);
            }
        }

        // Tail call: jmp <addr> or push <addr>; ret
        if (want_tail) {
            if (op1 && is_jmp) {
                if (is_operand_type(*op1, o_near)
                    || is_operand_type(*op1, o_far)) {
                    ida::Address t = static_cast<ida::Address>(op1->addr);
                    std::optional<ida::Address> tf = func_start_cached(t);
                    if (tf && *tf == t && t != func_ea)
                        refs.emplace_back(t, RefType::TailCallPushRet);
                }
            }
            if (op1 && is_operand_type(*op1, o_imm) && mnem_eq("push")) {
                insn_t nxt;
                if (decode_raw(addr + static_cast<ida::Address>(insn.size), nxt)
                    && is_return_opcode(nxt))
                {
                    ida::Address v = static_cast<ida::Address>(op1->value);
                    std::optional<ida::Address> tf = func_start_cached(v);
                    if (tf && *tf == v)
                        refs.emplace_back(v, RefType::TailCallPushRet);
                }
            }
        }

        // Jump table (switch lowered as indirect jmp via table)
        if (want_jmptab && op1 && is_jmp &&
            (is_operand_type(*op1, o_displ)
             || is_operand_type(*op1, o_phrase)))
        {
            ida::Result<ida::graph::SwitchTable> table =
                ida::graph::switch_table(addr);
            if (table) {
                std::size_t entry_size = table->entry_size != 0
                    ? table->entry_size
                    : static_cast<std::size_t>(ptr_size);
                for (std::size_t i = 0; i < table->entry_count; i++) {
                    ida::Address entry = static_cast<ida::Address>(table->table_address + (i * entry_size));
                    std::optional<ida::Address> t = read_pointer(entry, is64);
                    if (t) {
                        if (std::optional<ida::Address> tf = func_start_cached(*t))
                            refs.emplace_back(*tf, RefType::JumpTable);
                    }
                }
            } else {
                auto targets = detect_jump_table(addr);
                for (ida::Address t : targets) {
                    if (std::optional<ida::Address> tf = func_start_cached(t))
                        refs.emplace_back(*tf, RefType::JumpTable);
                }
            }
        }

        addr += static_cast<ida::Address>(insn.size);
    }
}

//--------------------------------------------------------------------------
// Indirect call register-tracer (unchanged behavior, kept compact)
//--------------------------------------------------------------------------

std::optional<ida::Address> GraphBuilder::detect_indirect_target(ida::Address call_ea, ida::Address func_start) {
    insn_t call_insn;
    if (!decode_raw(call_ea, call_insn)) return std::nullopt;
    const op_t *call_op = operand_at(call_insn, 0);
    if (!call_op) return std::nullopt;

    std::uint16_t target_reg = 0;
    std::int64_t mem_offset = 0;

    if (is_operand_type(*call_op, o_reg)) {
        target_reg = call_op->reg;
    } else if (is_operand_type(*call_op, o_phrase)
               || is_operand_type(*call_op, o_displ)) {
        target_reg = call_op->reg;
        mem_offset = static_cast<std::int64_t>(call_op->addr);
    } else if (is_operand_type(*call_op, o_mem)) {
        ida::Address mem_ea = static_cast<ida::Address>(call_op->addr);
        std::optional<ida::Address> target = read_pointer(mem_ea, is_64bit());
        if (target) {
            if (std::optional<ida::Address> f = func_start_cached(*target)) return *f;
        }
        return std::nullopt;
    } else {
        return std::nullopt;
    }

    ida::Address scan_ea = call_ea;
    for (int i = 0; i < 20 && scan_ea > func_start; i++) {
        std::optional<ida::Address> prev = prev_idax_item(scan_ea, func_start);
        if (!prev) break;
        scan_ea = *prev;

        insn_t insn;
        if (!decode_raw(scan_ea, insn)) continue;
        if (!mnemonic_is_any(insn, {"mov", "lea"})) continue;
        const op_t *dst = operand_at(insn, 0);
        const op_t *src = operand_at(insn, 1);
        if (!dst || !src) continue;
        if (!is_operand_type(*dst, o_reg)
            || dst->reg != target_reg) continue;

        if (is_operand_type(*src, o_imm)) {
            if (std::optional<ida::Address> f = func_start_cached(static_cast<ida::Address>(src->value)))
                return *f;
        } else if (is_operand_type(*src, o_mem)) {
            ida::Address mem_ea = static_cast<ida::Address>(src->addr) + mem_offset;
            std::optional<ida::Address> target = read_pointer(mem_ea, is_64bit());
            if (target)
                if (std::optional<ida::Address> f = func_start_cached(*target)) return *f;
        }
        break;
    }
    return std::nullopt;
}

//--------------------------------------------------------------------------
// VTable scan — single pass with per-segment progress + cancellation
//--------------------------------------------------------------------------

bool GraphBuilder::scan_vtables(const GraphProgressCb &cb) {
    if (vtables_scanned_) return true;
    vtables_scanned_ = true;

    const bool is64 = is_64bit();
    const int ptr_size = is64 ? 8 : 4;

    // A slot only counts as a vtable entry if it lives in non-executable
    // memory. Capture the data-segment ranges once for fast membership.
    std::vector<std::pair<ida::Address, ida::Address>> data_ranges;
    for (const ida::segment::Segment &seg : ida::segment::all())
        if (!seg.permissions().execute)
            data_ranges.emplace_back(static_cast<ida::Address>(seg.start()),
                                     static_cast<ida::Address>(seg.end()));
    auto in_data = [&](ida::Address ea) {
        for (const auto &r : data_ranges)
            if (ea >= r.first && ea < r.second) return true;
        return false;
    };

    // Rather than brute-forcing a pointer read over every slot of every data
    // segment — O(total data bytes), the old bottleneck — reuse the data->code
    // references IDA already computed during analysis. Every vtable slot that
    // holds a function pointer has a data xref to that function's start, so we
    // gather (slot, func) for all such references (O(#code pointers in data))
    // and cluster the runs. The harness measured this ~67x faster with
    // effectively identical results.
    std::vector<std::pair<ida::Address, ida::Address>> slot_func;  // (slot, func)

    size_t func_total = 0;
    if (ida::Result<std::size_t> c = ida::function::count()) func_total = *c;

    size_t fi = 0;
    for (const ida::function::Function &fn : ida::function::all()) {
        // Periodic tick so the GUI shows life and stays cancellable.
        if ((fi & 0x3FF) == 0) {
            GraphProgress p;
            p.phase = "vtables";
            p.segment_index = fi;
            p.segment_total = func_total;
            p.current_name = "(scanning xrefs)";
            p.vtables_found = slot_func.size();
            if (!tick(cb, p)) return false;
        }
        ++fi;

        ida::Address fea = static_cast<ida::Address>(fn.start());
        if (!should_keep_function(fea)) continue;
        ida::Result<std::vector<ida::xref::Reference>> refs =
            ida::xref::data_refs_to(fea);
        if (!refs) continue;
        for (const ida::xref::Reference &r : *refs) {
            ida::Address slot = static_cast<ida::Address>(r.from);
            if ((slot % ptr_size) == 0 && in_data(slot))
                slot_func.emplace_back(slot, fea);
        }
    }

    // Sort by slot and dedup — a slot references exactly one target.
    std::sort(slot_func.begin(), slot_func.end());
    slot_func.erase(
        std::unique(slot_func.begin(), slot_func.end(),
                    [](const auto &a, const auto &b) { return a.first == b.first; }),
        slot_func.end());

    // Cluster runs of >=3 consecutive pointer-aligned slots into vtables.
    size_t i = 0;
    while (i < slot_func.size()) {
        size_t j = i + 1;
        while (j < slot_func.size() &&
               slot_func[j].first ==
                   slot_func[j - 1].first + static_cast<ida::Address>(ptr_size))
            ++j;
        if (j - i >= 3) {
            ida::Address vt_ea = slot_func[i].first;
            int off = 0;
            for (size_t k = i; k < j; k++) {
                VTableEntry entry;
                entry.vtable_ea = vt_ea;
                entry.offset = off;
                entry.func_ea = slot_func[k].second;
                vtables_.push_back(entry);
                vtable_by_offset_.emplace(off, slot_func[k].second);
                off += ptr_size;
            }
        }
        i = j;
    }

    // Final tick so the caller sees the completed count.
    GraphProgress p;
    p.phase = "vtables";
    p.segment_index = func_total;
    p.segment_total = func_total;
    p.current_name = "(done)";
    p.vtables_found = 0;
    for (const auto &v : vtables_)
        if (v.offset == 0) ++p.vtables_found;
    if (!tick(cb, p)) return false;

    return true;
}

//--------------------------------------------------------------------------
// Jump-table fallback (manual)
//--------------------------------------------------------------------------

std::vector<ida::Address> GraphBuilder::detect_jump_table(ida::Address jmp_ea) {
    std::vector<ida::Address> results;

    insn_t insn;
    if (!decode_raw(jmp_ea, insn)) return results;

    ida::Address table_ea = ida::BadAddress;
    const op_t *op1 = operand_at(insn, 0);
    if (op1 && is_operand_type(*op1, o_displ))
        table_ea = static_cast<ida::Address>(op1->addr);
    if (table_ea == ida::BadAddress) return results;

    bool is64 = is_64bit();
    int ptr_size = is64 ? 8 : 4;
    for (int i = 0; i < 20; i++) {
        ida::Address entry_ea = table_ea + (i * ptr_size);
        std::optional<ida::Address> target = read_pointer(entry_ea, is64);
        if (!target || !is_executable_address(*target)) break;
        results.push_back(*target);
    }
    return results;
}

} // namespace codedump
