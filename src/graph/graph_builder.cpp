#include "graph_builder.h"

#include <ida/address.hpp>
#include <ida/data.hpp>
#include <ida/database.hpp>
#include <ida/function.hpp>
#include <ida/graph.hpp>
#include <ida/instruction.hpp>
#include <ida/segment.hpp>
#include <ida/xref.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <initializer_list>
#include <string_view>

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
    ida::Result<ida::function::Function> function = ida::function::at(ea);
    if (!function) return std::nullopt;
    return static_cast<ida::Address>(function->start());
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

std::string lower_mnemonic(const ida::instruction::Instruction &insn) {
    std::string mnemonic = insn.mnemonic();
    std::transform(mnemonic.begin(), mnemonic.end(), mnemonic.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return mnemonic;
}

bool mnemonic_is_any(const ida::instruction::Instruction &insn,
                     std::initializer_list<std::string_view> names) {
    std::string mnemonic = lower_mnemonic(insn);
    return std::find(names.begin(), names.end(), mnemonic) != names.end();
}

bool is_call_opcode(const ida::instruction::Instruction &insn) {
    return mnemonic_is_any(insn, {"call", "callni"});
}

bool is_jump_opcode(const ida::instruction::Instruction &insn) {
    return mnemonic_is_any(insn, {"jmp", "jmpni", "jmpfi"});
}

bool is_return_opcode(const ida::instruction::Instruction &insn) {
    return mnemonic_is_any(insn, {"ret", "retn", "retf"});
}

bool is_operand_type(const ida::instruction::Operand &operand,
                     ida::instruction::OperandType type) {
    return operand.type() == type;
}

const ida::instruction::Operand *operand_at(
        const ida::instruction::Instruction &insn, std::size_t index) {
    const auto &operands = insn.operands();
    return index < operands.size() ? &operands[index] : nullptr;
}

} // namespace

GraphBuilder::GraphBuilder(const DumpOptions &opts) : opts_(opts) {}

void GraphBuilder::add_start_function(ida::Address ea) {
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
        std::optional<ida::Address> caller = function_start(static_cast<ida::Address>(xref.from));
        if (!caller || *caller == func_ea) continue;

        RefType rt = RefType::DirectCall;
        ida::Result<ida::instruction::Instruction> insn =
            ida::instruction::decode(xref.from);
        if (insn) {
            if (is_jump_opcode(*insn)) {
                rt = RefType::TailCallPushRet;
            }
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
    const bool is64 = database_is_64bit();
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

    bool need_decode = want_indirect || want_imm || want_tail ||
                       want_virtual || want_jmptab;

    for (ida::Address addr = start; addr < end && addr != ida::BadAddress; ) {
        // crefs (direct calls) — function-start filtered
        if (want_direct) {
            ida::Result<std::vector<ida::xref::Reference>> crefs =
                ida::xref::code_refs_from(addr);
            if (crefs) {
                for (const ida::xref::Reference &cref : *crefs) {
                    ida::Address target = static_cast<ida::Address>(cref.to);
                    std::optional<ida::Address> rf = function_start(target);
                    if (rf && *rf == target && seen_direct.insert(target).second)
                        refs.emplace_back(target, RefType::DirectCall);
                }
            }
        }
        // drefs (data references that resolve to function starts)
        if (want_data) {
            ida::Result<std::vector<ida::xref::Reference>> drefs =
                ida::xref::data_refs_from(addr);
            if (drefs) {
                for (const ida::xref::Reference &dref : *drefs) {
                    ida::Address target = static_cast<ida::Address>(dref.to);
                    std::optional<ida::Address> rf = function_start(target);
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

        ida::Result<ida::instruction::Instruction> decoded =
            ida::instruction::decode(addr);
        if (!decoded) {
            std::optional<ida::Address> next = next_idax_item(addr, end);
            if (!next) break;
            addr = *next;
            continue;
        }
        const ida::instruction::Instruction &insn = *decoded;
        const ida::instruction::Operand *op1 = operand_at(insn, 0);

        // Indirect call (call reg / call [mem] / call [reg+disp])
        if (want_indirect && op1 && is_call_opcode(insn) &&
            (is_operand_type(*op1, ida::instruction::OperandType::Register) ||
             is_operand_type(*op1, ida::instruction::OperandType::MemoryPhrase) ||
             is_operand_type(*op1, ida::instruction::OperandType::MemoryDisplacement) ||
             is_operand_type(*op1, ida::instruction::OperandType::MemoryDirect)))
        {
            if (auto t = detect_indirect_target(addr, start))
                refs.emplace_back(*t, RefType::IndirectCall);
        }

        // Virtual call (call [reg+offset]) — dispatch via vtable index
        if (want_virtual && op1 && is_call_opcode(insn) &&
            is_operand_type(*op1, ida::instruction::OperandType::MemoryDisplacement))
        {
            int vt_off = static_cast<int>(op1->target_address());
            auto range = vtable_by_offset_.equal_range(vt_off);
            for (auto it = range.first; it != range.second; ++it)
                refs.emplace_back(it->second, RefType::VirtualCall);
        }

        // Immediate operands that happen to be function starts
        if (want_imm) {
            for (const ida::instruction::Operand &op : insn.operands()) {
                if (!is_operand_type(op, ida::instruction::OperandType::Immediate))
                    continue;
                ida::Address v = static_cast<ida::Address>(op.value());
                std::optional<ida::Address> tf = function_start(v);
                if (tf && *tf == v)
                    refs.emplace_back(v, RefType::ImmediateRef);
            }
        }

        // Tail call: jmp <addr> or push <addr>; ret
        if (want_tail) {
            if (op1 && is_jump_opcode(insn)) {
                if (is_operand_type(*op1, ida::instruction::OperandType::NearAddress)
                    || is_operand_type(*op1, ida::instruction::OperandType::FarAddress)) {
                    ida::Address t = static_cast<ida::Address>(op1->target_address());
                    std::optional<ida::Address> tf = function_start(t);
                    if (tf && *tf == t && t != func_ea)
                        refs.emplace_back(t, RefType::TailCallPushRet);
                }
            }
            if (op1 && mnemonic_is_any(insn, {"push"})
                && is_operand_type(*op1, ida::instruction::OperandType::Immediate)) {
                ida::Result<ida::instruction::Instruction> nxt =
                    ida::instruction::decode(addr + static_cast<ida::Address>(insn.size()));
                if (nxt && is_return_opcode(*nxt))
                {
                    ida::Address v = static_cast<ida::Address>(op1->value());
                    std::optional<ida::Address> tf = function_start(v);
                    if (tf && *tf == v)
                        refs.emplace_back(v, RefType::TailCallPushRet);
                }
            }
        }

        // Jump table (switch lowered as indirect jmp via table)
        if (want_jmptab && op1 && is_jump_opcode(insn) &&
            (is_operand_type(*op1, ida::instruction::OperandType::MemoryDisplacement)
             || is_operand_type(*op1, ida::instruction::OperandType::MemoryPhrase)))
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
                        if (std::optional<ida::Address> tf = function_start(*t))
                            refs.emplace_back(*tf, RefType::JumpTable);
                    }
                }
            } else {
                auto targets = detect_jump_table(addr);
                for (ida::Address t : targets) {
                    if (std::optional<ida::Address> tf = function_start(t))
                        refs.emplace_back(*tf, RefType::JumpTable);
                }
            }
        }

        addr += static_cast<ida::Address>(insn.size());
    }
}

//--------------------------------------------------------------------------
// Indirect call register-tracer (unchanged behavior, kept compact)
//--------------------------------------------------------------------------

std::optional<ida::Address> GraphBuilder::detect_indirect_target(ida::Address call_ea, ida::Address func_start) {
    ida::Result<ida::instruction::Instruction> call_insn =
        ida::instruction::decode(call_ea);
    if (!call_insn) return std::nullopt;
    const ida::instruction::Operand *call_op = operand_at(*call_insn, 0);
    if (!call_op) return std::nullopt;

    std::uint16_t target_reg = 0;
    std::int64_t mem_offset = 0;

    if (is_operand_type(*call_op, ida::instruction::OperandType::Register)) {
        target_reg = call_op->register_id();
    } else if (is_operand_type(*call_op, ida::instruction::OperandType::MemoryPhrase)
               || is_operand_type(*call_op, ida::instruction::OperandType::MemoryDisplacement)) {
        target_reg = call_op->register_id();
        mem_offset = static_cast<std::int64_t>(call_op->target_address());
    } else if (is_operand_type(*call_op, ida::instruction::OperandType::MemoryDirect)) {
        ida::Address mem_ea = static_cast<ida::Address>(call_op->target_address());
        std::optional<ida::Address> target = read_pointer(mem_ea, database_is_64bit());
        if (target) {
            if (std::optional<ida::Address> f = function_start(*target)) return *f;
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

        ida::Result<ida::instruction::Instruction> insn =
            ida::instruction::decode(scan_ea);
        if (!insn) continue;
        if (!mnemonic_is_any(*insn, {"mov", "lea"})) continue;
        const ida::instruction::Operand *dst = operand_at(*insn, 0);
        const ida::instruction::Operand *src = operand_at(*insn, 1);
        if (!dst || !src) continue;
        if (!is_operand_type(*dst, ida::instruction::OperandType::Register)
            || dst->register_id() != target_reg) continue;

        if (is_operand_type(*src, ida::instruction::OperandType::Immediate)) {
            if (std::optional<ida::Address> f = function_start(static_cast<ida::Address>(src->value())))
                return *f;
        } else if (is_operand_type(*src, ida::instruction::OperandType::MemoryDirect)) {
            ida::Address mem_ea = static_cast<ida::Address>(src->target_address()) + mem_offset;
            std::optional<ida::Address> target = read_pointer(mem_ea, database_is_64bit());
            if (target)
                if (std::optional<ida::Address> f = function_start(*target)) return *f;
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

    const bool is64 = database_is_64bit();
    const int ptr_size = is64 ? 8 : 4;

    // First, count data segments so the callback can render "k/N".
    size_t data_seg_total = 0;
    for (const ida::segment::Segment &seg : ida::segment::all()) {
        if (!seg.permissions().execute) ++data_seg_total;
    }

    size_t seg_idx = 0;
    for (const ida::segment::Segment &seg : ida::segment::all()) {
        if (seg.permissions().execute) continue;
        std::string sname = seg.name();

        // Emit a phase tick on every segment boundary so the user sees life.
        GraphProgress p;
        p.phase = "vtables";
        p.segment_index = seg_idx;
        p.segment_total = data_seg_total;
        p.current_name = sname.empty() ? "?" : sname.c_str();
        p.vtables_found = 0;
        for (const auto &v : vtables_)
            if (v.offset == 0) ++p.vtables_found;
        if (!tick(cb, p)) return false;

        ida::Address addr = static_cast<ida::Address>(seg.start());
        size_t scanned = 0;
        while (addr < seg.end()) {
            // Periodic in-segment tick so very large segments still feel alive.
            if ((scanned & 0xFFFF) == 0) {
                p.layer_index = scanned;
                p.layer_total = seg.end() - seg.start();
                p.vtables_found = 0;
                for (const auto &v : vtables_)
                    if (v.offset == 0) ++p.vtables_found;
                if (!tick(cb, p)) return false;
            }
            ++scanned;

            if (addr % ptr_size != 0) { addr++; continue; }

            // Try to find 3+ consecutive function pointers.
            std::vector<ida::Address> potential;
            ida::Address scan = addr;
            while (scan < seg.end()) {
                std::optional<ida::Address> ptr = read_pointer(scan, is64);
                if (!ptr) break;
                std::optional<ida::Address> fp = function_start(*ptr);
                if (!fp || *fp != *ptr) break;
                potential.push_back(*ptr);
                scan += ptr_size;
            }

            if (potential.size() >= 3) {
                int off = 0;
                for (ida::Address fptr : potential) {
                    VTableEntry entry;
                    entry.vtable_ea = addr;
                    entry.offset = off;
                    entry.func_ea = fptr;
                    vtables_.push_back(entry);
                    vtable_by_offset_.emplace(off, fptr);
                    off += ptr_size;
                }
                addr = scan;
            } else {
                addr += ptr_size;
            }
        }

        ++seg_idx;
    }

    // Final tick so the caller sees the completed count.
    GraphProgress p;
    p.phase = "vtables";
    p.segment_index = seg_idx;
    p.segment_total = data_seg_total;
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

    ida::Result<ida::instruction::Instruction> insn =
        ida::instruction::decode(jmp_ea);
    if (!insn) return results;

    ida::Address table_ea = ida::BadAddress;
    const ida::instruction::Operand *op1 = operand_at(*insn, 0);
    if (op1 && is_operand_type(*op1, ida::instruction::OperandType::MemoryDisplacement))
        table_ea = static_cast<ida::Address>(op1->target_address());
    if (table_ea == ida::BadAddress) return results;

    bool is64 = database_is_64bit();
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
