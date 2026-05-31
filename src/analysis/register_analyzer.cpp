#include "register_analyzer.h"

#include <ida/graph.hpp>
#include <ida/instruction.hpp>

#include <algorithm>
#include <map>
#include <regex>
#include <vector>

namespace codedump {

namespace {

// Map an x86 sub-register name to its 64-bit parent. Returns the input
// unchanged for non-x86 names so the analyzer is still usable elsewhere.
std::string normalize_x86(const std::string &raw) {
    static const std::map<std::string, std::string> aliases = {
        {"al", "rax"}, {"ah", "rax"}, {"ax", "rax"}, {"eax", "rax"},
        {"cl", "rcx"}, {"ch", "rcx"}, {"cx", "rcx"}, {"ecx", "rcx"},
        {"dl", "rdx"}, {"dh", "rdx"}, {"dx", "rdx"}, {"edx", "rdx"},
        {"bl", "rbx"}, {"bh", "rbx"}, {"bx", "rbx"}, {"ebx", "rbx"},
        {"spl", "rsp"}, {"sp", "rsp"}, {"esp", "rsp"},
        {"bpl", "rbp"}, {"bp", "rbp"}, {"ebp", "rbp"},
        {"sil", "rsi"}, {"si", "rsi"}, {"esi", "rsi"},
        {"dil", "rdi"}, {"di", "rdi"}, {"edi", "rdi"},
    };
    auto it = aliases.find(raw);
    if (it != aliases.end()) return it->second;

    // r8..r15 with b/w/d size suffix.
    static const std::regex r8_re("^r([0-9]+)[bwd]$");
    std::smatch m;
    if (std::regex_match(raw, m, r8_re)) return "r" + m[1].str();

    // SIMD wide forms — normalize down to xmmN since most ABIs talk in xmm.
    static const std::regex simd_re("^([xyz])mm([0-9]+)$");
    if (std::regex_match(raw, m, simd_re)) return "xmm" + m[2].str();

    return raw;
}

bool is_boring(const std::string &reg) {
    // Always live / always written — uninformative for the caller.
    return reg == "rsp" || reg == "rip" || reg == "eflags" || reg == "flags";
}

void collect_op_regs(const ida::instruction::Operand &op,
                     std::set<std::string> &reads,
                     std::set<std::string> &writes) {
    if (op.type() == ida::instruction::OperandType::None) return;

    if (op.is_register()) {
        std::string name = normalize_x86(op.register_name());
        if (name.empty() || is_boring(name)) return;
        if (op.is_read()) reads.insert(name);
        if (op.is_written()) writes.insert(name);
    } else if (op.type() == ida::instruction::OperandType::MemoryPhrase
               || op.type() == ida::instruction::OperandType::MemoryDisplacement) {
        // Address computation always reads the base register, regardless of
        // whether the memory itself is being read or written.
        std::string name = normalize_x86(op.register_name());
        if (!name.empty() && !is_boring(name))
            reads.insert(name);
    }
}

} // namespace

RegisterSummary analyze_function_registers(ida::Address function_ea) {
    RegisterSummary summary;

    ida::Result<std::vector<ida::graph::BasicBlock>> flow =
        ida::graph::flowchart(function_ea);
    if (!flow) return summary;

    int n = static_cast<int>(flow->size());
    if (n == 0) return summary;

    // Per-BB use/def sets.
    std::vector<std::set<std::string>> use(n), def(n);
    for (int i = 0; i < n; i++) {
        const ida::graph::BasicBlock &bb = (*flow)[i];
        std::set<std::string> bb_use, bb_def;

        for (ida::Address ea = static_cast<ida::Address>(bb.start);
             ea < static_cast<ida::Address>(bb.end); ) {
            auto insn = ida::instruction::decode(static_cast<ida::Address>(ea));
            if (!insn || insn->size() == 0) { ea++; continue; }

            std::set<std::string> reads, writes;
            for (const auto &op : insn->operands())
                collect_op_regs(op, reads, writes);

            // Add reads that haven't been written yet in this BB.
            for (const auto &r : reads)
                if (!bb_def.count(r))
                    bb_use.insert(r);
            for (const auto &r : writes)
                bb_def.insert(r);

            ea += static_cast<ida::Address>(insn->size());
        }

        use[i] = std::move(bb_use);
        def[i] = std::move(bb_def);
    }

    // Iterative liveness: live_in[B] = use[B] ∪ (live_out[B] − def[B]),
    // live_out[B] = ∪ live_in[succ]. Fixed point.
    std::vector<std::set<std::string>> live_in(n), live_out(n);

    bool changed = true;
    int iterations = 0;
    while (changed && iterations < 256) {
        changed = false;
        ++iterations;
        for (int i = n - 1; i >= 0; --i) {
            const ida::graph::BasicBlock &bb = (*flow)[i];

            std::set<std::string> new_out;
            for (size_t s = 0; s < bb.successors.size(); s++) {
                int sn = bb.successors[s];
                if (sn >= 0 && sn < n)
                    new_out.insert(live_in[sn].begin(), live_in[sn].end());
            }

            std::set<std::string> new_in = use[i];
            for (const auto &r : new_out)
                if (!def[i].count(r))
                    new_in.insert(r);

            if (new_in != live_in[i] || new_out != live_out[i]) {
                live_in[i] = std::move(new_in);
                live_out[i] = std::move(new_out);
                changed = true;
            }
        }
    }

    summary.incoming = std::move(live_in[0]);
    for (int i = 0; i < n; i++)
        summary.outgoing.insert(def[i].begin(), def[i].end());

    return summary;
}

} // namespace codedump
