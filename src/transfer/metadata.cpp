#include "metadata.h"

#include <ida/function.hpp>
#include <ida/graph.hpp>
#include <ida/instruction.hpp>

#include <cstring>
#include <format>
#include <sstream>

namespace codedump {

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

namespace {

constexpr uint64_t FNV_OFFSET = 1469598103934665603ULL;
constexpr uint64_t FNV_PRIME  = 1099511628211ULL;

inline void fnv_step(uint64_t &h, uint64_t v) {
    for (int i = 0; i < 8; i++) {
        h ^= (v & 0xFF);
        h *= FNV_PRIME;
        v >>= 8;
    }
}

} // namespace

FunctionFingerprint compute_fingerprint(ida::Address function_ea) {
    FunctionFingerprint fp;
    ida::Result<ida::function::Function> function =
        ida::function::at(function_ea);
    if (!function) return fp;

    ida::Address start = static_cast<ida::Address>(function->start());
    ida::Address end = static_cast<ida::Address>(function->end());
    fp.size_bytes = end - start;

    // Walk instructions linearly. We fold in the itype and operand-type
    // tuple for each instruction; operand values that are addresses are
    // intentionally omitted so an address shift between binaries doesn't
    // perturb the hash.
    uint64_t h = FNV_OFFSET;
    uint32_t insns = 0;

    ida::Result<std::vector<ida::Address>> addresses =
        ida::function::code_addresses(start);
    if (addresses) {
        for (ida::Address address : *addresses) {
            ida::Result<ida::instruction::Instruction> instruction =
                ida::instruction::decode(address);
            if (!instruction) continue;

            ++insns;

            fnv_step(h, instruction->opcode());
            constexpr std::size_t kMaxOperands = 8;
            for (std::size_t i = 0; i < kMaxOperands; i++) {
                uint64_t tag = 0;
                if (i < instruction->operands().size()) {
                    const ida::instruction::Operand &op = instruction->operands()[i];
                    tag = static_cast<uint64_t>(op.type());
                    if (op.type() == ida::instruction::OperandType::Register)
                        tag |= (uint64_t(op.register_id()) << 16);
                    // For relative jumps/calls we fold the in-function-or-not bit
                    // so a long-call vs. short-call distinction is captured but
                    // the absolute target isn't.
                    if (op.type() == ida::instruction::OperandType::NearAddress
                        || op.type() == ida::instruction::OperandType::FarAddress) {
                        ida::Address target = static_cast<ida::Address>(op.target_address());
                        bool in_func = (target >= start && target < end);
                        tag |= (uint64_t(in_func ? 1 : 0) << 32);
                        if (in_func) {
                            // Encode the relative offset of the target within the
                            // function so internal control flow shape is captured.
                            uint64_t rel = target - start;
                            tag |= (rel & 0xFFFFFFFFULL) << 40;
                        }
                    }
                }
                fnv_step(h, tag);
            }
        }
    }

    fp.insn_count = insns;
    fp.shape_hash = h;

    ida::Result<std::vector<ida::graph::BasicBlock>> blocks =
        ida::graph::flowchart(start);
    if (blocks)
        fp.bb_count = static_cast<uint32_t>(blocks->size());
    return fp;
}

std::string fingerprint_mismatch_reason(
    const FunctionFingerprint &e, const FunctionFingerprint &a
) {
    std::ostringstream ss;
    auto cmp = [&](const char *what, uint64_t exp, uint64_t got) {
        if (exp != got) {
            ss << "  " << what << ": expected " << exp << ", got " << got << "\n";
        }
    };
    cmp("size_bytes", e.size_bytes, a.size_bytes);
    cmp("insn_count", e.insn_count, a.insn_count);
    cmp("bb_count", e.bb_count, a.bb_count);
    if (e.shape_hash != a.shape_hash) {
        ss << std::format("  shape_hash: expected 0x{:016X}, got 0x{:016X}\n",
                          e.shape_hash,
                          a.shape_hash);
    }
    return ss.str();
}

// ---------------------------------------------------------------------------
// Serializer + parser
//
// Format: one directive per line. Top-level keys are followed by their
// values on the same line. Strings are double-quoted with C escapes
// (\n, \t, \\, \", \xHH). Functions are introduced by `func <id>` and
// terminated by `end_func`. Types are `type <id> "name" "decl"` on one
// line.
//
// Example:
//   #cdump-meta v1
//   image_base 0x140000000
//   root_ea 0x140012340
//   arch x86_64
//   type 1 "MyStruct" "struct MyStruct {\n  int x;\n};"
//   func 1
//     name "handle_req"
//     ea 0x140012340
//     rva 0x12340
//     fp_size 234
//     fp_insns 47
//     fp_bbs 5
//     fp_hash 0xABCDEF
//     proto "__int64 __fastcall handle_req(int)"
//     func_cmt "..."
//     func_cmt_rpt "..."
//     cmt 0x12 0 "..."
//     lvar reg 12 0x14 "argp" "char *"
//     lvar stk 16 0x20 "n" "int"
//     callee 0x18 2
//   end_func
// ---------------------------------------------------------------------------

namespace {

void emit_quoted(std::ostream &out, const std::string &s) {
    out << '"';
    for (char c : s) {
        switch (c) {
            case '"':  out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\n': out << "\\n";  break;
            case '\r': out << "\\r";  break;
            case '\t': out << "\\t";  break;
            default:
                if ((unsigned char)c < 0x20) {
                    out << std::format("\\x{:02X}",
                                       static_cast<unsigned char>(c));
                } else {
                    out << c;
                }
        }
    }
    out << '"';
}

void emit_hex(std::ostream &out, uint64_t v) {
    out << std::format("0x{:X}", v);
}

} // namespace

std::string serialize_metadata(const MetadataDocument &doc) {
    std::ostringstream ss;

    ss << "#cdump-meta v" << doc.schema_version << "\n";
    ss << "image_base ";   emit_hex(ss, doc.source_image_base); ss << "\n";
    ss << "root_ea ";      emit_hex(ss, doc.source_root_ea);    ss << "\n";
    ss << "arch ";         emit_quoted(ss, doc.source_arch);    ss << "\n";
    ss << "created ";      emit_quoted(ss, doc.created_at);     ss << "\n";

    for (const auto &t : doc.types) {
        ss << "type " << t.id << " ";
        emit_quoted(ss, t.name);
        ss << " ";
        emit_quoted(ss, t.decl);
        ss << "\n";
    }

    for (const auto &f : doc.functions) {
        ss << "func " << f.id << "\n";
        ss << "  name ";      emit_quoted(ss, f.name);      ss << "\n";
        ss << "  ea ";        emit_hex(ss, f.ea);           ss << "\n";
        ss << "  rva ";       emit_hex(ss, f.rva);          ss << "\n";
        ss << "  fp_size "  << f.fingerprint.size_bytes  << "\n";
        ss << "  fp_insns " << f.fingerprint.insn_count  << "\n";
        ss << "  fp_bbs "   << f.fingerprint.bb_count    << "\n";
        ss << "  fp_hash "; emit_hex(ss, f.fingerprint.shape_hash); ss << "\n";

        if (!f.prototype.empty()) {
            ss << "  proto "; emit_quoted(ss, f.prototype); ss << "\n";
        }
        if (!f.func_cmt.empty()) {
            ss << "  func_cmt "; emit_quoted(ss, f.func_cmt); ss << "\n";
        }
        if (!f.func_cmt_rpt.empty()) {
            ss << "  func_cmt_rpt "; emit_quoted(ss, f.func_cmt_rpt); ss << "\n";
        }
        for (const auto &c : f.comments) {
            ss << "  cmt "; emit_hex(ss, c.rva);
            ss << " " << (c.repeatable ? "1" : "0") << " ";
            emit_quoted(ss, c.text); ss << "\n";
        }
        for (const auto &l : f.lvars) {
            ss << "  lvar ";
            switch (l.loc_kind) {
                case LvarMeta::LK_REG: ss << "reg " << l.loc_reg;  break;
                case LvarMeta::LK_STK: ss << "stk " << l.loc_stk;  break;
                default:               ss << "none 0";              break;
            }
            ss << " "; emit_hex(ss, l.defea_rva);
            ss << " "; emit_quoted(ss, l.name);
            ss << " "; emit_quoted(ss, l.type);
            ss << "\n";
        }
        for (const auto &c : f.callees) {
            ss << "  callee "; emit_hex(ss, c.call_rva);
            ss << " " << c.callee_id << "\n";
        }
        ss << "end_func\n";
    }

    return ss.str();
}

// --- Parser ---

namespace {

struct Cursor {
    const char *p;
    const char *end;
    int line = 1;

    bool eof() const { return p >= end; }
    char peek() const { return eof() ? '\0' : *p; }

    void skip_spaces() {
        while (!eof() && (*p == ' ' || *p == '\t')) ++p;
    }
    void skip_to_eol() {
        while (!eof() && *p != '\n') ++p;
    }
    void skip_eol() {
        if (!eof() && *p == '\n') { ++p; ++line; }
    }

    bool parse_quoted(std::string *out, std::string *err) {
        skip_spaces();
        if (eof() || *p != '"') {
            *err = "expected '\"'";
            return false;
        }
        ++p;
        out->clear();
        while (!eof() && *p != '"') {
            if (*p == '\\') {
                ++p;
                if (eof()) { *err = "bad escape"; return false; }
                switch (*p) {
                    case 'n':  out->push_back('\n'); break;
                    case 't':  out->push_back('\t'); break;
                    case 'r':  out->push_back('\r'); break;
                    case '"':  out->push_back('"');  break;
                    case '\\': out->push_back('\\'); break;
                    case 'x': {
                        if (end - p < 3) { *err = "bad \\xHH"; return false; }
                        char hex[3] = { p[1], p[2], 0 };
                        char *e = nullptr;
                        unsigned long v = strtoul(hex, &e, 16);
                        if (e != hex + 2) { *err = "bad \\xHH"; return false; }
                        out->push_back((char)v);
                        p += 2;
                        break;
                    }
                    default: *err = "unknown escape"; return false;
                }
                ++p;
            } else {
                if (*p == '\n') { ++line; }
                out->push_back(*p);
                ++p;
            }
        }
        if (eof()) { *err = "unterminated string"; return false; }
        ++p;  // skip closing "
        return true;
    }

    bool parse_uint(uint64_t *out, std::string *err) {
        skip_spaces();
        if (eof()) { *err = "expected number"; return false; }
        char *e = nullptr;
        int base = 10;
        if (end - p >= 2 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) base = 16;
        unsigned long long v = strtoull(p, &e, base);
        if (e == p) { *err = "bad number"; return false; }
        p = e;
        *out = (uint64_t)v;
        return true;
    }

    bool parse_int(int64_t *out, std::string *err) {
        skip_spaces();
        if (eof()) { *err = "expected number"; return false; }
        char *e = nullptr;
        long long v = strtoll(p, &e, 0);
        if (e == p) { *err = "bad number"; return false; }
        p = e;
        *out = (int64_t)v;
        return true;
    }

    // Read a bare-word token (no quotes, no spaces). Used for keys.
    bool parse_word(std::string *out, std::string *err) {
        skip_spaces();
        out->clear();
        while (!eof() && *p != ' ' && *p != '\t' && *p != '\n') {
            out->push_back(*p);
            ++p;
        }
        if (out->empty()) {
            *err = "expected word";
            return false;
        }
        return true;
    }
};

} // namespace

ParseResult parse_metadata(const std::string &text, MetadataDocument *out) {
    ParseResult r;
    Cursor c{ text.data(), text.data() + text.size(), 1 };
    std::string err, word;

    auto fail = [&](const std::string &m) {
        r.ok = false;
        r.error_line = c.line;
        r.error = m;
        return r;
    };

    // Header
    c.skip_spaces();
    if (!c.parse_word(&word, &err) || word != "#cdump-meta")
        return fail("missing #cdump-meta header");
    if (!c.parse_word(&word, &err))
        return fail("missing schema version");
    if (word.empty() || word[0] != 'v')
        return fail("bad schema version");
    out->schema_version = atoi(word.c_str() + 1);
    c.skip_to_eol(); c.skip_eol();

    FunctionMeta *cur_func = nullptr;

    while (!c.eof()) {
        c.skip_spaces();
        if (c.eof()) break;
        if (c.peek() == '\n') { c.skip_eol(); continue; }
        if (c.peek() == '#') { c.skip_to_eol(); c.skip_eol(); continue; }

        if (!c.parse_word(&word, &err)) return fail("expected directive");

        if (word == "image_base") {
            if (!c.parse_uint(&out->source_image_base, &err)) return fail(err);
        } else if (word == "root_ea") {
            if (!c.parse_uint(&out->source_root_ea, &err)) return fail(err);
        } else if (word == "arch") {
            if (!c.parse_quoted(&out->source_arch, &err)) return fail(err);
        } else if (word == "created") {
            if (!c.parse_quoted(&out->created_at, &err)) return fail(err);
        } else if (word == "type") {
            TypeMeta t;
            uint64_t id;
            if (!c.parse_uint(&id, &err)) return fail(err);
            t.id = (uint32_t)id;
            if (!c.parse_quoted(&t.name, &err)) return fail(err);
            if (!c.parse_quoted(&t.decl, &err)) return fail(err);
            out->types.push_back(std::move(t));
        } else if (word == "func") {
            FunctionMeta f;
            uint64_t id;
            if (!c.parse_uint(&id, &err)) return fail(err);
            f.id = (uint32_t)id;
            out->functions.push_back(std::move(f));
            cur_func = &out->functions.back();
        } else if (word == "end_func") {
            cur_func = nullptr;
        } else if (cur_func != nullptr) {
            // Inside a function block.
            if (word == "name") {
                if (!c.parse_quoted(&cur_func->name, &err)) return fail(err);
            } else if (word == "ea") {
                if (!c.parse_uint(&cur_func->ea, &err)) return fail(err);
            } else if (word == "rva") {
                if (!c.parse_uint(&cur_func->rva, &err)) return fail(err);
            } else if (word == "fp_size") {
                uint64_t v; if (!c.parse_uint(&v, &err)) return fail(err);
                cur_func->fingerprint.size_bytes = v;
            } else if (word == "fp_insns") {
                uint64_t v; if (!c.parse_uint(&v, &err)) return fail(err);
                cur_func->fingerprint.insn_count = (uint32_t)v;
            } else if (word == "fp_bbs") {
                uint64_t v; if (!c.parse_uint(&v, &err)) return fail(err);
                cur_func->fingerprint.bb_count = (uint32_t)v;
            } else if (word == "fp_hash") {
                if (!c.parse_uint(&cur_func->fingerprint.shape_hash, &err))
                    return fail(err);
            } else if (word == "proto") {
                if (!c.parse_quoted(&cur_func->prototype, &err)) return fail(err);
            } else if (word == "func_cmt") {
                if (!c.parse_quoted(&cur_func->func_cmt, &err)) return fail(err);
            } else if (word == "func_cmt_rpt") {
                if (!c.parse_quoted(&cur_func->func_cmt_rpt, &err)) return fail(err);
            } else if (word == "cmt") {
                CommentMeta cm;
                if (!c.parse_uint(&cm.rva, &err)) return fail(err);
                uint64_t rpt;
                if (!c.parse_uint(&rpt, &err)) return fail(err);
                cm.repeatable = (rpt != 0);
                if (!c.parse_quoted(&cm.text, &err)) return fail(err);
                cur_func->comments.push_back(std::move(cm));
            } else if (word == "lvar") {
                LvarMeta lv;
                if (!c.parse_word(&word, &err)) return fail(err);
                if (word == "reg") {
                    int64_t v; if (!c.parse_int(&v, &err)) return fail(err);
                    lv.loc_kind = LvarMeta::LK_REG;
                    lv.loc_reg = (int)v;
                } else if (word == "stk") {
                    int64_t v; if (!c.parse_int(&v, &err)) return fail(err);
                    lv.loc_kind = LvarMeta::LK_STK;
                    lv.loc_stk = v;
                } else {
                    int64_t dummy;
                    c.parse_int(&dummy, &err);
                    lv.loc_kind = LvarMeta::LK_NONE;
                }
                if (!c.parse_uint(&lv.defea_rva, &err)) return fail(err);
                if (!c.parse_quoted(&lv.name, &err)) return fail(err);
                if (!c.parse_quoted(&lv.type, &err)) return fail(err);
                cur_func->lvars.push_back(std::move(lv));
            } else if (word == "callee") {
                CalleeRef cr;
                if (!c.parse_uint(&cr.call_rva, &err)) return fail(err);
                uint64_t id;
                if (!c.parse_uint(&id, &err)) return fail(err);
                cr.callee_id = (uint32_t)id;
                cur_func->callees.push_back(std::move(cr));
            } else {
                return fail("unknown function directive: " + word);
            }
        } else {
            return fail("unknown directive: " + word);
        }

        c.skip_to_eol();
        c.skip_eol();
    }

    r.ok = true;
    return r;
}

} // namespace codedump
