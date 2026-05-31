#pragma once

#include <ida/address.hpp>

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace codedump {

// ---------------------------------------------------------------------------
// Identity fingerprint used to verify that "the same" function exists in the
// target binary before any metadata is applied. The user's scenario: two
// builds where the .text bytes are byte-by-byte identical aside from an
// address shift, so we fingerprint structurally-invariant properties.
// ---------------------------------------------------------------------------
struct FunctionFingerprint {
    uint64_t size_bytes  = 0;   // end_ea - start_ea
    uint32_t insn_count  = 0;
    uint32_t bb_count    = 0;
    uint64_t shape_hash  = 0;   // FNV-1a over (itype, op_types[0..7]) per insn

    bool operator==(const FunctionFingerprint &o) const {
        return size_bytes == o.size_bytes
            && insn_count == o.insn_count
            && bb_count == o.bb_count
            && shape_hash == o.shape_hash;
    }
};

FunctionFingerprint compute_fingerprint(ida::Address function_ea);

// Build a human-readable explanation of how two fingerprints differ.
std::string fingerprint_mismatch_reason(
    const FunctionFingerprint &expected,
    const FunctionFingerprint &actual);

// ---------------------------------------------------------------------------
// Captured metadata for a single function.
// ---------------------------------------------------------------------------
struct CommentMeta {
    uint64_t rva = 0;
    bool repeatable = false;
    std::string text;
};

struct LvarMeta {
    // Locator (binary-portable form).
    enum LocKind { LK_NONE = 0, LK_REG = 1, LK_STK = 2 };
    LocKind loc_kind = LK_NONE;
    int loc_reg = 0;            // for LK_REG
    int64_t loc_stk = 0;        // for LK_STK
    uint64_t defea_rva = 0;     // defea relative to func start, for matching across binaries
    std::string name;
    std::string type;           // C declaration of the type; empty = leave type alone
};

struct CalleeRef {
    uint64_t call_rva  = 0;     // offset of the call instruction within the caller
    uint32_t callee_id = 0;     // FunctionMeta::id of the function being called
};

struct FunctionMeta {
    uint32_t id = 0;
    uint64_t ea = 0;            // original source ea (for diagnostics only)
    uint64_t rva = 0;           // ea - image_base in the source
    std::string name;
    std::string prototype;      // empty = unknown
    std::string func_cmt;       // non-repeatable function comment
    std::string func_cmt_rpt;   // repeatable function comment
    std::vector<CommentMeta> comments;   // per-address (rva) comments
    std::vector<LvarMeta>    lvars;
    std::vector<CalleeRef>   callees;
    FunctionFingerprint fingerprint;
};

// ---------------------------------------------------------------------------
// Captured metadata for a single user type.
// ---------------------------------------------------------------------------
struct TypeMeta {
    uint32_t id = 0;
    std::string name;
    std::string decl;           // C-style declaration text (parsable by IDA)
};

// ---------------------------------------------------------------------------
// Top-level document.
// ---------------------------------------------------------------------------
struct MetadataDocument {
    int      schema_version = 1;
    uint64_t source_image_base = 0;
    uint64_t source_root_ea    = 0;
    std::string source_arch;
    std::string created_at;     // ISO-8601 string, informational
    std::vector<TypeMeta>     types;
    std::vector<FunctionMeta> functions;
};

// ---------------------------------------------------------------------------
// Serialization: simple line-based text protocol with C-escaped quoted
// strings. The format is documented in metadata.cpp.
// ---------------------------------------------------------------------------
std::string serialize_metadata(const MetadataDocument &doc);

struct ParseResult {
    bool ok = false;
    std::string error;          // human-readable message on failure
    int error_line = 0;
};

ParseResult parse_metadata(const std::string &text, MetadataDocument *out);

} // namespace codedump
