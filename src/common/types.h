#pragma once

#include <ida/address.hpp>

#include <string>
#include <vector>
#include <map>
#include <set>
#include <optional>

namespace codedump {

// Reference types for edges in the call graph
enum class RefType {
    DirectCall,
    IndirectCall,
    DataRef,
    ImmediateRef,
    TailCallPushRet,
    VirtualCall,
    JumpTable
};

inline const char* ref_type_name(RefType rt) {
    switch (rt) {
        case RefType::DirectCall:      return "direct_call";
        case RefType::IndirectCall:    return "indirect_call";
        case RefType::DataRef:         return "data_ref";
        case RefType::ImmediateRef:    return "immediate_ref";
        case RefType::TailCallPushRet: return "tail_call_push_ret";
        case RefType::VirtualCall:     return "virtual_call";
        case RefType::JumpTable:       return "jump_table";
        default:                       return "unknown";
    }
}

// Edge in the call graph
struct Edge {
    ida::Address from;
    ida::Address to;
    std::set<RefType> types;

    Edge(ida::Address f, ida::Address t) : from(f), to(t) {}
    Edge(ida::Address f, ida::Address t, RefType rt) : from(f), to(t) { types.insert(rt); }
};

enum class FunctionOrder {
    Address,
    Entryness,
    Centrality
};

inline const char* function_order_name(FunctionOrder order) {
    switch (order) {
        case FunctionOrder::Address:    return "address";
        case FunctionOrder::Entryness:  return "entry-ness";
        case FunctionOrder::Centrality: return "centrality";
        default:                        return "address";
    }
}

// Dump options (mirrors Python DumpOptionsForm)
struct DumpOptions {
    int caller_depth = 2;
    int callee_depth = 2;
    bool include_direct_calls = true;
    bool include_indirect_calls = true;
    bool include_data_refs = true;
    bool include_immediate_refs = true;
    bool include_tail_calls = true;
    bool include_virtual_calls = true;
    bool include_jump_tables = true;
    bool output_code = true;
    bool output_dot = true;
    bool output_ptn = true;
    bool output_asm = false;
    bool omit_ptn = false;     // Skip PTN annotations in code/asm dumps
    bool size_comments = false; // Annotate udt members with // off=N size=M and structs with // sizeof=0xN
    bool copy_to_clipboard = false; // Skip the file write, push the rendered output to the OS clipboard
    bool register_summary = false;  // Add per-function "// incoming: ...  outgoing: ..." comment via liveness
    bool referenced_fields_only = false; // Trim struct/union members to only those actually accessed (recursive); pad unreferenced bytes
    std::string dot_rankdir = "TB"; // Graphviz rankdir for DOT output: TB, LR, RL, BT
    bool dot_ortho = false; // Emit splines=ortho for DOT output
    bool dot_omit_edge_labels = false; // Keep edge colors/styles but omit ref-type labels in DOT output
    bool dot_cluster_subsystems = false; // Group DOT nodes into subsystem clusters
    bool dot_collapse_subsystems = false; // Hide intra-cluster DOT edges and aggregate inter-cluster edges
    double subsystem_cluster_resolution = 1.0; // Louvain/RB modularity gamma; higher = smaller clusters
    bool tree_shake_stdlib_functions = false; // Drop library/thunk/common runtime functions from graph walks
    FunctionOrder function_order = FunctionOrder::Address; // Rendered function order
    int max_chars = 0;  // 0 = no limit
    std::string output_path;
};

// Options for a single-type dump (driven from the Local Types view).
struct TypeDumpOptions {
    // 0 = just the named type. -1 = unlimited. Otherwise: recurse this many levels.
    int depth = 0;
    bool size_comments = false;
    // Output destination; empty means "show in a text dialog for copy/paste".
    std::string output_path;
};

// Base kind for provenance tracking
enum class BaseKind {
    Local,      // L: local variable
    Param,      // P: parameter
    Global,     // G: global variable
    Constant,   // C: constant value
    Return,     // R: return value
    Derived,    // D: derived from multiple sources
    Unknown
};

inline char base_kind_char(BaseKind bk) {
    switch (bk) {
        case BaseKind::Local:    return 'L';
        case BaseKind::Param:    return 'P';
        case BaseKind::Global:   return 'G';
        case BaseKind::Constant: return 'C';
        case BaseKind::Return:   return 'R';
        case BaseKind::Derived:  return 'D';
        default:                 return '?';
    }
}

// Argument usage at a callsite
struct ArgUse {
    ida::Address call_ea;           // Address of the call instruction
    ida::Address callee_ea;         // Address of the called function
    int arg_idx;            // Argument index (0-based)
    BaseKind origin_kind;   // What kind of value is passed
    std::string origin_id;  // Variable name or global address
    std::string origin_name;// Human-readable name
    int offset = 0;         // Offset into the variable
    int length = 0;         // Size in bytes
    std::string cast_txt;   // Cast expression if any
    std::string mode;       // Access mode (e.g., "&" for address-of)
    std::string member_name;// Struct field name if applicable
    std::string callee_name;// Resolved callee function name
    std::string confidence = "med"; // Confidence: "low", "med", "high"
};

// Alias tracking (local/parameter assignment)
struct Alias {
    BaseKind lhs_kind;      // Kind of left-hand side (Local or Param)
    int lhs_id = -1;        // Variable index for LHS
    std::string lhs_name;   // Left-hand side variable name
    BaseKind rhs_kind;      // Kind of right-hand side
    int rhs_id = -1;        // Variable index for RHS (if local/param)
    std::string rhs_name;   // Human-readable name
    int offset = 0;         // Offset
    int length = 0;         // Size
    std::string mode;       // Access mode: "&", "*", ""
    std::string member_name;// Struct field name if applicable
    std::string confidence = "med"; // Confidence: "low", "med", "high"
};

// Global variable access
struct GlobalAccess {
    ida::Address global_ea;         // Address of the global
    std::string global_name;// Name of the global
    bool is_write;          // True if write, false if read
    ida::Address access_ea;         // Address where access occurs
};

// Alias chain resolution result
struct AliasChain {
    std::string ultimate_origin;              // Final origin variable/global name
    BaseKind origin_kind = BaseKind::Unknown; // Kind of the ultimate origin
    int accumulated_offset = 0;               // Total offset accumulated
    std::vector<std::string> intermediate_vars; // Variables traversed
    std::vector<int> offset_deltas;           // Offset at each step
    std::string confidence = "med";           // Overall confidence
};

// Function summary for provenance analysis
struct FunctionSummary {
    ida::Address func_ea;
    std::string func_name;
    std::vector<std::string> params;
    std::vector<std::string> locals;
    std::vector<ArgUse> arg_uses;
    std::vector<Alias> aliases;
    std::vector<GlobalAccess> global_accesses;
    std::string decompiled_code;
    std::string disassembly;
    // Register liveness summary (populated only when DumpOptions::register_summary is set).
    // `incoming` = registers read along some execution path before being written
    //              (i.e. function inputs the caller must supply).
    // `outgoing` = every register the function writes anywhere.
    std::set<std::string> incoming_regs;
    std::set<std::string> outgoing_regs;
};

// VTable entry
struct VTableEntry {
    ida::Address vtable_ea;
    int offset;
    ida::Address func_ea;
};

} // namespace codedump
