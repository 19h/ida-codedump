#pragma once

#include "common/types.h"

#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace codedump {

// Walks decompiled functions and accumulates every user-defined type they
// touch (structs, unions, enums, typedefs, function prototypes, etc.).
// Emits a single header block that contains the full transitive type tree
// in declaration order, suitable for prepending to a code dump.
class TypeCollector {
public:
    TypeCollector() = default;

    // Walk every type referenced by a decompiled function: prototype,
    // locals/params, and every expression's materialized type.
    void collect_from_function(ida::Address func_ea);

    // Record vtable entries discovered by the graph builder so we can emit a
    // companion block listing their addresses + slot -> function mapping.
    void add_vtables(const std::vector<VTableEntry> &vtables);

    // Note that the parent struct/union was accessed at the given byte
    // offset. Used by the "referenced-fields-only" trim emission: any
    // member that doesn't cover a recorded offset is replaced with __int8
    // padding so the struct's sizeof and the kept-member offsets stay
    // correct.
    // Produce the full C-style declaration block. Empty if nothing was found.
    // When `size_comments` is true, structs/unions get column-aligned
    // `// off=N size=M` member annotations and a `// sizeof=0xN` header.
    // When `trim_unreferenced` is true, structs are trimmed to the members
    // covering offsets we observed via record_member_access().
    std::string emit(bool size_comments = false,
                     bool trim_unreferenced = false) const;

private:
    std::set<std::uint32_t> ordinals_;
    std::vector<VTableEntry> vtables_;
    // struct/union name -> set of byte offsets accessed in some function body.
    std::map<std::string, std::set<int>> used_offsets_;
};

} // namespace codedump
