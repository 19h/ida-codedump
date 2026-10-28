#pragma once

#include "common/types.h"

#include <cstdint>
#include <map>
#include <set>
#include <string>

namespace codedump {

// How a dumped function uses a referenced data item, derived from the xref
// classification IDA already computed (dr_O / dr_R / dr_W / dr_t / info).
enum class DataUse : std::uint8_t {
    Read,     // r    : value read from the item
    Write,    // w    : value written into the item
    Offset,   // off  : address taken / pointer loaded (GOT slot, lea)
    Text,     // str  : string literal use
    Info,     // info : informational reference
};

inline const char *data_use_char(DataUse u) {
    switch (u) {
        case DataUse::Read:    return "r";
        case DataUse::Write:   return "w";
        case DataUse::Offset:  return "off";
        case DataUse::Text:    return "str";
        case DataUse::Info:    return "info";
        default:               return "?";
    }
}

// Walks the data xrefs of dumped functions and collects every referenced
// data item (string literals, pointer slots, defined data, zero memory).
//
// Emission is normalized to avoid repetition:
//   - emit() renders the "REF-DATA" catalog: one definition line per item
//     (D(addr name) seg kind content) carrying all semantic detail exactly
//     once — pointer targets resolved, zero memory called out in one line.
//   - per_function_records() returns PTN records per function:
//         D: F(func) -> D(item) [uses]
//     which writers place inside the referencing function's block, so the
//     fan-in relationship travels with the code and each mention costs one
//     short line instead of repeating the item's full detail.
class DataRefCollector {
public:
    DataRefCollector() = default;

    // Gather every data-referenced item inside `func_ea`. Safe to call for
    // the same function twice; targets and use-kinds are merged.
    void collect_from_function(ida::Address func_ea);

    // Number of distinct referenced data items collected so far.
    std::size_t size() const { return items_.size(); }
    bool empty() const { return items_.empty(); }

    // Render the "REF-DATA" item catalog (empty when nothing was collected).
    // `max_item_bytes` caps the inline payload shown per item (0 = default
    // 64). `summaries` supplies names for items/functions; unresolved names
    // fall back to the raw address.
    std::string emit(
        std::size_t max_item_bytes,
        const std::map<ida::Address, FunctionSummary> &summaries
    ) const;

    // PTN data-ref records, one entry per function that references data.
    // Lines are emitted WITHOUT the writer comment prefix (writers decide
    // `//` vs `;`). Only functions that reference at least one item appear.
    std::map<ida::Address, std::string> per_function_records(
        const std::map<ida::Address, FunctionSummary> &summaries
    ) const;

private:
    struct ReferencedItem {
        // Function start -> how that function uses this item.
        std::map<ida::Address, std::set<DataUse>> use_by_function;
    };

    // Item start address -> uses. Ordered so the catalog is in address
    // order regardless of collection order.
    std::map<ida::Address, ReferencedItem> items_;
};

} // namespace codedump
