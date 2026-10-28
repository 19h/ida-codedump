#include "data_ref_collector.h"

#include <ida/address.hpp>
#include <ida/data.hpp>
#include <ida/function.hpp>
#include <ida/name.hpp>
#include <ida/segment.hpp>
#include <ida/xref.hpp>

// Raw SDK flag checks: idax doesn't expose item flags, but distinguishing a
// genuinely-defined string literal / pointer-offset item from bytes that
// merely look like one (e.g. a GOT slot vs. an int array) needs
// is_strlit()/is_off() over get_flags(). Same guarded raw-include pattern as
// graph_builder.cpp.
#include "common/warn_off.h"
#include <pro.h>
#include <ida.hpp>
#include <bytes.hpp>
#include "common/warn_on.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <format>
#include <sstream>
#include <string>

namespace codedump {

namespace {

// Upper bound on the bytes we attempt to read for a single item. item_size()
// can return very large values for oversized arrays; capping keeps a stray
// reference from stalling the dump.
constexpr std::size_t kMaxProbeBytes = 4096;
// Bytes of an inline hex payload shown in the catalog when no tighter limit
// is requested. One line per item keeps the catalog scan-friendly.
constexpr std::size_t kDefaultPayloadBytes = 16;

std::string function_display_name(
    ida::Address func_ea,
    const std::map<ida::Address, FunctionSummary> &summaries
) {
    auto it = summaries.find(func_ea);
    if (it != summaries.end() && !it->second.func_name.empty())
        return it->second.func_name;
    auto name = ida::function::name_at(func_ea);
    if (name && !name->empty()) return *name;
    return std::format("sub_{:X}", static_cast<unsigned long long>(func_ea));
}

std::string escape_string_text(const std::string &text) {
    std::string out;
    out.reserve(text.size());
    for (unsigned char c : text) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (std::isprint(c)) {
                    out += static_cast<char>(c);
                } else {
                    out += std::format("\\x{:02x}", c);
                }
                break;
        }
    }
    return out;
}

// Resolve the address a pointer-typed item points at to a readable name when
// one exists (function start, named data, stub); otherwise raw hex.
std::string pointer_target_text(ida::Address value) {
    if (value == 0 || value == ida::BadAddress || !ida::address::is_mapped(value))
        return std::format("0x{:X}", static_cast<unsigned long long>(value));

    auto name = ida::name::get(value);
    if (name && !name->empty())
        return *name;
    auto func_name = ida::function::name_at(value);
    if (func_name && !func_name->empty())
        return *func_name;
    return std::format("0x{:X}", static_cast<unsigned long long>(value));
}

// Join a set of uses into the bracket token, e.g. "[off r]" / "[r w]".
std::string use_token(const std::set<DataUse> &uses) {
    std::string out = "[";
    for (DataUse u : uses) {
        if (out.size() > 1) out += " ";
        out += data_use_char(u);
    }
    out += "]";
    return out;
}

} // namespace

void DataRefCollector::collect_from_function(ida::Address func_ea) {
    ida::Result<ida::function::Function> function = ida::function::at(func_ea);
    if (!function) return;

    const ida::Address start = static_cast<ida::Address>(function->start());
    const ida::Address end = static_cast<ida::Address>(function->end());

    for (ida::Address addr = start; addr < end && addr != ida::BadAddress; ) {
        ida::Result<std::vector<ida::xref::Reference>> refs =
            ida::xref::data_refs_from(addr);
        if (refs) {
            for (const ida::xref::Reference &ref : *refs) {
                ida::Address target = static_cast<ida::Address>(ref.to);
                if (target == ida::BadAddress) continue;
                // Function pointers land in data as code refs; their "data"
                // lives in the functions themselves, not in a data item.
                if (ida::address::is_code(target)) continue;
                // Normalize tail-byte references (e.g. ptr+4) to the item
                // head so one item is listed once, not per offset.
                ida::Result<ida::Address> head = ida::address::item_start(target);
                if (head && *head != ida::BadAddress) target = *head;

                // Classify how the function uses the item from the xref kind
                // IDA recorded during analysis.
                DataUse use = DataUse::Info;
                switch (ref.type) {
                    case ida::xref::ReferenceType::Read:           use = DataUse::Read; break;
                    case ida::xref::ReferenceType::Write:          use = DataUse::Write; break;
                    case ida::xref::ReferenceType::Offset:         use = DataUse::Offset; break;
                    case ida::xref::ReferenceType::Text:           use = DataUse::Text; break;
                    case ida::xref::ReferenceType::Informational:  use = DataUse::Info; break;
                    default:                                       use = DataUse::Info; break;
                }

                if (auto existing = items_.find(target); existing != items_.end()) {
                    existing->second.use_by_function[func_ea].insert(use);
                    continue;
                }

                // Skip import/extern stubs: they have no file bytes to show.
                ida::Result<ida::segment::Segment> seg = ida::segment::at(target);
                if (seg && (seg->type() == ida::segment::Type::External ||
                            seg->type() == ida::segment::Type::Import))
                    continue;

                items_[target].use_by_function[func_ea].insert(use);
            }
        }

        ida::Result<ida::Address> next = ida::address::next_head(addr, end);
        if (!next || *next == ida::BadAddress || *next <= addr) break;
        addr = *next;
    }
}

std::string DataRefCollector::emit(
    std::size_t max_item_bytes,
    const std::map<ida::Address, FunctionSummary> &summaries
) const {
    if (items_.empty()) return {};

    if (max_item_bytes == 0) max_item_bytes = kDefaultPayloadBytes;
    max_item_bytes = std::min<std::size_t>(max_item_bytes, kMaxProbeBytes);

    std::ostringstream ss;
    ss << "// REF-DATA (" << items_.size() << " item"
       << (items_.size() == 1 ? "" : "s")
       << " referenced by the dumped code)\n";
    ss << "// LEGEND: D(addr name) = data item (declared once below);\n";
    ss << "//         D: F(func) -> D(item) [uses] = PTN data-ref record, one per\n";
    ss << "//         function block. uses: r=read w=write off=address-of/offset\n";
    ss << "//         str=string info\n";
    ss << "// ------------------------------------------------------------\n\n";

    for (const auto &[ea, item] : items_) {
        std::string seg_text;
        ida::Result<ida::segment::Segment> seg = ida::segment::at(ea);
        if (seg) seg_text = seg->name();

        std::string name_text;
        auto name = ida::name::get(ea);
        if (name && !name->empty()) name_text = *name;

        std::size_t item_size = 0;
        if (auto sz = ida::address::item_size(ea)) item_size = *sz;

        ss << "// D(" << std::format("0x{:X}", static_cast<unsigned long long>(ea));
        if (!name_text.empty()) ss << " " << name_text;
        ss << ")";
        if (!seg_text.empty()) ss << " " << seg_text;

        bool rendered_payload = false;

        // String literal: quoted, escaped, capped.
        if (item_size > 0 && is_strlit(get_flags(ea))) {
            auto str = ida::data::read_string(
                ea,
                static_cast<ida::AddressSize>(
                    std::min<std::size_t>(item_size, max_item_bytes + 1)));
            if (str && !str->empty()) {
                bool printable = std::all_of(str->begin(), str->end(), [](unsigned char c) {
                    return c == '\n' || c == '\r' || c == '\t' || std::isprint(c);
                });
                if (printable) {
                    bool truncated = str->size() >= max_item_bytes + 1;
                    ss << " str \"" << escape_string_text(truncated
                                                              ? str->substr(0, max_item_bytes)
                                                              : *str)
                       << "\"" << (truncated ? " ..." : "") << "\n";
                    rendered_payload = true;
                }
            }
        }

        // Pointer/offset item: resolve the target so the record carries
        // semantics instead of raw pointer bytes. is_off() is per-operand;
        // any operand marked as an offset counts.
        if (!rendered_payload && item_size > 0 && (item_size == 4 || item_size == 8)) {
            flags64_t flags = get_flags(ea);
            bool has_offset_operand = false;
            for (int n = 0; n < UA_MAXOP; ++n) {
                if (is_off(flags, n)) {
                    has_offset_operand = true;
                    break;
                }
            }
            if (has_offset_operand) {
                std::uint64_t value = 0;
                bool have_value = false;
                if (item_size == 8) {
                    if (auto v = ida::data::read_qword(ea)) {
                        value = *v;
                        have_value = true;
                    }
                } else {
                    if (auto v = ida::data::read_dword(ea)) {
                        value = *v;
                        have_value = true;
                    }
                }
                if (have_value) {
                    ss << " ptr->" << pointer_target_text(static_cast<ida::Address>(value))
                       << "\n";
                    rendered_payload = true;
                }
            }
        }

        // Everything else: hex payload, with the surgical zero callout.
        if (!rendered_payload && item_size > 0) {
            std::size_t want = std::min<std::size_t>(item_size, max_item_bytes);
            auto bytes = ida::data::read_bytes(ea, static_cast<ida::AddressSize>(want));
            if (bytes && !bytes->empty()) {
                bool all_zero = std::all_of(bytes->begin(), bytes->end(),
                                            [](std::uint8_t b) { return b == 0; });
                if (all_zero) {
                    // Surgical zero mention: one token instead of N bytes of 00.
                    // A fully-zero prefix of the item implies the whole item is
                    // zero (BSS/common or zero-initialized data).
                    ss << " " << item_size << " all-zero";
                    if (seg && (seg->type() == ida::segment::Type::Bss ||
                                seg->type() == ida::segment::Type::Common))
                        ss << "(uninit)";
                    ss << "\n";
                    rendered_payload = true;
                } else {
                    ss << " " << item_size << " [";
                    for (std::size_t i = 0; i < bytes->size(); ++i) {
                        if (i) ss << " ";
                        ss << std::format("{:02x}", (*bytes)[i]);
                    }
                    ss << "]";
                    if (bytes->size() < item_size)
                        ss << " +" << (item_size - bytes->size()) << "b";
                    ss << "\n";
                    rendered_payload = true;
                }
            } else if (seg && (seg->type() == ida::segment::Type::Bss ||
                               seg->type() == ida::segment::Type::Common)) {
                // Uninitialized segments have no file bytes backing them;
                // IDA's get_bytes reports them as unreadable but they are
                // zero-filled at runtime.
                ss << " " << item_size << " all-zero(uninit)\n";
                rendered_payload = true;
            }
        }

        if (!rendered_payload)
            ss << " unreadable\n";
    }

    // Trailing blank line so the catalog stays separated from whatever the
    // writer appends next (function blocks, etc.).
    ss << "\n";

    return ss.str();
}

std::map<ida::Address, std::string> DataRefCollector::per_function_records(
    const std::map<ida::Address, FunctionSummary> &summaries
) const {
    // Function -> lines (items in address order, since items_ is ordered).
    std::map<ida::Address, std::ostringstream> out;

    for (const auto &[ea, item] : items_) {
        std::string item_display;
        auto name = ida::name::get(ea);
        if (name && !name->empty())
            item_display = *name;
        else
            item_display = std::format("0x{:X}", static_cast<unsigned long long>(ea));

        for (const auto &[func_ea, uses] : item.use_by_function) {
            out[func_ea] << "D: F(" << function_display_name(func_ea, summaries)
                         << ") -> D(" << item_display << ") "
                         << use_token(uses) << "\n";
        }
    }

    std::map<ida::Address, std::string> records;
    for (auto &[func_ea, lines] : out)
        records.emplace(func_ea, lines.str());
    return records;
}

} // namespace codedump
