// The decisions behind one codedump binary talking to the IDA 9.4 and 9.5
// decompilers. The expected values are the Hex-Rays SDK's own: 9.4 answers
// handshake magic 0x00DEC0DE00000005, 9.5 answers 0x00DEC0DE00000006 once its
// ABI change was declared, 9.5.0-beta.1 still answers ...05 with the 9.5
// layout, 9.5 stores a bit offset in cexpr_t::m under EXFL_BITFIELD (0x0400),
// and 9.4's 32-bit m shares its 8-byte slot with the y/a pointers of the same
// union.

#include "common/hexrays_abi.hpp"

#include <cstdint>
#include <cstdio>
#include <optional>

namespace {

int g_checks = 0;
int g_failures = 0;

#define CHECK_MSG(cond, msg)                                                                       \
    do {                                                                                           \
        ++g_checks;                                                                                \
        if (!(cond)) {                                                                             \
            ++g_failures;                                                                          \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, msg);                              \
        }                                                                                          \
    } while (0)

using codedump::hexrays_abi::DecompilerLayout;
using codedump::hexrays_abi::KernelVersion;
namespace abi = codedump::hexrays_abi;

constexpr std::int64_t k_sdk_94_magic = 0x00DEC0DE00000005LL;
constexpr std::int64_t k_sdk_95_magic = 0x00DEC0DE00000006LL;
constexpr std::int64_t k_sdk_93_magic = 0x00DEC0DE00000004LL;

bool parses_as(const char* text, int major, int minor) {
    const std::optional<KernelVersion> parsed = abi::parse_kernel_version(text);
    return parsed.has_value() && parsed->major == major && parsed->minor == minor;
}

void test_sdk_facts() {
    CHECK_MSG(abi::hexrays_magic_94 == k_sdk_94_magic, "9.4 magic is the 9.4 SDK's");
    CHECK_MSG(abi::hexrays_magic_95 == k_sdk_95_magic, "9.5 magic is the bumped one");
    CHECK_MSG(abi::handshake_reply(k_sdk_94_magic) == 0x00DEC0DE,
              "accepted handshake answers the magic's high half");
    CHECK_MSG(abi::handshake_reply(k_sdk_95_magic) == 0x00DEC0DE,
              "both magics share the reply, so the reply alone cannot tell them apart");
    CHECK_MSG(abi::exfl_bitfield_95 == 0x0400, "EXFL_BITFIELD of IDA 9.5");
}

void test_kernel_version_parsing() {
    CHECK_MSG(parses_as("9.4", 9, 4), "plain 9.4");
    CHECK_MSG(parses_as("9.5", 9, 5), "plain 9.5");
    CHECK_MSG(parses_as("9.4.260915", 9, 4), "build suffix ignored");
    CHECK_MSG(parses_as("9.5.260915", 9, 5), "9.5 build suffix ignored");
    CHECK_MSG(parses_as("9.5sp1", 9, 5), "service-pack suffix ignored");
    CHECK_MSG(parses_as("10.0", 10, 0), "two-digit major");

    CHECK_MSG(!abi::parse_kernel_version("").has_value(), "empty answer");
    CHECK_MSG(!abi::parse_kernel_version("9").has_value(), "no minor");
    CHECK_MSG(!abi::parse_kernel_version("9.").has_value(), "dot without minor");
    CHECK_MSG(!abi::parse_kernel_version(".5").has_value(), "minor without major");
    CHECK_MSG(!abi::parse_kernel_version("v9.5").has_value(), "leading text");
    CHECK_MSG(!abi::parse_kernel_version("9-5").has_value(), "wrong separator");
}

void test_handshake_order() {
    const auto on_94 = abi::handshake_order(KernelVersion{9, 4});
    CHECK_MSG(on_94[0] == k_sdk_94_magic && on_94[1] == k_sdk_95_magic,
              "9.4 kernel offers its own magic first, the 9.5 one second");

    const auto on_95 = abi::handshake_order(KernelVersion{9, 5});
    CHECK_MSG(on_95[0] == k_sdk_95_magic && on_95[1] == k_sdk_94_magic,
              "9.5 kernel offers the bumped magic first and still the old one: "
              "9.5.0-beta.1 answers only the old one");

    const auto unknown = abi::handshake_order(std::nullopt);
    CHECK_MSG(unknown[0] == k_sdk_94_magic && unknown[1] == k_sdk_95_magic,
              "an unreadable kernel version still offers both");

    const auto later = abi::handshake_order(KernelVersion{10, 0});
    CHECK_MSG(later[0] == k_sdk_95_magic && later[1] == k_sdk_94_magic, "later majors lead with 9.5");

    for (const std::int64_t magic : abi::handshake_order(KernelVersion{9, 3}))
        CHECK_MSG(magic != k_sdk_93_magic, "the 9.3 decompiler ABI is never offered");
}

void test_layout_for_handshake() {
    CHECK_MSG(abi::layout_for_handshake(k_sdk_94_magic, KernelVersion{9, 4}) == DecompilerLayout::V94,
              "IDA 9.4 answering its magic is the 9.4 layout");
    CHECK_MSG(abi::layout_for_handshake(k_sdk_95_magic, KernelVersion{9, 5}) == DecompilerLayout::V95,
              "IDA 9.5 answering the bumped magic is the 9.5 layout");
    CHECK_MSG(abi::layout_for_handshake(k_sdk_94_magic, KernelVersion{9, 5}) == DecompilerLayout::V95,
              "9.5.0-beta.1 answers the old magic with the new layout");
    CHECK_MSG(abi::layout_for_handshake(k_sdk_95_magic, KernelVersion{9, 4}) == DecompilerLayout::V95,
              "the bumped magic is the decompiler's own word, whatever the kernel says");
    CHECK_MSG(abi::layout_for_handshake(k_sdk_95_magic, std::nullopt) == DecompilerLayout::V95,
              "bumped magic without a kernel version");
    CHECK_MSG(abi::layout_for_handshake(k_sdk_94_magic, std::nullopt) == DecompilerLayout::V94,
              "old magic without a kernel version is the released 9.4");
    CHECK_MSG(abi::layout_for_handshake(k_sdk_93_magic, KernelVersion{9, 3}) == DecompilerLayout::Unknown,
              "a magic this build does not know has no layout");
    CHECK_MSG(abi::layout_for_handshake(0, KernelVersion{9, 4}) == DecompilerLayout::Unknown,
              "no magic, no layout");
    CHECK_MSG(abi::layout_name(DecompilerLayout::V94)[0] == '9' &&
                  abi::layout_name(DecompilerLayout::V95)[2] == '5' &&
                  abi::layout_name(DecompilerLayout::Unknown)[0] == 'u',
              "layout names");
}

void test_member_byte_offset() {
    // 9.4: m is the low half of a slot shared with a pointer.
    CHECK_MSG(abi::member_byte_offset(0xDEADBEEF00000020ull, 0, DecompilerLayout::V94) == 0x20,
              "9.4 layout ignores the stale upper half");
    CHECK_MSG(abi::member_byte_offset(0x20, abi::exfl_bitfield_95, DecompilerLayout::V94) == 0x20,
              "9.4 never means a bit offset, whatever exflags holds");
    CHECK_MSG(abi::member_byte_offset(0, 0, DecompilerLayout::V94) == 0, "offset zero");
    CHECK_MSG(abi::member_byte_offset(0xFFFFFFFFull, 0, DecompilerLayout::V94) == 0xFFFFFFFFull,
              "largest 9.4 offset");

    // 9.5: a full 64-bit byte offset, or a bit offset for bitfield accesses.
    CHECK_MSG(abi::member_byte_offset(0x20, 0, DecompilerLayout::V95) == 0x20,
              "plain 9.5 member access is a byte offset");
    CHECK_MSG(abi::member_byte_offset(0x100000020ull, 0, DecompilerLayout::V95) == 0x100000020ull,
              "9.5 keeps offsets past 32 bits");
    CHECK_MSG(abi::member_byte_offset(35, abi::exfl_bitfield_95, DecompilerLayout::V95) == 4,
              "9.5 bitfield at bit 35 lies in byte 4");
    CHECK_MSG(abi::member_byte_offset(7, abi::exfl_bitfield_95, DecompilerLayout::V95) == 0,
              "9.5 bitfield inside the first byte");
    CHECK_MSG(abi::member_byte_offset(64, abi::exfl_bitfield_95 | 0x0001, DecompilerLayout::V95) == 8,
              "other exflags bits do not hide the bitfield bit");

    // Before any handshake: read conservatively, as 9.4.
    CHECK_MSG(abi::member_byte_offset(0xDEADBEEF00000020ull, abi::exfl_bitfield_95,
                                      DecompilerLayout::Unknown) == 0x20,
              "unknown layout reads the 32 bits every layout agrees on");
}

} // namespace

int main() {
    test_sdk_facts();
    test_kernel_version_parsing();
    test_handshake_order();
    test_layout_for_handshake();
    test_member_byte_offset();

    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
