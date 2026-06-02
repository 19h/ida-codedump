// Headless idalib benchmark harness for the codedump graph builder.
//
// Purpose: reproduce the GUI slowness (vtable scan + callee crawl) outside
// IDA, and isolate whether the cost is in idax's wrappers or in the SDK
// calls themselves. It runs the *real* GraphBuilder code path and a
// raw-SDK reimplementation of the same inner loops, then compares.
//
// Usage:
//   cdump_bench <idb-or-binary> [--ea 0x1800xxxxx | --name sub_xxx]
//                               [--caller-depth N] [--callee-depth N]
//                               [--no-raw]
//
// Build: configured as the `cdump_bench` target when CODEDUMP_BUILD_BENCH=ON.

#include <ida/address.hpp>
#include <ida/data.hpp>
#include <ida/function.hpp>
#include <ida/instruction.hpp>

#include "graph/graph_builder.h"

// Raw SDK headers for the comparison path.
#include <ida.hpp>
#include <idp.hpp>
#include <ua.hpp>
#include <auto.hpp>
#include <funcs.hpp>
#include <bytes.hpp>
#include <segment.hpp>
#include <xref.hpp>
#include <name.hpp>
#include <idalib.hpp>

#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <algorithm>
#include <vector>

using clock_type = std::chrono::steady_clock;

static double secs_since(clock_type::time_point t0) {
    return std::chrono::duration<double>(clock_type::now() - t0).count();
}

// ── raw-SDK mirror of GraphBuilder::scan_vtables inner loop ──────────────
// Mirrors the algorithm exactly but uses raw get_qword/get_func and only
// reads start_ea (no name resolution / no populate). This is the floor cost.

namespace {

struct RawStats {
    uint64_t slots = 0;       // pointer-aligned slots examined
    uint64_t reads = 0;       // get_qword / get_dword calls
    uint64_t func_lookups = 0;// get_func calls
    uint64_t vtables = 0;     // tables found (>=3 consecutive fptrs)
};

bool raw_is64() { return inf_is_64bit(); }

bool raw_read_ptr(ea_t ea, bool is64, ea_t &out, RawStats &st) {
    if (!is_loaded(ea)) return false;
    ++st.reads;
    ea_t v = is64 ? (ea_t)get_qword(ea) : (ea_t)get_dword(ea);
    if (v == BADADDR || v == 0) return false;
    out = v;
    return true;
}

bool raw_func_start(ea_t ea, ea_t &out, RawStats &st) {
    ++st.func_lookups;
    func_t *f = get_func(ea);
    if (f == nullptr) return false;
    out = f->start_ea;
    return true;
}

RawStats raw_scan_vtables() {
    RawStats st;
    const bool is64 = raw_is64();
    const int ptr_size = is64 ? 8 : 4;

    int nseg = get_segm_qty();
    for (int i = 0; i < nseg; i++) {
        segment_t *seg = getnseg(i);
        if (seg == nullptr) continue;
        if ((seg->perm & SEGPERM_EXEC) != 0) continue;  // data segments only

        ea_t addr = seg->start_ea;
        while (addr < seg->end_ea) {
            ++st.slots;
            if (addr % ptr_size != 0) { addr++; continue; }

            // Try to find 3+ consecutive function pointers.
            int found = 0;
            ea_t scan = addr;
            while (scan < seg->end_ea) {
                ea_t ptr;
                if (!raw_read_ptr(scan, is64, ptr, st)) break;
                ea_t fp;
                if (!raw_func_start(ptr, fp, st) || fp != ptr) break;
                ++found;
                scan += ptr_size;
            }

            if (found >= 3) {
                ++st.vtables;
                addr = scan;
            } else {
                addr += ptr_size;
            }
        }
    }
    return st;
}

// Bulk variant: read each data segment into memory once with get_bytes, then
// interpret pointers in-RAM. Replaces ~N get_qword calls (~283 ns each) with
// one get_bytes per segment + in-RAM loads. get_func is still called per
// candidate slot, but that's only ~11 ns. Should be functionally identical.
RawStats raw_scan_vtables_bulk() {
    RawStats st;
    const bool is64 = raw_is64();
    const int ptr_size = is64 ? 8 : 4;

    int nseg = get_segm_qty();
    std::vector<uint8_t> buf;
    for (int i = 0; i < nseg; i++) {
        segment_t *seg = getnseg(i);
        if (seg == nullptr) continue;
        if ((seg->perm & SEGPERM_EXEC) != 0) continue;

        size_t seg_len = (size_t)(seg->end_ea - seg->start_ea);
        buf.assign(seg_len, 0);
        // get_bytes fills unmapped/unloaded bytes per the gaps mask; we pass
        // GMB_READALL semantics implicitly (missing bytes stay 0).
        get_bytes(buf.data(), seg_len, seg->start_ea, GMB_READALL);
        ++st.reads;  // one bulk read per segment

        auto load_ptr = [&](size_t off, ea_t &out) -> bool {
            if (off + (size_t)ptr_size > seg_len) return false;
            uint64_t v = 0;
            for (int b = 0; b < ptr_size; b++)
                v |= (uint64_t)buf[off + b] << (8 * b);
            if (v == 0 || v == BADADDR) return false;
            out = (ea_t)v;
            return true;
        };

        size_t off = 0;
        while (off < seg_len) {
            ++st.slots;
            ea_t addr = seg->start_ea + off;
            if (addr % ptr_size != 0) { off++; continue; }

            int found = 0;
            size_t scan = off;
            while (scan + (size_t)ptr_size <= seg_len) {
                ea_t ptr;
                if (!load_ptr(scan, ptr)) break;
                ea_t fp;
                if (!raw_func_start(ptr, fp, st) || fp != ptr) break;
                ++found;
                scan += ptr_size;
            }

            if (found >= 3) { ++st.vtables; off = scan; }
            else off += ptr_size;
        }
    }
    return st;
}

// Function-start-set variant: precompute a sorted vector of all function
// start addresses once, then the per-slot "is this value a function start?"
// test becomes an in-RAM binary search (~20 ns) instead of get_func (~300 ns).
// This is the candidate fix for the real bottleneck.
RawStats raw_scan_vtables_fnset() {
    RawStats st;
    const bool is64 = raw_is64();
    const int ptr_size = is64 ? 8 : 4;

    // Precompute sorted function starts.
    std::vector<ea_t> starts;
    size_t fq = get_func_qty();
    starts.reserve(fq);
    for (size_t i = 0; i < fq; i++) {
        func_t *f = getn_func(i);
        if (f) starts.push_back(f->start_ea);
    }
    std::sort(starts.begin(), starts.end());

    auto is_func_start = [&](ea_t ea) -> bool {
        return std::binary_search(starts.begin(), starts.end(), ea);
    };

    int nseg = get_segm_qty();
    for (int i = 0; i < nseg; i++) {
        segment_t *seg = getnseg(i);
        if (seg == nullptr) continue;
        if ((seg->perm & SEGPERM_EXEC) != 0) continue;

        ea_t addr = seg->start_ea;
        while (addr < seg->end_ea) {
            ++st.slots;
            if (addr % ptr_size != 0) { addr++; continue; }

            int found = 0;
            ea_t scan = addr;
            while (scan < seg->end_ea) {
                ea_t ptr;
                if (!raw_read_ptr(scan, is64, ptr, st)) break;
                ++st.func_lookups;
                if (!is_func_start(ptr)) break;   // value must be a function start
                ++found;
                scan += ptr_size;
            }

            if (found >= 3) { ++st.vtables; addr = scan; }
            else addr += ptr_size;
        }
    }
    return st;
}

// Xref variant: instead of reading every data slot, enumerate the data->code
// references IDA already computed during analysis. Every vtable slot that
// points at a function start already has a dref to that function. So gather
// all such slot addresses, sort them, and cluster runs of >=3 consecutive
// pointer-aligned slots into vtables. Work is O(#code-pointers-in-data), not
// O(#data-bytes) — no brute-force reads at all.
RawStats raw_scan_vtables_xref() {
    RawStats st;
    const bool is64 = raw_is64();
    const int ptr_size = is64 ? 8 : 4;

    // Set of data segment ranges for fast membership.
    std::vector<std::pair<ea_t, ea_t>> data_ranges;
    int nseg = get_segm_qty();
    for (int i = 0; i < nseg; i++) {
        segment_t *seg = getnseg(i);
        if (seg == nullptr || (seg->perm & SEGPERM_EXEC)) continue;
        data_ranges.emplace_back(seg->start_ea, seg->end_ea);
    }
    auto in_data = [&](ea_t ea) -> bool {
        for (auto &r : data_ranges)
            if (ea >= r.first && ea < r.second) return true;
        return false;
    };

    // Collect (slot_addr) for every dref from data to a function start.
    std::vector<ea_t> slots;
    size_t fq = get_func_qty();
    for (size_t i = 0; i < fq; i++) {
        func_t *f = getn_func(i);
        if (f == nullptr) continue;
        ea_t fea = f->start_ea;
        for (ea_t from = get_first_dref_to(fea); from != BADADDR;
             from = get_next_dref_to(fea, from)) {
            ++st.func_lookups;
            if ((from % ptr_size) == 0 && in_data(from))
                slots.push_back(from);
        }
    }
    std::sort(slots.begin(), slots.end());
    slots.erase(std::unique(slots.begin(), slots.end()), slots.end());
    st.slots = slots.size();

    // Cluster consecutive pointer-aligned slots into runs of >=3.
    size_t i = 0;
    while (i < slots.size()) {
        size_t j = i + 1;
        while (j < slots.size() && slots[j] == slots[j - 1] + (ea_t)ptr_size)
            ++j;
        if (j - i >= 3) ++st.vtables;
        i = j;
    }
    return st;
}

// Micro-benchmark the two idax primitives vs their raw counterparts over a
// fixed set of probe addresses, to attribute per-call overhead precisely.
void micro_bench(const std::vector<ea_t> &probe) {
    // function_start: idax ida::function::at(...) vs raw get_func()->start_ea
    {
        auto t0 = clock_type::now();
        volatile uint64_t sink = 0;
        for (ea_t ea : probe) {
            ida::Result<ida::function::Function> f = ida::function::at(ea);
            if (f) sink += f->start();
        }
        double idax_s = secs_since(t0);

        t0 = clock_type::now();
        sink = 0;
        for (ea_t ea : probe) {
            func_t *f = get_func(ea);
            if (f) sink += f->start_ea;
        }
        double raw_s = secs_since(t0);
        (void)sink;
        printf("  function_start: idax %.0f ns/call  raw %.0f ns/call  (%.1fx)\n",
               idax_s / probe.size() * 1e9, raw_s / probe.size() * 1e9,
               raw_s > 0 ? idax_s / raw_s : 0.0);
    }

    // read_qword: idax ida::data::read_qword(...) vs raw get_qword()
    {
        auto t0 = clock_type::now();
        volatile uint64_t sink = 0;
        for (ea_t ea : probe) {
            ida::Result<std::uint64_t> v = ida::data::read_qword(ea);
            if (v) sink += *v;
        }
        double idax_s = secs_since(t0);

        t0 = clock_type::now();
        sink = 0;
        for (ea_t ea : probe) sink += get_qword(ea);
        double raw_s = secs_since(t0);
        (void)sink;
        printf("  read_qword:     idax %.0f ns/call  raw %.0f ns/call  (%.1fx)\n",
               idax_s / probe.size() * 1e9, raw_s / probe.size() * 1e9,
               raw_s > 0 ? idax_s / raw_s : 0.0);
    }
}

} // namespace

int main(int argc, char *argv[]) {
    const char *db = nullptr;
    ea_t start_ea = BADADDR;
    const char *start_name = nullptr;
    int caller_depth = 2;
    int callee_depth = 10;
    bool run_raw = true;
    bool run_crawl = true;
    const char *only_mode = nullptr;  // "idax" | "raw" | "bulk" | "fnset"
    const char *profile_feature = nullptr;  // sweep all funcs through one feature
    long profile_limit = 0;  // 0 = all functions

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&](const char *def) -> const char * {
            return (i + 1 < argc) ? argv[++i] : def;
        };
        if (a == "--ea") start_ea = (ea_t)strtoull(next("0"), nullptr, 0);
        else if (a == "--name") start_name = next(nullptr);
        else if (a == "--caller-depth") caller_depth = atoi(next("2"));
        else if (a == "--callee-depth") callee_depth = atoi(next("10"));
        else if (a == "--no-raw") run_raw = false;
        else if (a == "--only") only_mode = next("");
        else if (a == "--no-crawl") run_crawl = false;
        else if (a == "--profile-feature") profile_feature = next("");
        else if (a == "--profile-limit") profile_limit = atol(next("0"));
        else if (a[0] != '-') db = argv[i];
    }

    if (db == nullptr) {
        fprintf(stderr, "usage: %s <idb-or-binary> [--ea 0x.. | --name sub_..] "
                        "[--caller-depth N] [--callee-depth N] [--no-raw]\n", argv[0]);
        return 2;
    }

    if (init_library() != 0) {
        fprintf(stderr, "init_library failed\n");
        return 1;
    }
    enable_console_messages(true);

    printf("opening %s ...\n", db);
    auto t_open = clock_type::now();
    if (open_database(db, true) != 0) {
        fprintf(stderr, "open_database failed\n");
        return 1;
    }
    auto_wait();
    printf("opened + analyzed in %.2f s\n", secs_since(t_open));

    // Resolve start function.
    if (start_ea == BADADDR && start_name != nullptr)
        start_ea = get_name_ea(BADADDR, start_name);
    if (start_ea == BADADDR) {
        // Default: first function in the database.
        func_t *f0 = getn_func(0);
        if (f0) start_ea = f0->start_ea;
    }
    func_t *sf = get_func(start_ea);
    if (sf) start_ea = sf->start_ea;
    qstring sn;
    get_func_name(&sn, start_ea);
    printf("start function: %s @ 0x%" PRIxPTR "\n", sn.c_str(), (uintptr_t)start_ea);

    // Segment summary.
    int nseg = get_segm_qty();
    uint64_t data_bytes = 0;
    int data_segs = 0;
    for (int i = 0; i < nseg; i++) {
        segment_t *seg = getnseg(i);
        if (!seg || (seg->perm & SEGPERM_EXEC)) continue;
        data_bytes += (seg->end_ea - seg->start_ea);
        ++data_segs;
    }
    printf("data segments: %d  (%.1f MiB)\n", data_segs, data_bytes / 1048576.0);

    codedump::DumpOptions opts;
    opts.caller_depth = caller_depth;
    opts.callee_depth = callee_depth;

    // ── Cold-cache single-variant mode ──────────────────────────────────
    // Run exactly one scan variant (first thing after open) so the .i64 page
    // cache is cold. Invoke the harness in separate processes per mode to
    // compare apples-to-apples without warming confounds.
    if (only_mode) {
        printf("\n[ONLY %s — cold cache]\n", only_mode);
        auto t0 = clock_type::now();
        RawStats st;
        if (std::strcmp(only_mode, "idax") == 0) {
            codedump::GraphBuilder gb(opts);
            gb.add_start_function(start_ea);
            gb.scan_vtables();
        } else if (std::strcmp(only_mode, "raw") == 0) {
            st = raw_scan_vtables();
        } else if (std::strcmp(only_mode, "bulk") == 0) {
            st = raw_scan_vtables_bulk();
        } else if (std::strcmp(only_mode, "fnset") == 0) {
            st = raw_scan_vtables_fnset();
        } else if (std::strcmp(only_mode, "xref") == 0) {
            st = raw_scan_vtables_xref();
        } else {
            fprintf(stderr, "unknown --only mode '%s'\n", only_mode);
            close_database(false);
            return 2;
        }
        printf("  TOTAL %s scan: %.2f s   (slots=%" PRIu64 " reads=%" PRIu64
               " lookups=%" PRIu64 " vtables=%" PRIu64 ")\n",
               only_mode, secs_since(t0), st.slots, st.reads, st.func_lookups,
               st.vtables);
        close_database(false);
        return 0;
    }

    // ── Decode micro-benchmark: walk every instruction of every function and
    // time idax decode vs raw SDK decode variants, to attribute the per-
    // instruction cost that every decode-requiring feature pays.
    if (profile_feature && std::strcmp(profile_feature, "decode") == 0) {
        std::vector<std::pair<ea_t, ea_t>> ranges;  // (start,end)
        size_t fq = get_func_qty();
        for (size_t i = 0; i < fq; i++) {
            func_t *f = getn_func(i);
            if (f) ranges.emplace_back(f->start_ea, f->end_ea);
        }
        if (profile_limit > 0 && (long)ranges.size() > profile_limit)
            ranges.resize(profile_limit);

        // Count instructions (raw decode_insn just to advance) — also warms.
        uint64_t ninsn = 0;
        for (auto &r : ranges) {
            ea_t a = r.first;
            while (a < r.second) {
                insn_t in;
                int sz = decode_insn(&in, a);
                if (sz <= 0) { a = next_head(a, r.second); if (a == BADADDR) break; continue; }
                ++ninsn;
                a += sz;
            }
        }
        printf("\n[decode-bench: %" PRIu64 " instructions over %zu funcs]\n",
               ninsn, ranges.size());

        // A: raw decode_insn only (no mnemonic, no operand strings).
        {
            auto t0 = clock_type::now();
            volatile uint64_t sink = 0;
            for (auto &r : ranges) {
                ea_t a = r.first;
                while (a < r.second) {
                    insn_t in;
                    int sz = decode_insn(&in, a);
                    if (sz <= 0) { a = next_head(a, r.second); if (a==BADADDR) break; continue; }
                    sink += in.itype;
                    a += sz;
                }
            }
            (void)sink;
            double dt = secs_since(t0);
            printf("  raw decode_insn only:        %.3f s  (%.0f ns/insn)\n",
                   dt, dt / ninsn * 1e9);
        }
        // B: raw decode_insn + print_insn_mnem (idax builds the mnemonic str).
        {
            auto t0 = clock_type::now();
            volatile uint64_t sink = 0;
            for (auto &r : ranges) {
                ea_t a = r.first;
                while (a < r.second) {
                    insn_t in;
                    int sz = decode_insn(&in, a);
                    if (sz <= 0) { a = next_head(a, r.second); if (a==BADADDR) break; continue; }
                    qstring m; print_insn_mnem(&m, a);
                    sink += m.length();
                    a += sz;
                }
            }
            (void)sink;
            double dt = secs_since(t0);
            printf("  raw + print_insn_mnem:       %.3f s  (%.0f ns/insn)\n",
                   dt, dt / ninsn * 1e9);
        }
        // D: raw decode_insn + get_canon_mnem (table lookup, no string build).
        {
            processor_t *ph = get_ph();
            auto t0 = clock_type::now();
            volatile uint64_t sink = 0;
            for (auto &r : ranges) {
                ea_t a = r.first;
                while (a < r.second) {
                    insn_t in;
                    int sz = decode_insn(&in, a);
                    if (sz <= 0) { a = next_head(a, r.second); if (a==BADADDR) break; continue; }
                    const char *m = in.get_canon_mnem(*ph);
                    sink += m ? (unsigned char)m[0] : 0;
                    a += sz;
                }
            }
            (void)sink;
            double dt = secs_since(t0);
            printf("  raw + get_canon_mnem:        %.3f s  (%.0f ns/insn)\n",
                   dt, dt / ninsn * 1e9);
        }
        // C: full idax ida::instruction::decode (mnemonic + per-operand reg names).
        {
            auto t0 = clock_type::now();
            volatile uint64_t sink = 0;
            for (auto &r : ranges) {
                ea_t a = r.first;
                while (a < r.second) {
                    ida::Result<ida::instruction::Instruction> d =
                        ida::instruction::decode(a);
                    if (!d) { a = next_head(a, r.second); if (a==BADADDR) break; continue; }
                    sink += d->size() + d->operands().size();
                    a += d->size();
                }
            }
            (void)sink;
            double dt = secs_since(t0);
            printf("  idax instruction::decode:    %.3f s  (%.0f ns/insn)\n",
                   dt, dt / ninsn * 1e9);
        }
        close_database(false);
        return 0;
    }

    // ── Per-feature profiling: sweep every function through collect_*_refs
    // with exactly one ref-type enabled. Seeds every function as a start node
    // and runs find_callees(depth=1) / find_callers(depth=1) so each function
    // body is walked exactly once via the real GraphBuilder code path.
    if (profile_feature) {
        // Collect all function start addresses.
        std::vector<ea_t> all_funcs;
        size_t fq = get_func_qty();
        all_funcs.reserve(fq);
        for (size_t i = 0; i < fq; i++) {
            func_t *f = getn_func(i);
            if (f) all_funcs.push_back(f->start_ea);
        }
        if (profile_limit > 0 && (long)all_funcs.size() > profile_limit)
            all_funcs.resize(profile_limit);

        // Build a DumpOptions with a single feature enabled.
        std::string feat = profile_feature;
        codedump::DumpOptions o;
        o.include_direct_calls = o.include_indirect_calls = o.include_data_refs =
            o.include_immediate_refs = o.include_tail_calls =
            o.include_virtual_calls = o.include_jump_tables = false;
        bool callers = false;
        if (feat == "direct") o.include_direct_calls = true;
        else if (feat == "indirect") o.include_indirect_calls = true;
        else if (feat == "data") o.include_data_refs = true;
        else if (feat == "immediate") o.include_immediate_refs = true;
        else if (feat == "tail") o.include_tail_calls = true;
        else if (feat == "virtual") o.include_virtual_calls = true;
        else if (feat == "jumptable") o.include_jump_tables = true;
        else if (feat == "all") {
            o.include_direct_calls = o.include_indirect_calls = o.include_data_refs =
                o.include_immediate_refs = o.include_tail_calls =
                o.include_virtual_calls = o.include_jump_tables = true;
        } else if (feat == "none") {
            /* baseline: pure decode+walk, no ref dispatch */
        } else if (feat == "callers") {
            callers = true; o.include_direct_calls = true; o.include_tail_calls = true;
        } else {
            fprintf(stderr, "unknown --profile-feature '%s'\n", profile_feature);
            close_database(false);
            return 2;
        }

        printf("\n[profile-feature %s over %zu functions]\n", profile_feature,
               all_funcs.size());
        codedump::GraphBuilder gb(o);
        for (ea_t ea : all_funcs) gb.add_start_function(ea);

        auto t0 = clock_type::now();
        if (callers) gb.find_callers(1);
        else gb.find_callees(1);   // virtual triggers vtable scan internally
        double dt = secs_since(t0);
        printf("  TOTAL %s: %.3f s   (%.0f funcs/s, %.1f us/func)  edges=%zu disc=%zu\n",
               profile_feature, dt, all_funcs.size() / dt,
               dt / all_funcs.size() * 1e6, gb.get_edges().size(),
               gb.get_functions().size());
        close_database(false);
        return 0;
    }

    // ── Phase: vtable scan via the real GraphBuilder ────────────────────
    {
        codedump::GraphBuilder gb(opts);
        gb.add_start_function(start_ea);

        auto seg_t0 = clock_type::now();
        const char *last_seg = "";
        auto cb = [&](const codedump::GraphProgress &p) -> bool {
            if (std::strcmp(p.phase, "vtables") == 0 &&
                std::strcmp(p.current_name, last_seg) != 0) {
                if (last_seg[0])
                    printf("    seg done in %.2f s\n", secs_since(seg_t0));
                printf("  vtables: segment %zu/%zu (%s)  tables=%zu\n",
                       p.segment_index + 1, p.segment_total, p.current_name,
                       p.vtables_found);
                last_seg = p.current_name;
                seg_t0 = clock_type::now();
            }
            return true;
        };

        printf("\n[idax GraphBuilder::scan_vtables]\n");
        auto t0 = clock_type::now();
        gb.scan_vtables(cb);
        double idax_scan = secs_since(t0);
        printf("  TOTAL idax scan_vtables: %.2f s\n", idax_scan);

        if (run_raw) {
            printf("\n[raw SDK scan (start_ea only, no name/populate)]\n");
            t0 = clock_type::now();
            RawStats st = raw_scan_vtables();
            double raw_scan = secs_since(t0);
            printf("  slots=%" PRIu64 " reads=%" PRIu64 " get_func=%" PRIu64
                   " vtables=%" PRIu64 "\n",
                   st.slots, st.reads, st.func_lookups, st.vtables);
            printf("  TOTAL raw scan: %.2f s\n", raw_scan);
            printf("\n  >>> idax/raw ratio: %.1fx   (idax overhead per scan: %.2f s)\n",
                   raw_scan > 0 ? idax_scan / raw_scan : 0.0, idax_scan - raw_scan);

            printf("\n[bulk SDK scan (get_bytes per segment, in-RAM pointer scan)]\n");
            t0 = clock_type::now();
            RawStats bst = raw_scan_vtables_bulk();
            double bulk_scan = secs_since(t0);
            printf("  slots=%" PRIu64 " bulk_reads=%" PRIu64 " get_func=%" PRIu64
                   " vtables=%" PRIu64 "\n",
                   bst.slots, bst.reads, bst.func_lookups, bst.vtables);
            printf("  TOTAL bulk scan: %.2f s\n", bulk_scan);
            printf("  >>> speedup vs per-slot raw: %.1fx   vtables match: %s\n",
                   bulk_scan > 0 ? raw_scan / bulk_scan : 0.0,
                   bst.vtables == st.vtables ? "YES" : "NO (!!)");

            printf("\n[fnset SDK scan (sorted func-start array + binary_search)]\n");
            t0 = clock_type::now();
            RawStats fst = raw_scan_vtables_fnset();
            double fnset_scan = secs_since(t0);
            printf("  slots=%" PRIu64 " reads=%" PRIu64 " membership=%" PRIu64
                   " vtables=%" PRIu64 "\n",
                   fst.slots, fst.reads, fst.func_lookups, fst.vtables);
            printf("  TOTAL fnset scan: %.2f s\n", fnset_scan);
            printf("  >>> speedup vs idax scan: %.1fx   vtables match: %s\n",
                   fnset_scan > 0 ? idax_scan / fnset_scan : 0.0,
                   fst.vtables == st.vtables ? "YES" : "NO (!!)");

            // Build a probe set from the first data segment for micro-bench.
            std::vector<ea_t> probe;
            for (int i = 0; i < nseg && probe.size() < 200000; i++) {
                segment_t *seg = getnseg(i);
                if (!seg || (seg->perm & SEGPERM_EXEC)) continue;
                for (ea_t a = seg->start_ea;
                     a < seg->end_ea && probe.size() < 200000; a += 8)
                    probe.push_back(a);
            }
            printf("\n[micro-bench over %zu probe addresses]\n", probe.size());
            micro_bench(probe);
        }
    }

    // ── Phase: full callee crawl ────────────────────────────────────────
    if (run_crawl) {
        codedump::GraphBuilder gb(opts);
        gb.add_start_function(start_ea);

        printf("\n[find_callers depth=%d]\n", caller_depth);
        auto t0 = clock_type::now();
        gb.find_callers(caller_depth);
        printf("  callers: %.2f s  (funcs=%zu edges=%zu)\n",
               secs_since(t0), gb.get_functions().size(), gb.get_edges().size());

        printf("\n[find_callees depth=%d]\n", callee_depth);
        t0 = clock_type::now();
        gb.find_callees(callee_depth);
        printf("  callees: %.2f s  (funcs=%zu edges=%zu)\n",
               secs_since(t0), gb.get_functions().size(), gb.get_edges().size());
    }

    close_database(false);
    return 0;
}
