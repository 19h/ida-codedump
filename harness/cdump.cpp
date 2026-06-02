// cdump - headless idalib CLI for codedump-style function+type dumps.
//
// Usage is extremely intuitive:
//   cdump mybin.i64
//   cdump -f 0x140001000,main,sub_foo -o out.c mybin.i64
//   cdump -f main --callee-depth 3 --ptn --regs --offsets --trim-types mybin
//
// -f/--functions: comma/pipe-separated names or 0xaddrs (optional; omit for ALL functions)
// -o/--out: output path (defaults to <input>.c next to input or idb)
// PTN off by default (UI has it on); --ptn to enable.
// Supports every DumpOptions toggle from the UI via obvious flags.
//
// When -f is omitted we simply walk every function (no graph resolution) so the
// emitted types are exactly those referenced by the dumped functions (no unused types).
//
// Build with: cmake -B build -DCODEDUMP_BUILD_CLI=ON && cmake --build build --target cdump

#include <ida/database.hpp>
#include <ida/decompiler.hpp>
#include <ida/function.hpp>
#include <ida/name.hpp>
#include <ida/instruction.hpp>
#include <ida/address.hpp>
#include <ida/analysis.hpp>

#include "common/types.h"
#include "graph/graph_builder.h"
#include "analysis/ctree_analyzer.h"
#include "analysis/ptn_emitter.h"
#include "analysis/register_analyzer.h"
#include "analysis/type_collector.h"
#include "output/code_writer.h"
#include "output/dot_writer.h"
#include "output/asm_writer.h"
#include "output/ptn_writer.h"

#include <algorithm>
#include <cctype>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace {

struct Cli {
    std::string input;
    std::string output;
    bool output_default = true;
    std::vector<std::string> func_specs;
    int caller_depth = 0;
    int callee_depth = 0;
    int max_chars = 0;
    bool quiet = false;
    bool verbose = false;

    // format
    std::string format = "code"; // code, asm, dot, ptn

    // toggles (mirror DumpOptions, PTN off by default for CLI)
    bool omit_ptn = true;
    bool size_comments = false;
    bool register_summary = false;
    bool referenced_fields_only = false;

    bool include_direct_calls = true;
    bool include_indirect_calls = true;
    bool include_data_refs = true;
    bool include_immediate_refs = true;
    bool include_tail_calls = true;
    bool include_virtual_calls = true;
    bool include_jump_tables = true;
};

static void print_usage(const char* prog) {
    std::cout <<
R"(cdump - idalib Code Dumper (headless)

Usage:
  )" << prog << R"( [options] <input.idb|binary>

Options:
  -f, --functions <spec>   Functions to start from (names or 0xADDR). Comma/pipe or
                           repeat -f. If omitted: dump *all* functions.
  -o, --out <file>         Output file (default: <input>.c next to input/idb).
                           Use "-" for stdout.
  --format <code|asm|dot|ptn>
                           Output kind (default: code). code/asm include types.
  --caller-depth <n>       Callers to walk (default 0).
  --callee-depth <n>       Callees/refs to walk (default 0). With -f this pulls a
                           neighbourhood; without -f it is ignored (we take all).
  --max-chars <n>          Truncate output by dropping smallest non-roots (0=unlimited).

  --ptn                    Enable PTN provenance (default: off for CLI).
  --no-ptn                 Force omit PTN (default).

  --offsets, --size-comments
                           Annotate struct members with // off=N size=M and sizeof.
  --no-offsets             Disable size comments.

  --regs, --register-summary, --register-in-out
                           Add // incoming: ...  // outgoing: ... per function.
  --no-regs                Disable register summary.

  --trim, --trim-types, --referenced-only
                           Trim structs/unions to only referenced fields (pad rest).
  --no-trim                Include full types (default).

  --no-direct-calls, --no-indirect-calls, --no-data-refs,
  --no-immediate-refs, --no-tail-calls, --no-virtual-calls, --no-jump-tables
                           Disable specific xref kinds during graph walk (when depths>0).

  -q, --quiet              Suppress progress output.
  -v, --verbose            Extra progress detail.
  -h, --help               This help.

Examples:
  )" << prog << R"( mybin.i64
  )" << prog << R"( -f 0x140001000,main -o out.c mybin.i64
  )" << prog << R"( -f sub_foo --callee-depth 2 --ptn --regs --offsets --trim-types mybin
  )" << prog << R"( --format dot -o callgraph.dot mybin.i64
  )" << prog << R"( -f main --callee-depth 5 -o big.c --no-ptn mybin

The tool never pulls "all types" from the Local Types window; types come only from
decompiling the walked functions (exactly the used ones).
)";
}

static std::vector<std::string> split_specs(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == ',' || c == '|') {
            auto b = cur.find_first_not_of(" \t\r\n");
            auto e = cur.find_last_not_of(" \t\r\n");
            if (b != std::string::npos) out.push_back(cur.substr(b, e - b + 1));
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    auto b = cur.find_first_not_of(" \t\r\n");
    auto e = cur.find_last_not_of(" \t\r\n");
    if (b != std::string::npos) out.push_back(cur.substr(b, e - b + 1));
    return out;
}

static bool parse_int(const char* s, int& out) {
    char* end = nullptr;
    long v = std::strtol(s, &end, 10);
    if (end == s || *end != '\0' || v < 0) return false;
    out = static_cast<int>(v);
    return true;
}

static bool parse_cli(int argc, char** argv, Cli& cli) {
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](const char* def = nullptr) -> const char* {
            return (i + 1 < argc) ? argv[++i] : def;
        };

        if (a == "-h" || a == "--help") {
            print_usage(argv[0]);
            std::exit(0);
        } else if (a == "-f" || a == "--functions") {
            const char* v = next();
            if (!v) { std::cerr << "Error: " << a << " requires value\n"; return false; }
            auto more = split_specs(v);
            cli.func_specs.insert(cli.func_specs.end(), more.begin(), more.end());
        } else if (a == "-o" || a == "--out" || a == "--output") {
            const char* v = next();
            if (!v) { std::cerr << "Error: " << a << " requires file\n"; return false; }
            cli.output = v;
            cli.output_default = false;
        } else if (a == "--format") {
            const char* v = next("code");
            cli.format = v ? v : "code";
        } else if (a == "--caller-depth") {
            const char* v = next();
            if (!v || !parse_int(v, cli.caller_depth)) { std::cerr << "Error: --caller-depth needs int\n"; return false; }
        } else if (a == "--callee-depth") {
            const char* v = next();
            if (!v || !parse_int(v, cli.callee_depth)) { std::cerr << "Error: --callee-depth needs int\n"; return false; }
        } else if (a == "--max-chars") {
            const char* v = next();
            int m = 0;
            if (!v || !parse_int(v, m)) { std::cerr << "Error: --max-chars needs int\n"; return false; }
            cli.max_chars = m;
        } else if (a == "--ptn") {
            cli.omit_ptn = false;
        } else if (a == "--no-ptn") {
            cli.omit_ptn = true;
        } else if (a == "--offsets" || a == "--size-comments") {
            cli.size_comments = true;
        } else if (a == "--no-offsets" || a == "--no-size-comments") {
            cli.size_comments = false;
        } else if (a == "--regs" || a == "--register-summary" || a == "--register-in-out") {
            cli.register_summary = true;
        } else if (a == "--no-regs" || a == "--no-register-summary") {
            cli.register_summary = false;
        } else if (a == "--trim" || a == "--trim-types" || a == "--referenced-only" || a == "--referenced-fields-only") {
            cli.referenced_fields_only = true;
        } else if (a == "--no-trim" || a == "--no-referenced-only") {
            cli.referenced_fields_only = false;
        } else if (a == "--no-direct-calls") {
            cli.include_direct_calls = false;
        } else if (a == "--direct-calls") {
            cli.include_direct_calls = true;
        } else if (a == "--no-indirect-calls") {
            cli.include_indirect_calls = false;
        } else if (a == "--indirect-calls") {
            cli.include_indirect_calls = true;
        } else if (a == "--no-data-refs") {
            cli.include_data_refs = false;
        } else if (a == "--data-refs") {
            cli.include_data_refs = true;
        } else if (a == "--no-immediate-refs") {
            cli.include_immediate_refs = false;
        } else if (a == "--immediate-refs") {
            cli.include_immediate_refs = true;
        } else if (a == "--no-tail-calls") {
            cli.include_tail_calls = false;
        } else if (a == "--tail-calls") {
            cli.include_tail_calls = true;
        } else if (a == "--no-virtual-calls") {
            cli.include_virtual_calls = false;
        } else if (a == "--virtual-calls") {
            cli.include_virtual_calls = true;
        } else if (a == "--no-jump-tables") {
            cli.include_jump_tables = false;
        } else if (a == "--jump-tables") {
            cli.include_jump_tables = true;
        } else if (a == "-q" || a == "--quiet") {
            cli.quiet = true;
        } else if (a == "-v" || a == "--verbose") {
            cli.verbose = true;
        } else if (a[0] == '-') {
            std::cerr << "Error: unknown option " << a << "\n";
            return false;
        } else {
            if (cli.input.empty()) {
                cli.input = a;
            } else {
                std::cerr << "Error: multiple inputs\n";
                return false;
            }
        }
    }
    if (cli.input.empty()) {
        std::cerr << "Error: missing input file\n";
        print_usage(argv[0]);
        return false;
    }
    if (cli.format != "code" && cli.format != "asm" && cli.format != "dot" && cli.format != "ptn") {
        std::cerr << "Error: --format must be code|asm|dot|ptn\n";
        return false;
    }
    return true;
}

static ida::Address resolve_spec(const std::string& spec) {
    if (spec.empty()) return ida::BadAddress;
    std::string s = spec;
    // hex?
    bool hex = false;
    if (s.size() > 2 && (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0)) {
        s = s.substr(2);
        hex = true;
    }
    if (hex || std::all_of(s.begin(), s.end(), [](unsigned char c){ return std::isxdigit(c); })) {
        char* end = nullptr;
        unsigned long long v = std::strtoull(s.c_str(), &end, 16);
        if (end && *end == '\0') return static_cast<ida::Address>(v);
    }
    // name
    auto r = ida::name::resolve(spec);
    if (r && *r != ida::BadAddress) return *r;
    return ida::BadAddress;
}

static void progress(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fflush(stderr);
}

} // namespace

int main(int argc, char** argv) {
    Cli cli;
    if (!parse_cli(argc, argv, cli)) {
        return 2;
    }

    // init idalib / idax
    auto init_res = ida::database::init();
    if (!init_res) {
        std::cerr << "init failed: " << init_res.error().message << "\n";
        return 1;
    }

    if (!cli.quiet) progress("[cdump] opening %s\n", cli.input.c_str());
    auto open_res = ida::database::open(cli.input, true);
    if (!open_res) {
        std::cerr << "open failed: " << open_res.error().message << "\n";
        return 1;
    }
    (void)ida::analysis::wait();

    // decompiler (required for ctree + pseudocode)
    auto decomp = ida::decompiler::initialize();
    if (!decomp) {
        std::cerr << "Hex-Rays decompiler not available (required for dumps)\n";
        (void)ida::database::close(false);
        return 1;
    }

    // resolve -f specs now that DB is open
    std::vector<ida::Address> requested;
    for (const auto& spec : cli.func_specs) {
        auto ea = resolve_spec(spec);
        if (ea == ida::BadAddress) {
            if (cli.verbose) progress("[cdump] warning: could not resolve '%s'\n", spec.c_str());
            continue;
        }
        auto f = ida::function::at(ea);
        if (f) {
            requested.push_back(f->start());
        } else if (cli.verbose) {
            progress("[cdump] warning: %s is not a function\n", spec.c_str());
        }
    }

    bool dumping_all = requested.empty();
    if (!cli.quiet) {
        if (dumping_all) {
            auto n = ida::function::count().value_or(0);
            progress("[cdump] dumping ALL functions (%zu)\n", (size_t)n);
        } else {
            progress("[cdump] dumping from %zu seed(s), caller=%d callee=%d\n",
                     requested.size(), cli.caller_depth, cli.callee_depth);
        }
    }

    // build opts
    codedump::DumpOptions opts;
    opts.caller_depth = cli.caller_depth;
    opts.callee_depth = cli.callee_depth;
    opts.max_chars = cli.max_chars;
    opts.omit_ptn = cli.omit_ptn;
    opts.size_comments = cli.size_comments;
    opts.register_summary = cli.register_summary;
    opts.referenced_fields_only = cli.referenced_fields_only;
    opts.include_direct_calls = cli.include_direct_calls;
    opts.include_indirect_calls = cli.include_indirect_calls;
    opts.include_data_refs = cli.include_data_refs;
    opts.include_immediate_refs = cli.include_immediate_refs;
    opts.include_tail_calls = cli.include_tail_calls;
    opts.include_virtual_calls = cli.include_virtual_calls;
    opts.include_jump_tables = cli.include_jump_tables;
    opts.output_code = (cli.format == "code");
    opts.output_asm = (cli.format == "asm");
    opts.output_dot = (cli.format == "dot");
    opts.output_ptn = (cli.format == "ptn");

    // compute final output path
    std::string out_path;
    if (cli.output == "-") {
        out_path = "-";
    } else if (!cli.output_default) {
        out_path = cli.output;
    } else {
        // Always place output next to what the user actually passed on the command line.
        // This is intuitive and avoids writing to stale metadata paths recorded inside IDBs.
        std::filesystem::path base(cli.input);
        auto dir = base.parent_path();
        if (dir.empty()) dir = ".";
        std::string stem = base.stem().string();
        if (stem.empty()) stem = "dump";
        out_path = (dir / (stem + ".c")).string();
    }
    if (cli.format == "dot" && cli.output_default) {
        // adjust extension if default
        if (out_path.size() > 2 && out_path.substr(out_path.size()-2) == ".c")
            out_path = out_path.substr(0, out_path.size()-2) + ".dot";
    } else if (cli.format == "ptn" && cli.output_default) {
        if (out_path.size() > 2 && out_path.substr(out_path.size()-2) == ".c")
            out_path = out_path.substr(0, out_path.size()-2) + ".ptn";
    } else if (cli.format == "asm" && cli.output_default) {
        if (out_path.size() > 2 && out_path.substr(out_path.size()-2) == ".c")
            out_path = out_path.substr(0, out_path.size()-2) + ".asm";
    }

    // discover functions + edges
    std::set<ida::Address> func_set;
    std::vector<codedump::Edge> edges;
    auto graph_progress = [&](const codedump::GraphProgress& p) -> bool {
        if (cli.quiet) return true;
        if (cli.verbose || (p.depth % 1 == 0 && p.layer_index == 0)) {
            progress("[cdump] graph %s d=%d/%d  layer %zu/%zu  discovered=%zu edges=%zu  %s\n",
                     p.phase, p.depth, p.max_depth, p.layer_index, p.layer_total,
                     p.discovered, p.edges, p.current_name);
        }
        return true;
    };

    if (!requested.empty() && (cli.caller_depth > 0 || cli.callee_depth > 0)) {
        codedump::GraphBuilder gb(opts);
        for (auto ea : requested) gb.add_start_function(ea);
        if (cli.caller_depth > 0) {
            if (!cli.quiet) progress("[cdump] pass graph: callers (depth %d)\n", cli.caller_depth);
            gb.find_callers(cli.caller_depth, graph_progress);
        }
        if (cli.callee_depth > 0) {
            if (!cli.quiet) progress("[cdump] pass graph: callees (depth %d)\n", cli.callee_depth);
            gb.find_callees(cli.callee_depth, graph_progress);
        }
        func_set = gb.get_functions();
        edges = gb.get_edges();
    } else if (!requested.empty()) {
        for (auto ea : requested) func_set.insert(ea);
    } else {
        // all functions, no resolution walk (per request)
        auto n = ida::function::count().value_or(0);
        for (size_t i = 0; i < n; ++i) {
            if (auto f = ida::function::by_index(i); f) {
                func_set.insert(f->start());
            }
        }
    }

    if (!cli.quiet) progress("[cdump] %zu functions\n", func_set.size());

    // provenance (ctree) for anything needing summaries
    bool needs_prov = (cli.format == "code" || cli.format == "asm" || cli.format == "ptn");
    std::map<ida::Address, codedump::FunctionSummary> summaries;
    if (needs_prov) {
        codedump::CtreeAnalyzer analyzer;
        size_t i = 0, tot = func_set.size();
        for (auto ea : func_set) {
            ++i;
            if (!cli.quiet && (cli.verbose || (i % 50 == 0) || i == tot)) {
                progress("[cdump] analyze %zu/%zu\n", i, tot);
            }
            codedump::FunctionSummary s;
            if (analyzer.analyze_function(ea, s)) {
                if (opts.register_summary) {
                    auto rs = codedump::analyze_function_registers(ea);
                    s.incoming_regs = std::move(rs.incoming);
                    s.outgoing_regs = std::move(rs.outgoing);
                }
                summaries[ea] = std::move(s);
            }
        }
    }

    // second decompile pass for pseudocode text + type collection + asm
    bool needs_text = (cli.format == "code" || cli.format == "asm");
    bool needs_types = needs_text;
    codedump::TypeCollector type_collector;
    if (needs_prov) {
        size_t i = 0, tot = summaries.size();
        for (auto& [ea, s] : summaries) {
            ++i;
            if (!cli.quiet && (cli.verbose || (i % 20 == 0) || i == tot)) {
                progress("[cdump] decompile %zu/%zu  %s\n", i, tot, s.func_name.c_str());
            }
            auto d = ida::decompiler::decompile(ea);
            if (d) {
                if (auto c = d->pseudocode(); c) s.decompiled_code = *c;
                if (needs_types) type_collector.collect_from_function(ea);
            }
            if (cli.format == "asm") {
                auto fn = ida::function::at(ea);
                if (fn) {
                    std::string as;
                    for (ida::Address addr = fn->start(); addr < fn->end(); ) {
                        auto line = ida::instruction::text(addr);
                        as += std::format("0x{:x}: {}\n", (unsigned long long)addr,
                                          line ? *line : "");
                        auto nxt = ida::address::next_head(addr, fn->end());
                        if (!nxt) break;
                        addr = *nxt;
                    }
                    s.disassembly = std::move(as);
                }
            }
        }
    }

    // PTN annotations (only if needed and not omitted)
    codedump::PTNEmitter ptn_emitter(summaries);
    std::map<ida::Address, std::string> annotations;
    if (!opts.omit_ptn && (cli.format == "code" || cli.format == "asm")) {
        if (!cli.quiet) progress("[cdump] building PTN annotations\n");
        annotations = ptn_emitter.per_function_annotations(std::max(1, cli.callee_depth));
    }

    std::string type_decls;
    if (needs_types) {
        if (!cli.quiet) progress("[cdump] resolving types\n");
        type_decls = type_collector.emit(opts.size_comments, opts.referenced_fields_only);
    }

    // start set for headers (empty => "all" handled in writers)
    std::set<ida::Address> start_set;
    for (auto e : requested) start_set.insert(e);

    int h_call = dumping_all ? 0 : cli.caller_depth;
    int h_callee = dumping_all ? 0 : cli.callee_depth;

    std::string rendered;
    if (cli.format == "code") {
        codedump::CodeWriter cw;
        rendered = cw.render(summaries, annotations, edges, start_set,
                             h_call, h_callee, cli.max_chars, type_decls, opts.omit_ptn);
    } else if (cli.format == "dot") {
        codedump::DotWriter dw;
        rendered = dw.render(func_set, edges, start_set);
    } else if (cli.format == "ptn") {
        codedump::PTNWriter pw;
        rendered = pw.render(summaries, start_set, h_callee, ptn_emitter);
    } else if (cli.format == "asm") {
        codedump::AsmWriter aw;
        rendered = aw.render(summaries, annotations, ptn_emitter,
                             h_callee, type_decls, opts.omit_ptn);
    }

    if (rendered.empty()) {
        std::cerr << "Nothing rendered.\n";
        (void)ida::database::close(false);
        return 1;
    }

    if (out_path == "-") {
        std::cout << rendered;
        if (!cli.quiet) progress("[cdump] wrote %zu bytes to stdout\n", rendered.size());
    } else {
        std::ofstream f(out_path, std::ios::binary);
        if (!f) {
            std::cerr << "Failed to open output: " << out_path << "\n";
            (void)ida::database::close(false);
            return 1;
        }
        f << rendered;
        if (!cli.quiet) progress("[cdump] wrote %zu bytes -> %s\n", rendered.size(), out_path.c_str());
    }

    // clean
    decomp->close();
    (void)ida::database::close(false);
    return 0;
}
