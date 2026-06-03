// CodeDumper plugin entrypoint.
//
// Hybrid design: plugin scaffolding, user interaction, analysis, and export
// flows are built on idax (C++23), with raw SDK types confined to the IDA
// plugin ABI boundary.

#include <ida/address.hpp>
#include <ida/database.hpp>
#include <ida/decompiler.hpp>
#include <ida/function.hpp>
#include <ida/instruction.hpp>
#include <ida/plugin.hpp>
#include <ida/path.hpp>
#include <ida/ui.hpp>
#include <ida/error.hpp>
#include <ida/type.hpp>

#include "common/types.h"
#include "graph/graph_builder.h"
#include "analysis/ctree_analyzer.h"
#include "analysis/ptn_emitter.h"
#include "analysis/register_analyzer.h"
#include "analysis/type_collector.h"
#include "transfer/metadata.h"
#include "transfer/metadata_export.h"
#include "transfer/metadata_apply.h"
#include "output/code_writer.h"
#include "output/dot_writer.h"
#include "output/asm_writer.h"
#include "output/ptn_writer.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <format>
#include <fstream>
#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace codedump {

namespace {

bool phase_is(const char *phase, const char *expected) {
    return phase != nullptr && std::strcmp(phase, expected) == 0;
}

} // namespace

// ── Action IDs ──────────────────────────────────────────────────────────
constexpr const char ACTION_DUMP_CODE[]            = "codedump:dump_code";
constexpr const char ACTION_DUMP_DOT[]             = "codedump:dump_dot";
constexpr const char ACTION_DUMP_PTN[]             = "codedump:dump_ptn";
constexpr const char ACTION_DUMP_ASM[]             = "codedump:dump_asm";
constexpr const char ACTION_DUMP_TYPE[]            = "codedump:dump_type";
constexpr const char ACTION_DUMP_TYPE_RECURSIVE[]  = "codedump:dump_type_recursive";
constexpr const char ACTION_COPY_TYPE[]            = "codedump:copy_type";
constexpr const char ACTION_COPY_TYPE_RECURSIVE[]  = "codedump:copy_type_recursive";
constexpr const char ACTION_TYPE_GRAPH_DUMP[]      = "codedump:type_graph_dump";
constexpr const char ACTION_TYPE_GRAPH_COPY[]      = "codedump:type_graph_copy";
constexpr const char ACTION_EXPORT_META[]          = "codedump:export_metadata";
constexpr const char ACTION_APPLY_META[]           = "codedump:apply_metadata";

constexpr const char POPUP_PATH[]      = "Dump code/";
constexpr const char TYPE_POPUP_PATH[] = "Dump type/";

template <typename... Args>
inline void log(std::format_string<Args...> fmt, Args&&... args) {
    ida::ui::message(std::format(fmt, std::forward<Args>(args)...));
}

static ida::ui::WaitBox *g_active_wait_box = nullptr;

template <typename... Args>
static std::string cformat(const char *fmt, Args... args) {
    if (!fmt) return {};
    std::array<char, 4096> small{};
    int needed = std::snprintf(small.data(), small.size(), fmt, args...);
    if (needed < 0) return std::string{fmt};
    if (static_cast<std::size_t>(needed) < small.size())
        return std::string(small.data(), static_cast<std::size_t>(needed));

    std::vector<char> buffer(static_cast<std::size_t>(needed) + 1);
    needed = std::snprintf(buffer.data(), buffer.size(), fmt, args...);
    if (needed < 0) return std::string{fmt};
    return std::string(buffer.data(), static_cast<std::size_t>(needed));
}

template <typename... Args>
static void warn_user(const char *fmt, Args... args) {
    ida::ui::warning(cformat(fmt, args...));
}

template <typename... Args>
static void info_user(const char *fmt, Args... args) {
    ida::ui::info(cformat(fmt, args...));
}

template <typename... Args>
static void replace_wait_box(const char *fmt, Args... args) {
    if (!g_active_wait_box) return;
    ida::Status status = g_active_wait_box->update(cformat(fmt, args...));
    if (!status)
        log("[codedump] Wait box update failed: {}\n", status.error().message);
}

static bool user_cancelled() {
    return g_active_wait_box && g_active_wait_box->cancelled();
}

template <typename... Bindings>
static bool ask_form_or_warn(std::string_view markup, Bindings&&... bindings) {
    ida::Result<bool> accepted =
        ida::ui::ask_form(markup, std::forward<Bindings>(bindings)...);
    if (!accepted) {
        ida::ui::warning(std::format("CodeDumper: failed to show form: {}",
                                     accepted.error().message));
        return false;
    }
    return *accepted;
}

static void show_copy_fallback(std::string_view title,
                               const std::string &payload) {
    ida::Result<std::string> ignored =
        ida::ui::ask_text(title, payload, 0, true, true);
    if (!ignored)
        log("[codedump] Manual copy dialog closed: {}\n",
            ignored.error().message);
}

// RAII guard so the idax wait box is always closed on early returns /
// exceptions while preserving the plugin's existing printf-style updates.
struct WaitBoxGuard {
    ida::ui::WaitBox box;
    ida::ui::WaitBox *previous{nullptr};

    explicit WaitBoxGuard(const char *initial) : box(initial) {
        previous = g_active_wait_box;
        g_active_wait_box = &box;
    }
    ~WaitBoxGuard() {
        if (g_active_wait_box == &box)
            g_active_wait_box = previous;
    }
    WaitBoxGuard(const WaitBoxGuard&) = delete;
    WaitBoxGuard& operator=(const WaitBoxGuard&) = delete;

    void dismiss() {
        if (g_active_wait_box == &box)
            g_active_wait_box = previous;
        box.dismiss();
    }
};

// ── Core dump pipeline ──────────────────────────────────────────────────

static void dump_functions_impl(std::span<const ida::Address> start_funcs,
                                const DumpOptions &opts) {
    log("[codedump] Starting dump for {} function(s)\n", start_funcs.size());

    WaitBoxGuard wait("NODELAY\nHIDECANCEL\nCodeDumper: preparing...");

    GraphBuilder gb(opts);
    for (ida::Address ea : start_funcs) gb.add_start_function(ea);

    auto graph_progress = [&](const GraphProgress &p) -> bool {
        if (user_cancelled()) return false;

        if (phase_is(p.phase, "callers") || phase_is(p.phase, "callees")) {
            const char *step = (phase_is(p.phase, "callers")) ? "1/5" : "2/5";
            const char *what = (phase_is(p.phase, "callers"))
                ? "finding callers" : "finding callees";
            int max_d = p.max_depth > 0 ? p.max_depth : 1;
            int layer_pct = p.layer_total
                ? static_cast<int>((p.layer_index * 100) / p.layer_total)
                : 100;
            replace_wait_box(
                "CodeDumper: pass %s — %s\n"
                "Depth %d/%d   Layer %zu/%zu (%d%%)\n"
                "Discovered: %zu funcs   Edges: %zu\n"
                "Current: %s",
                step, what,
                p.depth + 1, max_d, p.layer_index + 1, p.layer_total, layer_pct,
                p.discovered, p.edges,
                p.current_name);
        } else if (phase_is(p.phase, "vtables")) {
            replace_wait_box(
                "CodeDumper: scanning vtables\n"
                "Segment %zu/%zu (%s)\n"
                "Tables found so far: %zu",
                p.segment_index + 1, p.segment_total,
                p.current_name, p.vtables_found);
        }
        return true;
    };

    replace_wait_box("CodeDumper: pass 1/5 — finding callers (depth %d)",
                     opts.caller_depth);
    log("[codedump] Pass 1: Finding callers...\n");
    if (!gb.find_callers(opts.caller_depth, graph_progress)) {
        log("[codedump] Cancelled during callers.\n");
        return;
    }

    replace_wait_box("CodeDumper: pass 2/5 — finding callees (depth %d)",
                     opts.callee_depth);
    log("[codedump] Pass 2: Finding callees...\n");
    if (!gb.find_callees(opts.callee_depth, graph_progress)) {
        log("[codedump] Cancelled during callees.\n");
        return;
    }

    const auto &functions = gb.get_functions();
    const auto &edges = gb.get_edges();
    log("[codedump] Found {} functions, {} edges\n", functions.size(), edges.size());

    log("[codedump] Pass 3: Analyzing function bodies...\n");
    CtreeAnalyzer analyzer;
    std::map<ida::Address, FunctionSummary> summaries;
    size_t total = functions.size();
    size_t i = 0;
    for (ida::Address ea : functions) {
        ida::Result<std::string> fname = ida::function::name_at(ea);
        std::string display_name = (fname && !fname->empty()) ? *fname : "?";
        int pct = total ? static_cast<int>((i * 100) / total) : 100;
        replace_wait_box(
            "CodeDumper: pass 3/5 — analyzing ctrees%s\n"
            "%d%% (%zu / %zu)\n"
            "Current: %s",
            opts.register_summary ? " + registers" : "",
            pct, i, total, display_name.c_str());
        if (user_cancelled()) { log("[codedump] Cancelled.\n"); return; }
        ++i;

        FunctionSummary summary;
        if (analyzer.analyze_function(ea, summary)) {
            if (opts.register_summary) {
                RegisterSummary rs = analyze_function_registers(ea);
                summary.incoming_regs = std::move(rs.incoming);
                summary.outgoing_regs = std::move(rs.outgoing);
            }
            summaries[ea] = std::move(summary);
        }
    }

    log("[codedump] Pass 4: Decompiling functions...\n");
    TypeCollector type_collector;
    total = summaries.size();
    i = 0;
    size_t decompile_ok = 0, decompile_fail = 0;
    for (auto &[ea, summary] : summaries) {
        int pct = total ? static_cast<int>((i * 100) / total) : 100;
        replace_wait_box(
            "CodeDumper: pass 4/5 — decompiling\n"
            "%d%% (%zu / %zu)  ok=%zu  fail=%zu\n"
            "Current: %s",
            pct, i, total, decompile_ok, decompile_fail,
            summary.func_name.empty() ? "?" : summary.func_name.c_str());
        if (user_cancelled()) { log("[codedump] Cancelled.\n"); return; }
        ++i;

        ida::Result<ida::function::Function> function = ida::function::at(ea);
        if (!function) continue;

        ida::Result<ida::decompiler::DecompiledFunction> decompiled =
            ida::decompiler::decompile(ea);
        if (decompiled) {
            ++decompile_ok;
            ida::Result<std::string> code = decompiled->pseudocode();
            if (code) summary.decompiled_code = *code;

            type_collector.collect_from_function(ea);
        } else {
            ++decompile_fail;
        }

        if (opts.output_asm) {
            std::string asm_text;
            ida::Address end = static_cast<ida::Address>(function->end());
            for (ida::Address addr = static_cast<ida::Address>(function->start()); addr < end; ) {
                ida::Result<std::string> line = ida::instruction::text(addr);
                asm_text += std::format("{:x}: {}\n",
                                        static_cast<unsigned long long>(addr),
                                        line ? *line : "");
                ida::Result<ida::Address> next = ida::address::next_head(addr, end);
                if (!next) break;
                addr = *next;
            }
            summary.disassembly = std::move(asm_text);
        }
    }

    replace_wait_box(
        "CodeDumper: pass 5/5 — generating output\n"
        "Step 1/3: building PTN annotations (%s)",
        opts.omit_ptn ? "skipped" : "active");
    log("[codedump] Pass 5: Generating output...\n");
    PTNEmitter ptn_emitter(summaries);
    std::map<ida::Address, std::string> annotations;
    if (!opts.omit_ptn)
        annotations = ptn_emitter.per_function_annotations(std::max(1, opts.callee_depth));
    if (user_cancelled()) { log("[codedump] Cancelled.\n"); return; }

    replace_wait_box(
        "CodeDumper: pass 5/5 — generating output\n"
        "Step 2/3: resolving type tree (%s size-comments)",
        opts.size_comments ? "with" : "without");
    std::string type_decls = type_collector.emit(opts.size_comments,
                                                  opts.referenced_fields_only);
    log("[codedump] Type tree: {} chars\n", type_decls.size());
    if (user_cancelled()) { log("[codedump] Cancelled.\n"); return; }

    std::string base_path = opts.output_path;
    std::set<ida::Address> start_set(start_funcs.begin(), start_funcs.end());
    std::string bn = ida::path::basename(base_path);

    std::string rendered;
    const char *kind = "";
    size_t kind_count = 0;

    if (opts.output_code) {
        replace_wait_box(
            "CodeDumper: pass 5/5 — generating output\n"
            "Step 3/3: rendering code (%zu functions, %zu types)",
            summaries.size(), type_decls.size() ? size_t(1) : size_t(0));
        CodeWriter cw;
        rendered = cw.render(summaries, annotations, edges, start_set,
                             opts.caller_depth, opts.callee_depth, opts.max_chars,
                             type_decls, opts.omit_ptn);
        kind = "code";
        kind_count = summaries.size();
    }
    if (opts.output_dot) {
        replace_wait_box(
            "CodeDumper: pass 5/5 — generating output\n"
            "Step 3/3: rendering DOT (%zu nodes, %zu edges)",
            functions.size(), edges.size());
        DotWriter dw;
        rendered = dw.render(functions, edges, start_set, opts);
        kind = "DOT";
        kind_count = functions.size();
    }
    if (opts.output_ptn) {
        replace_wait_box(
            "CodeDumper: pass 5/5 — generating output\n"
            "Step 3/3: rendering PTN (%zu functions)",
            summaries.size());
        PTNWriter pw;
        rendered = pw.render(summaries, start_set, opts.callee_depth, ptn_emitter);
        kind = "PTN";
        kind_count = summaries.size();
    }
    if (opts.output_asm) {
        replace_wait_box(
            "CodeDumper: pass 5/5 — generating output\n"
            "Step 3/3: rendering assembly (%zu functions)",
            summaries.size());
        AsmWriter aw;
        rendered = aw.render(summaries, annotations, ptn_emitter,
                             opts.callee_depth, type_decls, opts.omit_ptn);
        kind = "asm";
        kind_count = summaries.size();
    }

    if (rendered.empty()) {
        log("[codedump] No output type selected.\n");
        return;
    }

    if (opts.copy_to_clipboard) {
        replace_wait_box(
            "CodeDumper: copying %s to clipboard\n"
            "Bytes: %zu   Items: %zu",
            kind, rendered.size(), kind_count);
        wait.dismiss();
        ida::Status copied = ida::ui::copy_to_clipboard(rendered);
        if (copied) {
            log("[codedump] Copied {} to clipboard via {} ({} bytes)\n",
                kind, ida::ui::clipboard_backend(), rendered.size());
            info_user("CodeDumper: %s (%zu bytes) copied to clipboard (%s)",
                 kind, rendered.size(), ida::ui::clipboard_backend().data());
        } else {
            log("[codedump] Clipboard unavailable ({}); showing text dialog\n",
                copied.error().message);
            show_copy_fallback("Clipboard unavailable. Select all + copy manually:",
                               rendered);
        }
    } else {
        replace_wait_box(
            "CodeDumper: writing %s\n"
            "Bytes: %zu\n"
            "-> %s",
            kind, rendered.size(), bn.c_str());
        std::ofstream out(base_path);
        if (!out) {
            ida::ui::warning(std::format(
                "CodeDumper: could not open '{}' for writing", base_path));
        } else {
            out << rendered;
            log("[codedump] Wrote {} to {} ({} bytes)\n",
                kind, base_path.c_str(), rendered.size());
        }
    }

    log("[codedump] Done!\n");
}

// ── Path helpers ────────────────────────────────────────────────────────

static std::string default_dump_dir() {
    ida::Result<std::string> input = ida::database::input_file_path();
    if (input && !input->empty()) {
        std::string dir = ida::path::dirname(*input);
        if (!dir.empty())
            return dir;
    }

    ida::Result<std::string> idb = ida::database::idb_path();
    if (idb && !idb->empty()) {
        std::string dir = ida::path::dirname(*idb);
        if (!dir.empty())
            return dir;
    }

    if (const char *home = std::getenv("HOME"); home && *home)
        return home;
    return ".";
}

static std::string join_path(std::string_view dir, std::string_view name) {
    if (dir.empty()) return std::string{name};
#ifdef __NT__
    constexpr char sep = '\\';
#else
    constexpr char sep = '/';
#endif
    std::string result{dir};
    char last = result.back();
    if (last != '/' && last != '\\')
        result.push_back(sep);
    result.append(name);
    return result;
}

static std::string sanitize_for_filename(std::string_view name) {
    static const std::regex invalid_chars(R"([<>:"/\\|?*])");
    return std::regex_replace(std::string{name}, invalid_chars, "_");
}

// ── Code / DOT / PTN / ASM dump dialog ──────────────────────────────────

static void show_dump_dialog(std::string_view output_type) {
    ida::Result<ida::Address> ea = ida::ui::screen_address();
    if (!ea) {
        warn_user("Code Dumper: No function at cursor");
        return;
    }

    ida::Result<ida::function::Function> function = ida::function::at(*ea);
    if (!function) {
        warn_user("Code Dumper: No function at cursor");
        return;
    }

    ida::Address func_ea = static_cast<ida::Address>(function->start());
    std::string func_name = function->name();

    std::string default_name = sanitize_for_filename(func_name);

    std::string_view ext = ".c";
    if (output_type == "dot")      ext = ".dot";
    else if (output_type == "ptn") ext = ".ptn";
    else if (output_type == "asm") ext = ".asm";

    std::string default_basename = default_name + "_dump" + std::string{ext};
    std::string default_dir = default_dump_dir();
    std::string default_path = join_path(default_dir, default_basename);

    static const char form[] =
        "STARTITEM 0\n"
        "CodeDumper Options\n"
        "\n"
        "<#Depth of callers to traverse#Caller Depth:D:5:5::>\n"
        "<#Depth of callees/references to traverse#Callee Depth:D:5:5::>\n"
        "<#Maximum characters for output file (0=unlimited)#Max Characters:D:10:10::>\n"
        "<#Output file path#Output File:f:1:64::>\n"
        "\n"
        "Xref Types\n"
        "<Direct Calls:C>\n"
        "<Indirect Calls:C>\n"
        "<Data References:C>\n"
        "<Immediate References:C>\n"
        "<Tail Calls:C>\n"
        "<Virtual Calls:C>\n"
        "<Jump Tables:C>>\n"
        "\n"
        "Options\n"
        "<Omit PTN annotations:C>\n"
        "<Include size comments (sizeof / off / size):C>\n"
        "<Copy to clipboard (skip file write):C>\n"
        "<Include register summary (incoming/outgoing regs):C>\n"
        "<Trim types to referenced fields only (pad the rest):C>>\n"
        "\n";

    sval_t caller_depth = 2;
    sval_t callee_depth = 2;
    sval_t max_chars = 0;
    std::string chosen = default_path;
    std::uint16_t xref_checks = 0x7F;
    std::uint16_t options_check = 0;

    if (!ask_form_or_warn(form,
            ida::ui::form_sval(caller_depth),
            ida::ui::form_sval(callee_depth),
            ida::ui::form_sval(max_chars),
            ida::ui::form_path(chosen),
            ida::ui::form_bitset(xref_checks),
            ida::ui::form_bitset(options_check))) {
        return;
    }

    if (chosen.empty()) {
        chosen = default_path;
    } else {
        char last = chosen.back();
        bool ends_with_sep = (last == '/' || last == '\\');
        bool is_dir = !ends_with_sep && ida::path::is_directory(chosen);
        if (ends_with_sep || is_dir)
            chosen = join_path(chosen, default_basename);
    }

    DumpOptions opts{};
    opts.caller_depth          = static_cast<int>(caller_depth);
    opts.callee_depth          = static_cast<int>(callee_depth);
    opts.max_chars             = static_cast<int>(max_chars);
    opts.output_path           = chosen;
    opts.omit_ptn              = (options_check & 1) != 0;
    opts.size_comments         = (options_check & 2) != 0;
    opts.copy_to_clipboard     = (options_check & 4) != 0;
    opts.register_summary      = (options_check & 8) != 0;
    opts.referenced_fields_only= (options_check & 16) != 0;

    opts.include_direct_calls   = (xref_checks & (1 << 0)) != 0;
    opts.include_indirect_calls = (xref_checks & (1 << 1)) != 0;
    opts.include_data_refs      = (xref_checks & (1 << 2)) != 0;
    opts.include_immediate_refs = (xref_checks & (1 << 3)) != 0;
    opts.include_tail_calls     = (xref_checks & (1 << 4)) != 0;
    opts.include_virtual_calls  = (xref_checks & (1 << 5)) != 0;
    opts.include_jump_tables    = (xref_checks & (1 << 6)) != 0;

    opts.output_code = (output_type == "code");
    opts.output_dot  = (output_type == "dot");
    opts.output_ptn  = (output_type == "ptn");
    opts.output_asm  = (output_type == "asm");

    std::vector<ida::Address> start_funcs{func_ea};
    dump_functions_impl(start_funcs, opts);
}

// ── Single-type dump (from Local Types view) ────────────────────────────

static bool extract_type_ref(const ida::plugin::ActionContext &ctx,
                             std::string *out_name) {
    if (!ctx.type_ref || ctx.type_ref->name.empty()) return false;
    *out_name = ctx.type_ref->name;
    return true;
}

static std::string render_type_for_dump(const std::string &name,
                                        int depth,
                                        bool size_comments) {
    ida::type::TypeRenderOptions options;
    options.size_comments = size_comments;
    ida::Result<std::string> rendered =
        ida::type::render_named_declarations({name}, depth, options);
    return rendered ? *rendered : "";
}

static bool show_type_dump_dialog(const std::string &type_name,
                                  bool recursive,
                                  TypeDumpOptions *out) {
    std::string default_basename = sanitize_for_filename(type_name) + "_dump.h";
    std::string default_path = join_path(default_dump_dir(), default_basename);

    static const char form_dump[] =
        "STARTITEM 0\n"
        "Dump Type Options\n"
        "\n"
        "<#How many levels of dependent types to follow."
        " Use 0 for just this type, -1 for unlimited."
        "#Recursion Depth:D:6:10::>\n"
        "<#Output file path#Output File:f:1:64::>\n"
        "\n"
        "Options\n"
        "<Include size comments (sizeof / off / size):C>>\n"
        "\n";

    sval_t depth = recursive ? 5 : 0;
    std::string chosen = default_path;
    std::uint16_t opts_check = 1;

    if (!ask_form_or_warn(form_dump,
            ida::ui::form_sval(depth),
            ida::ui::form_path(chosen),
            ida::ui::form_bitset(opts_check)))
        return false;

    if (chosen.empty()) {
        chosen = default_path;
    } else {
        char last = chosen.back();
        bool ends_with_sep = (last == '/' || last == '\\');
        bool is_dir = !ends_with_sep && ida::path::is_directory(chosen);
        if (ends_with_sep || is_dir)
            chosen = join_path(chosen, default_basename);
    }

    out->depth = static_cast<int>(depth);
    out->size_comments = (opts_check & 1) != 0;
    out->output_path = chosen;
    return true;
}

static void emit_type_output(const std::string &type_name,
                             const std::string &body,
                             const std::string &out_path) {
    if (!out_path.empty()) {
        std::ofstream out(out_path);
        if (!out) {
            warn_user("Could not open '%s' for writing", out_path.c_str());
            return;
        }
        out << "// Type tree for " << type_name << "\n\n";
        out << body;
        log("[codedump] Wrote type {} to {}\n", type_name, out_path);
        return;
    }

    std::string payload = std::format("// Type tree for {}\n\n{}", type_name, body);

    ida::Status copied = ida::ui::copy_to_clipboard(payload);
    if (copied) {
        log("[codedump] Copied type {} to clipboard via {} ({} bytes)\n",
            type_name, ida::ui::clipboard_backend(), payload.size());
        info_user("CodeDumper: %zu bytes copied to clipboard (%s)",
             payload.size(), ida::ui::clipboard_backend().data());
        return;
    }

    log("[codedump] Clipboard unavailable ({}); showing text dialog\n",
        copied.error().message);
    show_copy_fallback("Clipboard unavailable. Select all + copy manually:",
                       payload);
}

static void do_dump_type(const ida::plugin::ActionContext &ctx, bool recursive) {
    std::string name;
    if (!extract_type_ref(ctx, &name)) {
        warn_user("CodeDumper: no named type at cursor");
        return;
    }

    TypeDumpOptions topts;
    if (!show_type_dump_dialog(name, recursive, &topts))
        return;

    WaitBoxGuard wait("NODELAY\nCodeDumper: rendering type...");
    replace_wait_box(
        "CodeDumper: rendering type tree\n"
        "Type: %s\n"
        "Depth: %s   Size comments: %s",
        name.c_str(),
        topts.depth < 0 ? "unlimited"
                        : std::to_string(topts.depth).c_str(),
        topts.size_comments ? "on" : "off");

    std::string body = render_type_for_dump(name, topts.depth, topts.size_comments);
    if (user_cancelled()) { log("[codedump] Cancelled.\n"); return; }
    if (body.empty()) {
        warn_user("CodeDumper: nothing to render for type '%s'", name.c_str());
        return;
    }

    replace_wait_box(
        "CodeDumper: writing type dump\n"
        "Type: %s   Bytes: %zu\n"
        "-> %s",
        name.c_str(), body.size(),
        ida::path::basename(topts.output_path).c_str());
    emit_type_output(name, body, topts.output_path);
}

static void do_copy_type(const ida::plugin::ActionContext &ctx, bool recursive) {
    std::string name;
    if (!extract_type_ref(ctx, &name)) {
        warn_user("CodeDumper: no named type at cursor");
        return;
    }

    int depth = 0;
    bool size_comments = true;
    if (recursive) {
        static const char form_copy[] =
            "STARTITEM 0\n"
            "Copy Type Recursively\n"
            "\n"
            "<#How many levels of dependent types to follow."
            " 0 = just this type, -1 = unlimited."
            "#Recursion Depth:D:6:10::>\n"
            "\n"
            "Options\n"
            "<Include size comments (sizeof / off / size):C>>\n"
            "\n";
        sval_t d = 5;
        std::uint16_t ck = 1;
        if (!ask_form_or_warn(form_copy,
                ida::ui::form_sval(d),
                ida::ui::form_bitset(ck)))
            return;
        depth = static_cast<int>(d);
        size_comments = (ck & 1) != 0;
    }

    {
        WaitBoxGuard wait("NODELAY\nCodeDumper: rendering type...");
        replace_wait_box(
            "CodeDumper: rendering type tree\n"
            "Type: %s\n"
            "Depth: %s   Size comments: %s",
            name.c_str(),
            depth < 0 ? "unlimited" : std::to_string(depth).c_str(),
            size_comments ? "on" : "off");

        std::string body = render_type_for_dump(name, depth, size_comments);
        if (user_cancelled()) { log("[codedump] Cancelled.\n"); return; }
        if (body.empty()) {
            warn_user("CodeDumper: nothing to render for type '%s'", name.c_str());
            return;
        }
        emit_type_output(name, body, /*out_path*/ "");
    }
}

static void do_type_graph(const ida::plugin::ActionContext &ctx, bool copy_default) {
    std::string name;
    if (!extract_type_ref(ctx, &name)) {
        warn_user("CodeDumper: no named type at cursor");
        return;
    }

    std::string default_basename =
        sanitize_for_filename(name) + "_typegraph.dot";
    std::string default_path =
        join_path(default_dump_dir(), default_basename);

    static const char form_graph[] =
        "STARTITEM 0\n"
        "Type Graph Options\n"
        "\n"
        "Render Mode\n"
        "<Simple (one node per type, edges between types):R>\n"
        "<Table (record-style node per type, edges leave the specific field row):R>>\n"
        "\n"
        "<#How many levels of dependent types to follow."
        " 0 = just the root, -1 = unlimited."
        "#Recursion Depth:D:6:10::>\n"
        "<#Output file path (ignored when 'Copy to clipboard' is set)."
        "#Output File:f:1:64::>\n"
        "\n"
        "Options\n"
        "<Include enums:C>\n"
        "<Include typedefs:C>\n"
        "<Copy to clipboard (skip file write):C>>\n"
        "\n";

    std::uint16_t mode_radio = 1; // default = Table layout
    sval_t depth = 4;
    std::string chosen = default_path;
    std::uint16_t opts_check = 0x3;
    if (copy_default) opts_check |= 4;

    if (!ask_form_or_warn(form_graph,
            ida::ui::form_radio(mode_radio),
            ida::ui::form_sval(depth),
            ida::ui::form_path(chosen),
            ida::ui::form_bitset(opts_check)))
        return;

    ida::type::TypeGraphOptions topts{};
    topts.mode = (mode_radio == 1)
        ? ida::type::TypeGraphOptions::Mode::Table
        : ida::type::TypeGraphOptions::Mode::Simple;
    topts.max_depth        = static_cast<int>(depth);
    topts.include_enums    = (opts_check & 1) != 0;
    topts.include_typedefs = (opts_check & 2) != 0;
    bool to_clipboard      = (opts_check & 4) != 0;

    WaitBoxGuard wait("NODELAY\nCodeDumper: building type graph...");
    replace_wait_box(
        "CodeDumper: building type graph\n"
        "Root: %s   Mode: %s\n"
        "Depth: %s   Enums: %s   Typedefs: %s",
        name.c_str(),
        topts.mode == ida::type::TypeGraphOptions::Mode::Table ? "table" : "simple",
        topts.max_depth < 0 ? "unlimited"
                            : std::to_string(topts.max_depth).c_str(),
        topts.include_enums ? "on" : "off",
        topts.include_typedefs ? "on" : "off");

    ida::Result<std::string> graph = ida::type::render_type_graph(name, topts);
    std::string dot = graph ? *graph : "";
    if (user_cancelled()) { log("[codedump] Cancelled.\n"); return; }
    if (dot.empty()) {
        warn_user("CodeDumper: empty graph for type '%s'", name.c_str());
        return;
    }

    if (to_clipboard) {
        wait.dismiss();
        ida::Status copied = ida::ui::copy_to_clipboard(dot);
        if (copied) {
            log("[codedump] Copied type graph ({} bytes) to clipboard via {}\n",
                dot.size(), ida::ui::clipboard_backend());
            info_user("CodeDumper: type graph (%zu bytes) copied to clipboard (%s)",
                 dot.size(), ida::ui::clipboard_backend().data());
        } else {
            show_copy_fallback("Clipboard unavailable. Select all + copy manually:",
                               dot);
        }
        return;
    }

    if (chosen.empty()) chosen = default_path;
    if (chosen.back() == '/' || chosen.back() == '\\' || ida::path::is_directory(chosen))
        chosen = join_path(chosen, default_basename);

    replace_wait_box(
        "CodeDumper: writing type graph\n"
        "Bytes: %zu\n"
        "-> %s",
        dot.size(), ida::path::basename(chosen).c_str());

    std::ofstream out(chosen);
    if (!out) {
        warn_user("CodeDumper: could not open '%s' for writing", chosen.c_str());
        return;
    }
    out << dot;
    log("[codedump] Wrote type graph ({} bytes) to {}\n", dot.size(), chosen);
}

// ── Metadata export / apply ─────────────────────────────────────────────

static void do_export_metadata(ida::Address func_ea) {
    ida::Result<ida::function::Function> function = ida::function::at(func_ea);
    if (!function) {
        warn_user("CodeDumper: no function at cursor");
        return;
    }
    ida::Address root_ea = static_cast<ida::Address>(function->start());

    std::string default_basename = sanitize_for_filename(function->name()) + ".cdumpmeta";
    std::string default_path = join_path(default_dump_dir(), default_basename);

    static const char form[] =
        "STARTITEM 0\n"
        "Export Metadata\n"
        "\n"
        "<#How deep to walk callees from the root function."
        " 1 = root only, 5 = root + 4 layers of callees."
        "#Callee Depth:D:6:10::>\n"
        "<#Where to write the .cdumpmeta file."
        "#Output File:f:1:64::>\n"
        "\n"
        "Options\n"
        "<Include referenced types:C>>\n"
        "\n";

    sval_t depth = 5;
    std::string chosen = default_path;
    std::uint16_t flags = 1;
    if (!ask_form_or_warn(form,
            ida::ui::form_sval(depth),
            ida::ui::form_path(chosen),
            ida::ui::form_bitset(flags)))
        return;

    if (chosen.empty()) chosen = default_path;
    if (chosen.back() == '/' || chosen.back() == '\\' || ida::path::is_directory(chosen))
        chosen = join_path(chosen, default_basename);

    MetadataExportOptions eopts{};
    eopts.callee_depth = static_cast<int>(depth);
    eopts.include_types = (flags & 1) != 0;

    WaitBoxGuard wait("NODELAY\nCodeDumper: preparing metadata export...");

    auto pcb = [&](const MetadataExportProgress &p) -> bool {
        if (user_cancelled()) return false;
        const char *phase = p.phase ? p.phase : "?";
        if (phase_is(phase, "graph")) {
            replace_wait_box(
                "CodeDumper: export — walking call graph\n"
                "Functions discovered: %zu / visited %zu\n"
                "Current: %s @ 0x%llX",
                p.total, p.processed, p.current_name,
                static_cast<unsigned long long>(p.current_ea));
        } else if (phase_is(phase, "metadata")) {
            int pct = p.total ? static_cast<int>((p.processed * 100) / p.total) : 100;
            replace_wait_box(
                "CodeDumper: export — collecting per-function metadata\n"
                "%d%% (%zu / %zu)\n"
                "Comments: %zu   Lvars: %zu\n"
                "Current: %s @ 0x%llX",
                pct, p.processed, p.total,
                p.comments_collected, p.lvars_collected,
                p.current_name, static_cast<unsigned long long>(p.current_ea));
        } else if (phase_is(phase, "types")) {
            int pct = p.total ? static_cast<int>((p.processed * 100) / p.total) : 100;
            replace_wait_box(
                "CodeDumper: export — resolving type tree\n"
                "%d%% (%zu / %zu) — %zu types collected\n"
                "Current: %s @ 0x%llX",
                pct, p.processed, p.total, p.types_collected,
                p.current_name, static_cast<unsigned long long>(p.current_ea));
        } else if (phase_is(phase, "serialize")) {
            replace_wait_box(
                "CodeDumper: export — serializing\n"
                "Functions: %zu   Types: %zu",
                p.total, p.types_collected);
        }
        return true;
    };

    MetadataDocument doc;
    if (!export_metadata(root_ea, eopts, &doc, pcb)) {
        log("[codedump] Metadata export cancelled.\n");
        return;
    }

    std::string serialized = serialize_metadata(doc);
    std::ofstream out(chosen);
    if (!out) {
        warn_user("CodeDumper: could not open '%s' for writing", chosen.c_str());
        return;
    }
    out << serialized;

    log("[codedump] Exported {} functions, {} types to {} ({} bytes)\n",
        doc.functions.size(), doc.types.size(),
        chosen.c_str(), serialized.size());
    info_user("CodeDumper: metadata exported\n"
         "Functions: %zu\nTypes: %zu\nFile: %s",
         doc.functions.size(), doc.types.size(), chosen.c_str());
}

static void do_apply_metadata(ida::Address func_ea) {
    ida::Result<ida::function::Function> function = ida::function::at(func_ea);
    if (!function) {
        warn_user("CodeDumper: no function at cursor (need a root function "
                "to map the metadata onto)");
        return;
    }
    ida::Address target_root = static_cast<ida::Address>(function->start());

    static const char form[] =
        "STARTITEM 0\n"
        "Apply Metadata\n"
        "\n"
        "<#Path to the .cdumpmeta file produced by Export Metadata."
        "#Metadata File:f:1:64::>\n"
        "\n"
        "Options\n"
        "<Continue past fingerprint mismatches (skip just that subtree):C>\n"
        "<Overwrite existing names:C>>\n"
        "\n";

    std::string metadata_path;
    std::uint16_t flags = 0x3;
    if (!ask_form_or_warn(form,
            ida::ui::form_path(metadata_path, false),
            ida::ui::form_bitset(flags)))
        return;

    if (metadata_path.empty()) {
        warn_user("CodeDumper: no metadata file specified");
        return;
    }

    std::ifstream in(metadata_path, std::ios::binary);
    if (!in) {
        warn_user("CodeDumper: cannot open '%s'", metadata_path.c_str());
        return;
    }
    std::string text((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());

    MetadataDocument doc;
    ParseResult pr = parse_metadata(text, &doc);
    if (!pr.ok) {
        warn_user("CodeDumper: failed to parse metadata at line %d: %s",
                pr.error_line, pr.error.c_str());
        return;
    }

    MetadataApplyOptions aopts{};
    aopts.continue_on_mismatch = (flags & 1) != 0;
    aopts.overwrite_existing   = (flags & 2) != 0;

    WaitBoxGuard wait("NODELAY\nCodeDumper: preparing metadata apply...");

    auto pcb = [&](const MetadataApplyProgress &p) -> bool {
        if (user_cancelled()) return false;
        const char *phase = p.phase ? p.phase : "?";
        if (phase_is(phase, "verify")) {
            int pct = p.total ? static_cast<int>((p.processed * 100) / p.total) : 100;
            replace_wait_box(
                "CodeDumper: apply — verifying fingerprints\n"
                "%d%% (%zu / %zu)   Mismatches: %zu\n"
                "Source: '%s' @ 0x%llX\n"
                "Target: 0x%llX",
                pct, p.processed, p.total, p.mismatches,
                p.current_name,
                static_cast<unsigned long long>(p.current_source_ea),
                static_cast<unsigned long long>(p.current_target_ea));
        } else if (phase_is(phase, "types")) {
            replace_wait_box(
                "CodeDumper: apply — importing type tree\n"
                "%zu / %zu types parsed",
                p.processed, p.total);
        } else if (phase_is(phase, "apply")) {
            int pct = p.total ? static_cast<int>((p.processed * 100) / p.total) : 100;
            replace_wait_box(
                "CodeDumper: apply — writing metadata\n"
                "%d%% (%zu / %zu)\n"
                "Names: %zu  Prototypes: %zu  Comments: %zu  Lvars: %zu  Types: %zu\n"
                "Current: '%s' @ 0x%llX -> 0x%llX",
                pct, p.processed, p.total,
                p.applied_names, p.applied_protos,
                p.applied_cmts, p.applied_lvars, p.applied_types,
                p.current_name,
                static_cast<unsigned long long>(p.current_source_ea),
                static_cast<unsigned long long>(p.current_target_ea));
        }
        return true;
    };

    MetadataApplyReport rep;
    bool ok = apply_metadata(doc, target_root, aopts, &rep, pcb);

    if (!ok) {
        warn_user("CodeDumper: metadata apply failed\n%s",
                rep.fatal_error.empty() ? "(cancelled)" : rep.fatal_error.c_str());
        return;
    }

    std::string summary = std::format(
        "Functions matched: {}\nFunctions mismatched: {}\n"
        "Names applied: {}\nPrototypes applied: {}\n"
        "Comments applied: {}\nLvars applied: {}\nTypes applied: {}",
        rep.functions_matched, rep.functions_mismatched,
        rep.names_applied, rep.prototypes_applied,
        rep.comments_applied, rep.lvars_applied, rep.types_applied);

    if (!rep.mismatch_details.empty()) {
        summary += std::format("\n\nMismatch details ({}):\n",
                               rep.mismatch_details.size());
        size_t shown = 0;
        for (const auto &d : rep.mismatch_details) {
            if (shown >= 6) {
                summary += std::format("...and {} more\n",
                                       rep.mismatch_details.size() - shown);
                break;
            }
            summary += std::format("- {}\n", d);
            ++shown;
        }
        log("[codedump] Mismatches:\n");
        for (const auto &d : rep.mismatch_details) log("  {}\n", d);
    }

    log("[codedump] Metadata apply complete: matched={} mismatched={} "
        "names={} protos={} cmts={} lvars={} types={}\n",
        rep.functions_matched, rep.functions_mismatched,
        rep.names_applied, rep.prototypes_applied,
        rep.comments_applied, rep.lvars_applied, rep.types_applied);

    info_user("CodeDumper: metadata apply complete\n\n%s", summary.c_str());
}

// ── idax action callbacks / Hex-Rays popup hook ────────────────────────

static bool is_pseudocode_context(const ida::plugin::ActionContext &ctx) {
    return ctx.widget_type == static_cast<int>(ida::ui::WidgetType::Pseudocode);
}

static bool is_type_context(const ida::plugin::ActionContext &ctx) {
    return ctx.widget_type == static_cast<int>(ida::ui::WidgetType::LocalTypes)
        && ctx.type_ref.has_value();
}

static ida::Address context_ea_or_screen(const ida::plugin::ActionContext &ctx) {
    if (ctx.current_address != ida::BadAddress)
        return static_cast<ida::Address>(ctx.current_address);
    ida::Result<ida::Address> screen = ida::ui::screen_address();
    return screen ? static_cast<ida::Address>(*screen) : ida::BadAddress;
}

static void attach_popup_action(ida::ui::PopupHandle popup,
                                void *widget_handle,
                                std::string_view action_id,
                                std::string_view menu_path) {
    ida::Status status =
        ida::ui::attach_registered_action(popup, widget_handle, action_id, menu_path);
    if (!status)
        log("[codedump] Failed to attach popup action {}: {}\n",
            action_id, status.error().message);
}

static void attach_popup_action(ida::ui::PopupHandle popup,
                                const ida::ui::Widget &widget,
                                std::string_view action_id,
                                std::string_view menu_path) {
    ida::Status status =
        ida::ui::attach_registered_action(popup, widget, action_id, menu_path);
    if (!status)
        log("[codedump] Failed to attach popup action {}: {}\n",
            action_id, status.error().message);
}

static void attach_pseudocode_actions(
        const ida::decompiler::PopulatingPopupEvent &event) {
    attach_popup_action(event.popup_handle, event.widget_handle,
                        ACTION_DUMP_CODE, POPUP_PATH);
    attach_popup_action(event.popup_handle, event.widget_handle,
                        ACTION_DUMP_DOT, POPUP_PATH);
    attach_popup_action(event.popup_handle, event.widget_handle,
                        ACTION_DUMP_PTN, POPUP_PATH);
    attach_popup_action(event.popup_handle, event.widget_handle,
                        ACTION_DUMP_ASM, POPUP_PATH);
    attach_popup_action(event.popup_handle, event.widget_handle,
                        ACTION_EXPORT_META, POPUP_PATH);
    attach_popup_action(event.popup_handle, event.widget_handle,
                        ACTION_APPLY_META, POPUP_PATH);
}

static void attach_type_actions(const ida::ui::PopupEvent &event) {
    if (event.type != ida::ui::WidgetType::LocalTypes) return;

    attach_popup_action(event.popup, event.widget,
                        ACTION_DUMP_TYPE, TYPE_POPUP_PATH);
    attach_popup_action(event.popup, event.widget,
                        ACTION_DUMP_TYPE_RECURSIVE, TYPE_POPUP_PATH);
    attach_popup_action(event.popup, event.widget,
                        ACTION_COPY_TYPE, TYPE_POPUP_PATH);
    attach_popup_action(event.popup, event.widget,
                        ACTION_COPY_TYPE_RECURSIVE, TYPE_POPUP_PATH);
    attach_popup_action(event.popup, event.widget,
                        ACTION_TYPE_GRAPH_DUMP, TYPE_POPUP_PATH);
    attach_popup_action(event.popup, event.widget,
                        ACTION_TYPE_GRAPH_COPY, TYPE_POPUP_PATH);
}

// ── Action registration table ───────────────────────────────────────────

struct ActionDesc {
    const char *id;
    const char *label;
    const char *tooltip;
};

static const ActionDesc kActions[] = {
    { ACTION_DUMP_CODE,           "Dump code (.c)...",
      "Dump decompiled code with PTN annotations" },
    { ACTION_DUMP_DOT,            "Dump call graph (.dot)...",
      "Generate DOT call graph" },
    { ACTION_DUMP_PTN,            "Dump PTN (.ptn)...",
      "Generate PTN provenance file" },
    { ACTION_DUMP_ASM,            "Dump assembly (.asm)...",
      "Generate annotated assembly" },
    { ACTION_DUMP_TYPE,           "Dump type...",
      "Dump this type to a file" },
    { ACTION_DUMP_TYPE_RECURSIVE, "Dump type recursively...",
      "Dump this type and its dependencies to a file" },
    { ACTION_COPY_TYPE,           "Copy type",
      "Show this type's definition for copy/paste" },
    { ACTION_COPY_TYPE_RECURSIVE, "Copy type recursively...",
      "Show this type and its dependencies for copy/paste" },
    { ACTION_TYPE_GRAPH_DUMP,     "Dump type graph (.dot)...",
      "Save a graphviz DOT graph of this type's dependency tree" },
    { ACTION_TYPE_GRAPH_COPY,     "Copy type graph (.dot)...",
      "Copy a graphviz DOT graph of this type's dependency tree to the clipboard" },
    { ACTION_EXPORT_META,         "Export metadata (functions+types)...",
      "Save names/comments/types/lvars for the function tree to a .cdumpmeta file" },
    { ACTION_APPLY_META,          "Apply metadata...",
      "Apply a .cdumpmeta file to the function under the cursor (with fingerprint verification)" },
};

static void register_action_or_warn(ida::plugin::Action action) {
    ida::Status status = ida::plugin::register_action(action);
    if (!status)
        warn_user("CodeDumper: failed to register action '%s': %s",
                action.id.c_str(), status.error().message.c_str());
}

static void register_actions() {
    ida::plugin::Action action;

    action = {};
    action.id = ACTION_DUMP_CODE;
    action.label = "Dump code (.c)...";
    action.tooltip = "Dump decompiled code with PTN annotations";
    action.handler_with_context = [](const ida::plugin::ActionContext &) {
        show_dump_dialog("code");
        return ida::ok();
    };
    action.enabled_with_context = is_pseudocode_context;
    register_action_or_warn(action);

    action = {};
    action.id = ACTION_DUMP_DOT;
    action.label = "Dump call graph (.dot)...";
    action.tooltip = "Generate DOT call graph";
    action.handler_with_context = [](const ida::plugin::ActionContext &) {
        show_dump_dialog("dot");
        return ida::ok();
    };
    action.enabled_with_context = is_pseudocode_context;
    register_action_or_warn(action);

    action = {};
    action.id = ACTION_DUMP_PTN;
    action.label = "Dump PTN (.ptn)...";
    action.tooltip = "Generate PTN provenance file";
    action.handler_with_context = [](const ida::plugin::ActionContext &) {
        show_dump_dialog("ptn");
        return ida::ok();
    };
    action.enabled_with_context = is_pseudocode_context;
    register_action_or_warn(action);

    action = {};
    action.id = ACTION_DUMP_ASM;
    action.label = "Dump assembly (.asm)...";
    action.tooltip = "Generate annotated assembly";
    action.handler_with_context = [](const ida::plugin::ActionContext &) {
        show_dump_dialog("asm");
        return ida::ok();
    };
    action.enabled_with_context = is_pseudocode_context;
    register_action_or_warn(action);

    action = {};
    action.id = ACTION_DUMP_TYPE;
    action.label = "Dump type...";
    action.tooltip = "Dump this type to a file";
    action.handler_with_context = [](const ida::plugin::ActionContext &ctx) {
        do_dump_type(ctx, false);
        return ida::ok();
    };
    action.enabled_with_context = is_type_context;
    register_action_or_warn(action);

    action = {};
    action.id = ACTION_DUMP_TYPE_RECURSIVE;
    action.label = "Dump type recursively...";
    action.tooltip = "Dump this type and its dependencies to a file";
    action.handler_with_context = [](const ida::plugin::ActionContext &ctx) {
        do_dump_type(ctx, true);
        return ida::ok();
    };
    action.enabled_with_context = is_type_context;
    register_action_or_warn(action);

    action = {};
    action.id = ACTION_COPY_TYPE;
    action.label = "Copy type";
    action.tooltip = "Show this type's definition for copy/paste";
    action.handler_with_context = [](const ida::plugin::ActionContext &ctx) {
        do_copy_type(ctx, false);
        return ida::ok();
    };
    action.enabled_with_context = is_type_context;
    register_action_or_warn(action);

    action = {};
    action.id = ACTION_COPY_TYPE_RECURSIVE;
    action.label = "Copy type recursively...";
    action.tooltip = "Show this type and its dependencies for copy/paste";
    action.handler_with_context = [](const ida::plugin::ActionContext &ctx) {
        do_copy_type(ctx, true);
        return ida::ok();
    };
    action.enabled_with_context = is_type_context;
    register_action_or_warn(action);

    action = {};
    action.id = ACTION_TYPE_GRAPH_DUMP;
    action.label = "Dump type graph (.dot)...";
    action.tooltip = "Save a graphviz DOT graph of this type's dependency tree";
    action.handler_with_context = [](const ida::plugin::ActionContext &ctx) {
        do_type_graph(ctx, false);
        return ida::ok();
    };
    action.enabled_with_context = is_type_context;
    register_action_or_warn(action);

    action = {};
    action.id = ACTION_TYPE_GRAPH_COPY;
    action.label = "Copy type graph (.dot)...";
    action.tooltip = "Copy a graphviz DOT graph of this type's dependency tree to the clipboard";
    action.handler_with_context = [](const ida::plugin::ActionContext &ctx) {
        do_type_graph(ctx, true);
        return ida::ok();
    };
    action.enabled_with_context = is_type_context;
    register_action_or_warn(action);

    action = {};
    action.id = ACTION_EXPORT_META;
    action.label = "Export metadata (functions+types)...";
    action.tooltip = "Save names/comments/types/lvars for the function tree to a .cdumpmeta file";
    action.handler_with_context = [](const ida::plugin::ActionContext &ctx) {
        do_export_metadata(context_ea_or_screen(ctx));
        return ida::ok();
    };
    action.enabled_with_context = is_pseudocode_context;
    register_action_or_warn(action);

    action = {};
    action.id = ACTION_APPLY_META;
    action.label = "Apply metadata...";
    action.tooltip = "Apply a .cdumpmeta file to the function under the cursor (with fingerprint verification)";
    action.handler_with_context = [](const ida::plugin::ActionContext &ctx) {
        do_apply_metadata(context_ea_or_screen(ctx));
        return ida::ok();
    };
    action.enabled_with_context = is_pseudocode_context;
    register_action_or_warn(action);
}

static void unregister_actions() {
    for (const auto &a : kActions) {
        ida::Status status = ida::plugin::unregister_action(a.id);
        if (!status)
            log("[codedump] Failed to unregister action {}: {}\n",
                a.id, status.error().message);
    }
}

// ── idax Plugin subclass ────────────────────────────────────────────────

class CodeDumpPlugin : public ida::plugin::Plugin {
public:
    ida::plugin::Info info() const override {
        return {
            .name    = "Code Dumper",
            .hotkey  = "",
            .comment = "Dumps decompiled code with provenance tracking annotations",
            .help    = "Right-click in pseudocode or Local Types view to dump code or types.",
            .icon    = -1,
        };
    }

    bool init() override {
        ida::Result<ida::decompiler::ScopedSession> session =
            ida::decompiler::initialize();
        if (!session) {
            ida::ui::message(std::format(
                "[codedump] Hex-Rays decompiler not available: {}\n",
                session.error().message));
            return false;
        }
        hexrays_session_.emplace(std::move(*session));

        register_actions();

        ida::Result<ida::decompiler::Token> popup_subscription =
            ida::decompiler::on_populating_popup(attach_pseudocode_actions);
        if (!popup_subscription) {
            warn_user("CodeDumper: failed to subscribe to Hex-Rays popup event: %s",
                    popup_subscription.error().message.c_str());
            unregister_actions();
            hexrays_session_.reset();
            return false;
        }
        popup_subscription_.emplace(*popup_subscription);

        ida::Result<ida::ui::Token> ui_subscription =
            ida::ui::on_popup_ready(attach_type_actions);
        if (!ui_subscription) {
            warn_user("CodeDumper: failed to subscribe to UI popup event: %s",
                      ui_subscription.error().message.c_str());
            popup_subscription_.reset();
            unregister_actions();
            hexrays_session_.reset();
            return false;
        }
        ui_subscription_.emplace(*ui_subscription);

        ida::ui::message("[codedump] Plugin initialized "
                         "(right-click in pseudocode or Local Types view)\n");
        return true;
    }

    void term() override {
        if (hexrays_session_) {
            ui_subscription_.reset();
            popup_subscription_.reset();
            unregister_actions();
            hexrays_session_.reset();
        }
        ida::ui::message("[codedump] Plugin terminated\n");
    }

    ida::Status run(std::size_t) override {
        show_dump_dialog("code");
        return ida::ok();
    }

private:
    std::optional<ida::decompiler::ScopedSession> hexrays_session_;
    std::optional<ida::decompiler::ScopedSubscription> popup_subscription_;
    std::optional<ida::ui::ScopedSubscription> ui_subscription_;
};

} // namespace codedump

// IDAX_PLUGIN_WITH_FLAGS token-pastes its ClassName argument into identifiers,
// so it cannot accept a qualified `ns::Type`. Pull the plugin class into the
// global namespace under a short alias and feed that to the macro.
using CodeDumpPlugin = codedump::CodeDumpPlugin;

IDAX_PLUGIN_WITH_FLAGS(CodeDumpPlugin,
                       ida::plugin::ExportFlags{ .hidden = true })
