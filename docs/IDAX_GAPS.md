# ida-cdump idax parity audit

This is the current, narrow answer to: what is left before ida-cdump is fully
ported to idax?

Last audited: 2026-05-31.

## Bottom Line

For current ida-cdump behavior, no idax parity blocker remains.

The old high-value SDK dependencies are gone from ida-cdump call sites: raw
Hex-Rays ctree/type walks, raw `tinfo_t` formatting, raw lvar metadata, raw
instruction decode/register feature checks, raw switch metadata, raw
xref/data/imagebase traversal, raw plugin popup hooks, direct Hex-Rays
init/term, typed `ask_form`, wait boxes, clipboard fallback, path helpers,
and metadata type import are routed through idax APIs now.

What remains is not missing idax capability. It is residual SDK vocabulary in
the IDA plugin build boundary:

- The CMake/IDA plugin build necessarily uses the IDA SDK ABI through idax and
  ida-cmake.
- idax itself includes SDK headers internally, as intended.

There are two useful definitions of done:

| Definition | Status | What remains |
| --- | --- | --- |
| Behavioral idax parity: no current feature depends on missing idax wrappers | Done | Nothing implementation-blocking |
| SDK-token-free ida-cdump sources outside the plugin ABI/build boundary | Done | Nothing in `src` |

## Evidence

Focused scan for the former blocker classes:

```sh
rg -n '#include <(hexrays|typeinf|nalt|allins|xref|funcs|segment|bytes|ua|idp|kernwin|loader)\.hpp>|get_tinfo|restore_user_lvar_settings|modify_user_lvar_info|parse_decl|decode_insn|get_canon_feature|get_switch_info|get_imagebase|getnseg|getseg|get_qword|get_dword|get_first_cref|get_next_cref|get_first_dref|get_next_dref|cfunc_t|cexpr_t|carg_t|lvar_saved_info_t|xrefblk_t|insn_t|op_t|get_ph|ctree_visitor_t|hook_event_listener|attach_action_to_popup|init_hexrays_plugin|term_hexrays_plugin|parse_decls|print_decls|get_idp_name|qbasename|qdirname|qisdir|get_path\(' src
```

Current hits:

- `src/transfer/metadata_apply.cpp`: `ida::type::parse_declarations(blob)` is
  an idax call, not raw SDK `parse_decls`.
- `src/transfer/metadata.h`: `op_types` appears in a comment and field name,
  not as SDK `op_t`.

Source-purity scan:

```sh
rg -n '\bea_t\b|\bBADADDR\b|qsnprintf|qstrcmp|#include <pro\.h>|#include <ida\.hpp>' src
```

Current hits: none.

Build evidence from the current port pass:

```sh
cmake --build /models/dev/idax/build-test-fetch --target idax_api_surface_check -j2
IDASDK=/models/dev/ida-cdump/build/_deps/ida_sdk-src cmake --build /models/dev/ida-cdump/build -j2
```

Both passed during the current parity closure pass.

## Current idax Replacements

| Former raw SDK area | Current idax API used by ida-cdump |
| --- | --- |
| Typed modal forms | `ida::ui::ask_form`, `form_sval`, `form_path`, `form_bitset`, `form_radio` |
| Wait box / cancellation | `ida::ui::WaitBox` |
| Clipboard and text fallback | `ida::ui::copy_to_clipboard`, `clipboard_backend`, `ask_text` |
| Input/IDB paths and path pieces | `ida::database::input_file_path`, `idb_path`, `ida::path::*` |
| Hex-Rays lifecycle | `ida::decompiler::initialize`, `ScopedSession` |
| Pseudocode popup | `ida::decompiler::on_populating_popup` |
| Local Types action context | `ida::plugin::ActionContext::type_ref` |
| Generic Local Types popup | `ida::ui::on_popup_ready`, `attach_registered_action` |
| Function lookup/comments/prototypes | `ida::function::*`, `ida::comment::*` |
| Names | `ida::name::*` |
| Instruction decode/text/operands | `ida::instruction::*` |
| Register read/write analysis | `Operand::is_read`, `Operand::is_written`, register metadata |
| Flow graph and switch metadata | `ida::graph::flowchart`, `switch_table` |
| Data reads/imagebase/segments/xrefs | `ida::data`, `ida::database`, `ida::segment`, `ida::xref` |
| Bulk type import | `ida::type::parse_declarations` |
| Lvar export/apply metadata | `saved_user_lvar_settings`, `apply_user_lvar_setting` |
| Ctree provenance analysis | `DecompiledFunction`, `ExpressionView`, `for_each_expression` |
| Referenced-type collection | `ida::decompiler::collect_referenced_types` |
| Type declaration rendering | `ida::type::render_named_declarations`, `render_ordinal_declarations` |
| Type graph rendering | `ida::type::render_type_graph` |
| Metadata type export | `ida::type::declarations_for_ordinals` |

## Future-Only Hex-Rays Features

These are not needed for current ida-cdump parity and should not be treated as
remaining work unless ida-cdump grows new features:

- Hex-Rays positioned user comments (`cfunc->user_cmts` / `treeloc_t`).
- Mutable ctree visitors.
- Broader microcode mutation beyond idax's existing filter/lifter APIs.

## Recommended Next Move

Move to the next topic. Current ida-cdump behavior is idax-backed, and the
source-purity cleanup for direct SDK address/formatting tokens is complete.
