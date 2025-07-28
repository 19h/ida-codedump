# -*- coding: utf-8 -*-
"""
summary: IDA Pro plugin to dump decompiled code of a function and its callers/callees/references,
         or multiple specified functions and their combined graphs.
         Now also supports generating DOT graphs of the call graphs.

description:
  This plugin adds:
  1. Context menu items ("Dump Function + Callers/Callees/Refs..." and "Generate DOT Graph + Callers/Callees/Refs...") to the Pseudocode view.
     When activated, it prompts for depths and an output file for the *current* function.
  2. Menu items under "Edit -> Plugins -> Code Dumper" for dumping code or generating DOT graphs for multiple functions.
     When activated, it prompts for a comma-separated list of function names/addresses,
     then prompts for depths and an output file to be applied to *all* specified functions.

  It traverses the call graph upwards (callers) and downwards (callees/references)
  up to the specified depths from the starting function(s), collects all unique
  function addresses, decompiles them using the Hex-Rays decompiler, and saves the
  results into the selected C file. Alternatively, generates a DOT file for Graphviz.

  Callee/Reference finding includes:
  - Direct calls (via code cross-references).
  - Functions whose addresses are referenced by instructions (via data cross-references, e.g., mov reg, offset func).
  - Functions whose addresses appear as immediate operands (e.g., push offset func).
  - Functions "called" via the 'push <addr>; ret' pattern.
  - Enhanced: Indirect calls via registers/memory, with basic def-use tracing in basic blocks.
  - Enhanced: VTable detection and virtual call resolution for C++ binaries.
  - Enhanced: Jump table entries pointing to functions.

  All IDA API interactions are performed synchronously in the main IDA thread, managed via
  execute_sync and execute_ui_requests from background threads.

  Requires:
  - IDA Pro 7.6+ (with Python 3 and PyQt5 support for dialogs)
  - Hex-Rays Decompiler
  - Uses ida_xref API (compatible with IDA 7.x and IDA 9+)

FINAL VERSION: Uses menu integration and supports DOT graph generation with advanced heuristics.
"""

# --- Imports ---
import ida_kernwin
import ida_hexrays
import ida_funcs
import ida_name
import ida_bytes
import idaapi
import idautils
import idc
import ida_xref   # For xref iteration
import ida_nalt
import ida_ua     # For instruction decoding
import ida_idp    # For is_ret_insn, instruction features
import ida_segment  # For segment access in vtable detection
import ida_ida  # For inf accessors like inf_is_64bit
import ida_gdl  # For FlowChart and switch info

import threading
import os
import sys
from functools import partial
import traceback
import time
import re # For parsing addresses
from collections import defaultdict, deque # For graph edges and BFS

# Third-party libraries (PyQt5 needed for standard IDA dialogs)
try:
    from PyQt5 import QtCore, QtGui, QtWidgets
    print("CodeDumper: PyQt5 imported successfully (needed for IDA dialogs).")
except ImportError:
    print("CodeDumper Error: PyQt5 not found. Standard IDA dialogs might not work.")
    # Allow plugin to load, but dialogs might fail later.

# --- Configuration ---
PLUGIN_NAME = "CodeDumper"
# Context Menu Actions
ACTION_ID_CTX = "codedumper:dump_callers_callees_refs_ctx"
ACTION_LABEL_CTX = "Dump Function + Callers/Callees/Refs..."
ACTION_TOOLTIP_CTX = "Decompile current function, callers, callees, and referenced functions to a C file"
ACTION_ID_DOT_CTX = "codedumper:generate_dot_ctx"
ACTION_LABEL_DOT_CTX = "Generate DOT Graph + Callers/Callees/Refs..."
ACTION_TOOLTIP_DOT_CTX = "Generate DOT graph of the call graph for current function, callers, callees, and referenced functions"
MENU_PATH_CTX = "Dump code/" # Submenu path for context menu
# Multi-Function Actions
ACTION_ID_CODE_MULTI = "codedumper:dump_code_multi"
ACTION_LABEL_CODE_MULTI = "Dump Code for Multiple Functions..."
ACTION_TOOLTIP_CODE_MULTI = "Decompile a list of functions and their combined callers/callees/refs to a C file"
ACTION_ID_DOT_MULTI = "codedumper:generate_dot_multi"
ACTION_LABEL_DOT_MULTI = "Generate DOT Graph for Multiple Functions..."
ACTION_TOOLTIP_DOT_MULTI = "Generate DOT graph for a list of functions and their combined callers/callees/refs"
MENU_PATH_MULTI = f"Edit/{PLUGIN_NAME}/"

# --- Concurrency Control ---
g_dump_in_progress = set() # Set of func_ea currently being processed (for single context menu dumps)
g_multi_dump_active = False # Flag for multi-function dump
g_dump_lock = threading.Lock()
print("CodeDumper: Concurrency control variables initialized.")


# --- Helper Functions for Graph Traversal (MUST run in main thread) ---

def find_callers_recursive(target_ea, current_depth, max_depth, visited_eas, edges=None, allowed_types=None):
    """
    Recursively finds callers up to a specified depth using xrefs.
    MUST be called from the main IDA thread (e.g., via execute_sync).
    Modifies visited_eas in place.
    If edges is provided, collects caller -> target edges.
    """
    if allowed_types is None:
        allowed_types = set(['direct_call', 'indirect_call', 'data_ref', 'immediate_ref', 'tail_call_push_ret', 'virtual_call', 'jump_table'])

    # Check depth first
    if current_depth > max_depth:
        return set()

    # Check if already visited *before* adding again (important for multi-start)
    if target_ea in visited_eas:
        return set()

    visited_eas.add(target_ea)
    callers = set()

    # Find direct callers to target_ea using code cross-references
    ref_ea = ida_xref.get_first_cref_to(target_ea)
    while ref_ea != idaapi.BADADDR:
        caller_func = ida_funcs.get_func(ref_ea)
        if caller_func:
            caller_ea = caller_func.start_ea
            if 'direct_call' in allowed_types:
                if edges is not None:
                    edges[caller_ea][target_ea].add('direct_call')
                # Recurse *only* if not already visited
                if caller_ea not in visited_eas:
                    callers.add(caller_ea)
                    # Pass the *same* visited_eas set down
                    callers.update(find_callers_recursive(caller_ea, current_depth + 1, max_depth, visited_eas, edges=edges, allowed_types=allowed_types))
                # else: # Already visited or part of the initial set, don't recurse further from here
                #    pass

        ref_ea = ida_xref.get_next_cref_to(target_ea, ref_ea)

    return callers

def detect_indirect_target(ea, func_start_ea, bb_start, bb_end):
    """
    Performs basic backward def-use analysis within the basic block to resolve indirect call targets.
    Returns set of possible function EAs if resolved.
    """
    possible_targets = set()
    mnem = idc.print_insn_mnem(ea)
    if mnem not in ['call', 'jmp']:
        return possible_targets

    op_type = idc.get_operand_type(ea, 0)
    if op_type in [idaapi.o_reg, idaapi.o_mem, idaapi.o_phrase, idaapi.o_displ]:  # Indirect
        # Trace back in block for defs of the reg/mem
        current_ea = ea - idc.get_item_size(ea)  # Start from prev insn
        traced_regs = set()
        if op_type == idaapi.o_reg:
            traced_regs.add(idc.get_operand_value(ea, 0))  # Reg number
        elif op_type in [idaapi.o_phrase, idaapi.o_displ]:
            traced_regs.add(idc.get_operand_value(ea, 0))  # Base reg

        while current_ea >= bb_start and current_ea < bb_end:
            prev_mnem = idc.print_insn_mnem(current_ea)
            if prev_mnem.startswith('mov'):  # Simple def
                prev_op_type0 = idc.get_operand_type(current_ea, 0)
                prev_op_type1 = idc.get_operand_type(current_ea, 1)
                if prev_op_type0 == idaapi.o_reg and idc.get_operand_value(current_ea, 0) in traced_regs:
                    if prev_op_type1 == idaapi.o_imm:
                        imm_val = idc.get_operand_value(current_ea, 1)
                        if ida_funcs.get_func(imm_val):
                            possible_targets.add(imm_val)
                    elif prev_op_type1 == idaapi.o_mem:
                        mem_addr = idc.get_operand_value(current_ea, 1)
                        if ida_bytes.is_func(ida_bytes.get_flags(mem_addr)):
                            possible_targets.add(mem_addr)
                    # Stop tracing this reg; assume single def
                    traced_regs.remove(idc.get_operand_value(current_ea, 0))
                    if not traced_regs:
                        break
            current_ea -= idc.get_item_size(current_ea)

    return possible_targets

def detect_jump_tables(ea):
    """
    Detects jump tables at the given ea.
    Returns list of target EAs if jump table detected.
    """
    si = ida_nalt.get_switch_info(ea)
    if si:
        cases = ida_xref.calc_switch_cases(ea, si)
        if cases:
            targets = set(cases.targets)  # Unique targets
            return [tgt for tgt in targets if ida_funcs.get_func(tgt)]

    # Manual pattern for jmp [table + reg*scale] (unchanged from original)
    op_type = idc.get_operand_type(ea, 0)
    if op_type == idaapi.o_displ and idc.print_insn_mnem(ea) == 'jmp':
        base = idc.get_operand_value(ea, 0)  # addr
        # Read table entries until non-code or out-of-bound
        entries = []
        ptr_size = 8 if ida_ida.inf_is_64bit() else 4
        for i in range(20):  # Arbitrary max cases
            ptr = ida_bytes.get_qword(base + i * ptr_size) if ptr_size == 8 else ida_bytes.get_dword(base + i * ptr_size)
            if ptr == 0 or not ida_funcs.get_func(ptr):
                break
            entries.append(ptr)
        if len(entries) > 1:
            return entries
    return []

def find_vtables():
    """
    Scans read-only data segments for vtable patterns: sequences of >=3 consecutive pointers to code functions.
    Returns dict {vtable_ea: list of vfunc_eas}.
    """
    vtables = {}
    code_seg = ida_segment.get_segm_by_name(".text") or ida_segment.get_segm_by_name("__text")  # Adapt for arch
    if not code_seg:
        return vtables

    data_segs = [ida_segment.getseg(s) for s in idautils.Segments() if ida_segment.getseg(s).perm & ida_segment.SEGPERM_EXEC == 0 and ida_segment.getseg(s).perm & ida_segment.SEGPERM_WRITE == 0]
    ptr_size = 8 if ida_ida.inf_is_64bit() else 4

    for seg in data_segs:
        ea = seg.start_ea
        end = seg.end_ea
        while ea < end:
            if ea % ptr_size != 0:  # Skip unaligned
                ea += 1
                continue
            count = 0
            vfuncs = []
            current = ea
            while current < end:
                ptr = ida_bytes.get_qword(current) if ptr_size == 8 else ida_bytes.get_dword(current)
                if ptr == 0 or not ida_funcs.get_func(ptr) or ida_segment.getseg(ptr).start_ea != code_seg.start_ea:  # Valid code ptr
                    break
                vfuncs.append(ptr)
                count += 1
                current += ptr_size
            if count >= 3:
                vtables[ea] = vfuncs
                ea = current  # Skip the vtable
            else:
                ea += ptr_size

    return vtables

def resolve_virtual_calls(target_ea, edges, vtables, allowed_types):
    """
    Resolves virtual calls within the function by pattern matching call [reg+offset] and mapping to vfuncs.
    """
    if 'virtual_call' not in allowed_types:
        return

    func = ida_funcs.get_func(target_ea)
    if not func:
        return

    current_item_ea = func.start_ea
    while current_item_ea < func.end_ea:
        mnem = idc.print_insn_mnem(current_item_ea)
        if mnem == 'call':
            op_type = idc.get_operand_type(current_item_ea, 0)
            if op_type == idaapi.o_displ:
                # Potential virtual call
                base_reg = idc.get_operand_value(current_item_ea, 0)  # Phrase (base)
                offset = idc.get_operand_value(current_item_ea, 1)  # Addr
                ptr_size = 8 if ida_ida.inf_is_64bit() else 4
                index = offset // ptr_size
                for vt_ea, vfuncs in vtables.items():
                    if index < len(vfuncs):
                        vfunc = vfuncs[index]
                        edges[target_ea][vfunc].add('virtual_call')
        current_item_ea = idc.next_head(current_item_ea, func.end_ea)

def taint_propagate(func_ea, taint_sources):
    """
    Simple intraprocedural taint propagation for function pointers.
    Returns set of EAs where tainted indirect calls occur.
    """
    func = idaapi.get_func(func_ea)
    tainted_heads = set()
    for head in idautils.Heads(func.start_ea, func.end_ea):
        insn = ida_ua.insn_t()
        ida_ua.decode_insn(insn, head)
        for op in insn.ops:
            if op.type == idaapi.o_mem and op.addr in taint_sources:
                tainted_heads.add(head)
            # Basic propagation: if src tainted, taint dst - for full, use more advanced DFA
    return tainted_heads

def detect_dynamic_imports(target_ea, edges):
    """
    Detects calls to GetProcAddress and tracks return to indirect calls.
    Adds resolved exports if possible.
    """
    resolver_ea = ida_name.get_name_ea(idaapi.BADADDR, "GetProcAddress")
    if resolver_ea == idaapi.BADADDR:
        return

    for xref in idautils.XrefsTo(resolver_ea, 0):
        if xref.type == ida_xref.fl_CN:  # Call
            call_ea = xref.frm
            # Assume return in rax; trace to indirect call
            # For simplicity, add placeholder; full taint needed for precision
            # Here, assume next indirect call after is the target
            next_ea = idc.next_head(call_ea)
            while next_ea < ida_funcs.get_func(call_ea).end_ea:
                mnem = idc.print_insn_mnem(next_ea)
                if mnem == 'call' and idc.get_operand_type(next_ea, 0) == idaapi.o_reg:
                    # Assume rax
                    pass
                next_ea = idc.next_head(next_ea)

def find_callees_recursive(target_ea, current_depth, max_depth, visited_eas, edges=None, vtables=None, allowed_types=None):
    """
    Recursively finds callees (direct calls) and referenced functions
    up to a specified depth using instruction analysis and cross-references.
    Handles direct calls, data references to functions (e.g., mov reg, offset func),
    immediate operands containing function addresses, and push <addr>/ret patterns.
    Enhanced with indirect call resolution via def-use, vtable/virtual calls, and jump tables.
    MUST be called from the main IDA thread (e.g., via execute_sync).
    Modifies visited_eas in place.
    If edges is provided, collects target -> callee/ref edges.
    """
    if allowed_types is None:
        allowed_types = set(['direct_call', 'indirect_call', 'data_ref', 'immediate_ref', 'tail_call_push_ret', 'virtual_call', 'jump_table'])

    # Check depth first
    if current_depth > max_depth:
        return set()

    # Check if already fully processed *before* adding again
    if target_ea in visited_eas:
        return set()

    # Mark as visited *now* before processing contents to handle recursion
    visited_eas.add(target_ea)
    # print(f"  [find_callees] Depth {current_depth}, Target: 0x{target_ea:X}") # Noisy

    callees_and_refs = set()

    func = ida_funcs.get_func(target_ea)
    if not func:
        # print(f"  [find_callees] Warning: Could not get func object for 0x{target_ea:X}")
        return callees_and_refs # Return empty set, already marked as visited

    if vtables is None:
        vtables = find_vtables()

    # Enhanced: VTable and virtual calls
    resolve_virtual_calls(target_ea, edges, vtables, allowed_types) if edges else None

    # Enhanced: Dynamic imports
    detect_dynamic_imports(target_ea, edges) if edges else None

    current_item_ea = func.start_ea
    insn = ida_ua.insn_t()
    next_insn = ida_ua.insn_t() # For push/ret lookahead

    # Get basic blocks for indirect analysis
    flowchart = ida_gdl.FlowChart(func)

    while current_item_ea < func.end_ea and current_item_ea != idaapi.BADADDR:
        insn_len = ida_ua.decode_insn(insn, current_item_ea)

        if insn_len == 0:
            next_ea = idc.next_head(current_item_ea, func.end_ea)
            if next_ea <= current_item_ea: break
            current_item_ea = next_ea
            continue

        # Enhanced: Indirect targets
        bb = next((b for b in flowchart if b.start_ea <= current_item_ea < b.end_ea), None)
        if bb and 'indirect_call' in allowed_types:
            indirect_targets = detect_indirect_target(current_item_ea, func.start_ea, bb.start_ea, bb.end_ea)
            for itgt in indirect_targets:
                if edges is not None:
                    edges[target_ea][itgt].add('indirect_call')
                if itgt not in visited_eas:
                    callees_and_refs.add(itgt)
                    recursive_results = find_callees_recursive(itgt, current_depth + 1, max_depth, visited_eas, edges=edges, vtables=vtables, allowed_types=allowed_types)
                    callees_and_refs.update(recursive_results)

        # Enhanced: Jump tables
        if 'jump_table' in allowed_types:
            jt_targets = detect_jump_tables(current_item_ea)
            for jtt in jt_targets:
                if edges is not None:
                    edges[target_ea][jtt].add('jump_table')
                if jtt not in visited_eas:
                    callees_and_refs.add(jtt)
                    recursive_results = find_callees_recursive(jtt, current_depth + 1, max_depth, visited_eas, edges=edges, vtables=vtables, allowed_types=allowed_types)
                    callees_and_refs.update(recursive_results)

        # --- Check Code References FROM ---
        cref_ea = ida_xref.get_first_cref_from(current_item_ea)
        while cref_ea != idaapi.BADADDR:
            ref_func = ida_funcs.get_func(cref_ea)
            if ref_func and ref_func.start_ea == cref_ea:
                if 'direct_call' in allowed_types:
                    if edges is not None:
                        edges[target_ea][cref_ea].add('direct_call')
                    if cref_ea not in visited_eas:
                        callees_and_refs.add(cref_ea)
                        recursive_results = find_callees_recursive(cref_ea, current_depth + 1, max_depth, visited_eas, edges=edges, vtables=vtables, allowed_types=allowed_types)
                        callees_and_refs.update(recursive_results)
            cref_ea = ida_xref.get_next_cref_from(current_item_ea, cref_ea)

        # --- Check Data References FROM ---
        dref_ea = ida_xref.get_first_dref_from(current_item_ea)
        while dref_ea != idaapi.BADADDR:
            ref_func = ida_funcs.get_func(dref_ea)
            if ref_func and ref_func.start_ea == dref_ea:
                if 'data_ref' in allowed_types:
                    if edges is not None:
                        edges[target_ea][dref_ea].add('data_ref')
                    if dref_ea not in visited_eas:
                        callees_and_refs.add(dref_ea)
                        recursive_results = find_callees_recursive(dref_ea, current_depth + 1, max_depth, visited_eas, edges=edges, vtables=vtables, allowed_types=allowed_types)
                        callees_and_refs.update(recursive_results)
            dref_ea = ida_xref.get_next_dref_from(current_item_ea, dref_ea)

        # --- Check Immediate Operands & Push/Ret Pattern ---
        is_push_imm_func = False
        pushed_func_addr = idaapi.BADADDR

        for i in range(idaapi.UA_MAXOP):
            op = insn.ops[i]
            if op.type == idaapi.o_void: break

            if op.type == idaapi.o_imm:
                imm_val = op.value
                ref_func = ida_funcs.get_func(imm_val)
                if ref_func and ref_func.start_ea == imm_val:
                    mnem = insn.get_canon_mnem()
                    added = False
                    if 'immediate_ref' in allowed_types:
                        if edges is not None:
                            edges[target_ea][imm_val].add('immediate_ref')
                        added = True
                    if mnem == "push":
                        is_push_imm_func = True
                        pushed_func_addr = imm_val
                    if is_push_imm_func:
                        # Check for 'ret' following a 'push <func_addr>'
                        next_insn_ea = current_item_ea + insn_len
                        if next_insn_ea < func.end_ea:
                            next_insn_len = ida_ua.decode_insn(next_insn, next_insn_ea)
                            if next_insn_len > 0:
                                if ida_idp.is_ret_insn(next_insn, ida_idp.IRI_RET_LITERALLY):
                                    if 'tail_call_push_ret' in allowed_types:
                                        if edges is not None:
                                            edges[target_ea][pushed_func_addr].add('tail_call_push_ret')
                                        added = True
                    if added:
                        if imm_val not in visited_eas:
                            callees_and_refs.add(imm_val)
                            recursive_results = find_callees_recursive(imm_val, current_depth + 1, max_depth, visited_eas, edges=edges, vtables=vtables, allowed_types=allowed_types)
                            callees_and_refs.update(recursive_results)

        # Advance
        next_ea = current_item_ea + insn_len
        if next_ea <= current_item_ea:
             next_ea = idc.next_head(current_item_ea, func.end_ea)
             if next_ea <= current_item_ea: break
        current_item_ea = next_ea

    return callees_and_refs


# --- Decompilation Function (MUST run in main thread) ---

def decompile_functions_main(eas_to_decompile):
    """
    Decompiles a set of function EAs.
    MUST be called from the main IDA thread (e.g., via execute_sync).
    Returns a dictionary {ea: decompiled_code_string_or_error}.
    """
    print(f"CodeDumper: [decompile_functions_main] Decompiling {len(eas_to_decompile)} functions in main thread...")
    results = {}
    total = len(eas_to_decompile)
    count = 0
    start_time = time.time()

    # Initialize Hex-Rays if not already done (safer)
    if not ida_hexrays.init_hexrays_plugin():
         print("CodeDumper Error: [decompile_functions_main] Failed to initialize Hex-Rays.")
         for func_ea in eas_to_decompile:
              func_name = ida_name.get_name(func_ea) or f"sub_{func_ea:X}"
              results[func_ea] = f"// Decompilation FAILED for {func_name} (0x{func_ea:X}) - Hex-Rays init failed"
         return results

    sorted_eas_list = sorted(list(eas_to_decompile)) # Decompile in a consistent order

    for func_ea in sorted_eas_list:
        count += 1
        func_name = ida_name.get_name(func_ea) or f"sub_{func_ea:X}"
        ida_kernwin.replace_wait_box(f"Decompiling {count}/{total}: {func_name}")
        try:
            cfunc = ida_hexrays.decompile(func_ea)
            if cfunc:
                results[func_ea] = str(cfunc)
            else:
                results[func_ea] = f"// Decompilation FAILED for {func_name} (0x{func_ea:X}) - Decompiler returned None"
                # print(f"  [decompile_main] Warning: Decompilation returned None for 0x{func_ea:X}")
        except ida_hexrays.DecompilationFailure as e:
            results[func_ea] = f"// Decompilation ERROR for {func_name} (0x{func_ea:X}): {e}"
            print(f"  [decompile_main] Error: Decompilation failed for 0x{func_ea:X}: {e}")
        except Exception as e:
            results[func_ea] = f"// Decompilation UNEXPECTED ERROR for {func_name} (0x{func_ea:X}): {e}"
            print(f"  [decompile_main] Error: Unexpected error decompiling 0x{func_ea:X}: {e}")
            traceback.print_exc()

    end_time = time.time()
    print(f"CodeDumper: [decompile_functions_main] Decompilation finished in {end_time - start_time:.2f} seconds.")
    return results

# --- Background Task Helper ---
def write_code_file(output_file_path, decompiled_results, start_func_eas, caller_depth, callee_depth, edges, max_chars=0):
    """Writes the decompiled results to the specified file, filtering xref comments to included functions."""
    print(f"CodeDumper: [write_code_file] Writing {len(decompiled_results)} functions to {output_file_path}...")
    num_funcs_written = 0
    try:
        name_map_container = [{}]
        eas_to_get_names = list(decompiled_results.keys())

        def get_names_main(eas, container):
            names = {}
            for ea in eas:
                names[ea] = ida_funcs.get_func_name(ea) or f"sub_{ea:X}"
            container[0] = names
            return 1

        sync_status = ida_kernwin.execute_sync(
            lambda: get_names_main(eas_to_get_names, name_map_container),
            ida_kernwin.MFF_READ
        )
        name_map = name_map_container[0] if sync_status == 1 else {ea: f"sub_{ea:X}" for ea in eas_to_get_names}
        if sync_status != 1:
            print("CodeDumper Warning: [write_code_file] Failed to get function names. Using defaults.")

        # Collect all nodes
        all_nodes = set(decompiled_results.keys())

        # Sort all potential functions by out-degree ascending for a consistent initial order
        out_degrees = [(len(edges[ea]), ea) for ea in all_nodes]
        sorted_out_degrees = sorted(out_degrees, key=lambda x: (x[0], x[1]))
        sorted_eas = [t[1] for t in sorted_out_degrees]

        # --- Pruning Logic (if max_chars is set) ---
        included_eas = set(all_nodes)
        removed_eas = set()
        if max_chars > 0:
            # Build temporary function blocks with UNFILTERED xrefs for accurate size calculation
            func_blocks_for_sizing = []
            for func_ea in sorted_eas:
                func_name = name_map.get(func_ea, f"sub_{func_ea:X}")
                incoming = [fr for fr in edges if func_ea in edges[fr]]
                incoming_line = f"// Incoming xrefs for {func_name} (0x{func_ea:X}): {len(incoming)} refs\n"
                outgoing = edges[func_ea]
                outgoing_line = f"// Outgoing xrefs for {func_name} (0x{func_ea:X}): {len(outgoing)} refs\n"
                code_or_error = decompiled_results[func_ea]
                block_str = ''.join([incoming_line, outgoing_line, f"// --- Function: {func_name}...\n", code_or_error, "\n// --- End Function...\n\n"])
                func_blocks_for_sizing.append({
                    'ea': func_ea,
                    'block_size': len(block_str),
                    'code_len': len(code_or_error) # For sorting removable items
                })

            current_size = sum(d['block_size'] for d in func_blocks_for_sizing)
            if current_size > max_chars:
                removable = [d for d in func_blocks_for_sizing if d['ea'] not in start_func_eas]
                removable.sort(key=lambda d: d['code_len']) # Sort smallest first

                while current_size > max_chars and removable:
                    to_remove = removable.pop(0)
                    included_eas.remove(to_remove['ea'])
                    removed_eas.add(to_remove['ea'])
                    current_size -= to_remove['block_size']

                if current_size > max_chars:
                    print(f"CodeDumper Warning: [write_code_file] Could not reduce size below {max_chars} even after removing all non-start functions.")

        # --- Build Final Output ---
        # Use the original sorted order, but only for functions that are still included
        sorted_included_eas = [ea for ea in sorted_eas if ea in included_eas]

        # Build header
        header_lines = []
        header_lines.append(f"// Decompiled code dump generated by {PLUGIN_NAME}\n")
        if len(start_func_eas) == 1:
            start_ea = list(start_func_eas)[0]
            header_lines.append(f"// Start Function: 0x{start_ea:X} ({name_map.get(start_ea, '')})\n")
        else:
            header_lines.append("// Start Functions:\n")
            for start_ea in sorted(list(start_func_eas)):
                header_lines.append(f"//   - 0x{start_ea:X} ({name_map.get(start_ea, '')})\n")

        header_lines.append(f"// Caller Depth: {caller_depth}\n")
        header_lines.append(f"// Callee/Ref Depth: {callee_depth}\n")
        if max_chars > 0:
            header_lines.append(f"// Max Characters: {max_chars}\n")
        header_lines.append(f"// Total Functions Found: {len(all_nodes)}\n")
        header_lines.append(f"// Included Functions ({len(included_eas)}):\n")
        for func_ea in sorted_included_eas:
            func_name = name_map.get(func_ea, f"sub_{func_ea:X}")
            header_lines.append(f"//   - {func_name} (0x{func_ea:X})\n")
        if removed_eas:
            header_lines.append(f"// Removed Functions ({len(removed_eas)}):\n")
            for func_ea in sorted(removed_eas):
                func_name = name_map.get(func_ea, f"sub_{func_ea:X}")
                header_lines.append(f"//   - {func_name} (0x{func_ea:X})\n")
        else:
            header_lines.append(f"// Removed Functions: None\n")
        header_lines.append(f"// {'-'*60}\n\n")
        header = ''.join(header_lines)

        # Build final content blocks with FILTERED xrefs
        final_content_blocks = []
        for func_ea in sorted_included_eas:
            func_name = name_map.get(func_ea, f"sub_{func_ea:X}")

            # Incoming xrefs (callers) - FILTERED against included_eas
            all_incoming = [fr for fr in edges if func_ea in edges[fr]]
            filtered_incoming = [fr for fr in all_incoming if fr in included_eas]
            incoming_strs = []
            for fr in sorted(filtered_incoming):
                reasons = sorted(edges[fr][func_ea])
                reason_str = '/'.join(reasons)
                incoming_strs.append(f"{name_map.get(fr, f'sub_{fr:X}')} (0x{fr:X}) [{reason_str}]")
            incoming_line = f"// Incoming xrefs for {func_name} (0x{func_ea:X}): {', '.join(incoming_strs) or 'None'}\n"

            # Outgoing xrefs (callees/refs) - FILTERED against included_eas
            all_outgoing = edges[func_ea]
            filtered_outgoing = {to: reasons for to, reasons in all_outgoing.items() if to in included_eas}
            outgoing_strs = []
            for to in sorted(filtered_outgoing):
                reasons = sorted(filtered_outgoing[to])
                reason_str = '/'.join(reasons)
                outgoing_strs.append(f"{name_map.get(to, f'sub_{to:X}')} (0x{to:X}) [{reason_str}]")
            outgoing_line = f"// Outgoing xrefs for {func_name} (0x{func_ea:X}): {', '.join(outgoing_strs) or 'None'}\n"

            code_or_error = decompiled_results[func_ea]

            block = [
                incoming_line,
                outgoing_line,
                f"// --- Function: {func_name} (0x{func_ea:X}) ---\n",
                code_or_error + "\n",
                f"// --- End Function: {func_name} (0x{func_ea:X}) ---\n\n"
            ]
            final_content_blocks.append(''.join(block))

        # Final content assembly
        content = header + ''.join(final_content_blocks)

        with open(output_file_path, "w", encoding="utf-8") as f:
            f.write(content)

        num_funcs_written = len(included_eas)
        print(f"CodeDumper: [write_code_file] Successfully wrote dump file: {output_file_path}")
        return num_funcs_written

    except Exception as e:
        print(f"CodeDumper Error: [write_code_file] Failed to write output file: {e}")
        traceback.print_exc()
        error_msg = f"{PLUGIN_NAME}: Error writing dump file:\n{e}"
        ida_kernwin.execute_ui_requests([lambda msg=error_msg: ida_kernwin.warning(msg)])
        return 0

def get_edge_style(reasons_set):
    """Determines the best edge style based on a priority of reasons."""
    if 'virtual_call' in reasons_set:
        return "bold"
    if 'direct_call' in reasons_set:
        return "solid"
    if 'tail_call_push_ret' in reasons_set:
        return "dashed,bold"
    if 'indirect_call' in reasons_set or 'jump_table' in reasons_set:
        return "dashed"
    if 'data_ref' in reasons_set or 'immediate_ref' in reasons_set:
        return "dotted"
    return "dotted" # Default fallback

def write_dot_file(output_file_path, edges, all_nodes, start_func_eas, caller_depth, callee_depth):
    """Writes the graph to a DOT file using an ortho layout and styled edges."""
    print(f"CodeDumper: [write_dot_file] Writing graph with {len(all_nodes)} nodes to {output_file_path}...")
    num_nodes_written = 0
    try:
        name_map = {}
        name_map_container = [{}]
        eas_to_get_names = list(all_nodes)

        def get_names_main(eas, container):
            names = {}
            for ea in eas:
                names[ea] = ida_funcs.get_func_name(ea) or f"sub_{ea:X}"
            container[0] = names
            return 1

        sync_status = ida_kernwin.execute_sync(
            lambda: get_names_main(eas_to_get_names, name_map_container),
            ida_kernwin.MFF_READ
        )
        if sync_status == 1:
            name_map = name_map_container[0]
        else:
            print("CodeDumper Warning: [write_dot_file] Failed to get function names. Using defaults.")
            for ea in eas_to_get_names:
                name_map[ea] = f"sub_{ea:X}"

        with open(output_file_path, "w", encoding="utf-8") as f:
            f.write(f"# DOT graph generated by {PLUGIN_NAME}\n")
            if len(start_func_eas) == 1:
                 start_ea = list(start_func_eas)[0]
                 f.write(f"# Start Function: 0x{start_ea:X} ({name_map.get(start_ea, '')})\n")
            else:
                 f.write("# Start Functions:\n")
                 for start_ea in sorted(list(start_func_eas)):
                      f.write(f"#   - 0x{start_ea:X} ({name_map.get(start_ea, '')})\n")

            f.write(f"# Caller Depth: {caller_depth}\n")
            f.write(f"# Callee/Ref Depth: {callee_depth}\n")
            f.write(f"# Total Nodes: {len(all_nodes)}\n")
            f.write("#\n# --- Legend ---\n")
            f.write("# Solid Line: Direct Call\n")
            f.write("# Bold Line: Virtual Call\n")
            f.write("# Dashed Line: Indirect Call / Jump Table\n")
            f.write("# Bold Dashed Line: Tail Call (push/ret)\n")
            f.write("# Dotted Line: Data / Immediate Reference\n")
            f.write(f"# {'-'*60}\n\n")

            f.write("digraph CallGraph {\n")
            f.write("    graph [splines=ortho];\n")
            f.write("    node [shape=box, style=filled, fillcolor=lightblue];\n")
            f.write("    edge [color=gray50];\n")

            # Nodes
            sorted_nodes = sorted(list(all_nodes))
            for ea in sorted_nodes:
                name = name_map[ea]
                if len(name) > 40:
                    name = name[:37] + "..."
                label = f"{name}\\n(0x{ea:X})"

                fillcolor = "fillcolor=red" if ea in start_func_eas else ""
                f.write(f"    \"0x{ea:X}\" [label=\"{label}\" {fillcolor}];\n")

            # Edges - Filtered to only include connections between nodes in the graph
            for from_ea in sorted_nodes:
                if from_ea in edges:
                    for to_ea in sorted(edges[from_ea]):
                        if to_ea in all_nodes:  # Ensure the target node is also part of the collected set
                            reasons_set = edges[from_ea][to_ea]
                            style = get_edge_style(reasons_set)
                            tooltip_str = '/'.join(sorted(reasons_set))
                            f.write(f"    \"0x{from_ea:X}\" -> \"0x{to_ea:X}\" [style={style}, tooltip=\"{tooltip_str}\"];\n")

            f.write("}\n")

        num_nodes_written = len(all_nodes)
        print(f"CodeDumper: [write_dot_file] Successfully wrote DOT file: {output_file_path}")
        return num_nodes_written

    except Exception as e:
        print(f"CodeDumper Error: [write_dot_file] Failed to write DOT file: {e}")
        traceback.print_exc()
        error_msg = f"{PLUGIN_NAME}: Error writing DOT file:\n{e}"
        ida_kernwin.execute_ui_requests([lambda msg=error_msg: ida_kernwin.warning(msg)])
        return 0

# --- Unified Background Task ---

def dump_task(start_func_eas, caller_depth, callee_depth, output_file_path, mode='code', xref_types=None, max_chars=0):
    """
    Unified background task for dumping code or generating DOT graphs for single or multiple starting functions.
    Orchestrates finding functions/edges, decompiling (if code), and writing the file.
    Uses execute_sync/execute_ui_requests for IDA API calls and UI.
    mode: 'code' or 'graph'
    """
    if xref_types is None:
        xref_types = set(['direct_call', 'indirect_call', 'data_ref', 'immediate_ref', 'tail_call_push_ret', 'virtual_call', 'jump_table'])

    global g_multi_dump_active, g_dump_in_progress # Not used directly here, but for consistency

    # --- Get Start Function Names (Main Thread) ---
    start_func_names = []
    start_names_container = [[]]

    def get_start_names_main(eas, container):
        names = []
        for ea in eas:
            name = ida_funcs.get_func_name(ea) or f"sub_{ea:X}"
            names.append(f"{name}(0x{ea:X})")
        container[0] = names
        return 1

    sync_status = ida_kernwin.execute_sync(
        lambda: get_start_names_main(start_func_eas, start_names_container),
        ida_kernwin.MFF_READ
    )

    if sync_status == 1:
        start_func_names = start_names_container[0]
        start_desc = ", ".join(start_func_names)
        print(f"CodeDumper: [dump_task] Background task started for {len(start_func_eas)} functions in mode '{mode}': {start_desc}")
    else:
        print(f"CodeDumper Warning: [dump_task] Failed to get start function names. Proceeding anyway.")
        print(f"CodeDumper: [dump_task] Background task started for {len(start_func_eas)} functions in mode '{mode}'.")

    print(f"  Callers: {caller_depth}, Callees/Refs: {callee_depth}, Output file: {output_file_path}")
    print(f"  Xref Types: {', '.join(sorted(xref_types))}")
    print(f"  Max Chars: {max_chars}")

    try:
        all_nodes = set(start_func_eas)
        edges = defaultdict(lambda: defaultdict(set))

        ida_kernwin.execute_ui_requests([lambda: ida_kernwin.show_wait_box(f"Finding callers/callees/refs for {len(start_func_eas)} functions...")])

        # --- Find Callers (Main Thread) ---
        visited_callers = set()
        if caller_depth > 0:
            caller_result_container = [set()]
            visited_caller_container = [set()]

            def run_find_multi_callers_main(container, visited_set_container, edges, allowed_types):
                combined_callers = set()
                try:
                    for start_ea in start_func_eas:
                        found = find_callers_recursive(start_ea, 1, caller_depth, visited_set_container[0], edges=edges, allowed_types=allowed_types)
                        combined_callers.update(found)
                    container[0] = combined_callers
                    return 1
                except Exception as e:
                    print(f"  [run_find_multi_callers_main] Error: {e}")
                    traceback.print_exc()
                    container[0] = set()
                    return 0

            sync_status = ida_kernwin.execute_sync(
                lambda: run_find_multi_callers_main(caller_result_container, visited_caller_container, edges, xref_types),
                ida_kernwin.MFF_READ
            )

            if sync_status == 1:
                total_caller_eas = caller_result_container[0]
                visited_callers = visited_caller_container[0]
                all_nodes |= visited_callers
                all_nodes.update(total_caller_eas)
                print(f"CodeDumper: [dump_task] Found {len(total_caller_eas)} total unique callers.")
            else:
                print("CodeDumper Error: [dump_task] Failed to find callers in main thread.")
                ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])
                ida_kernwin.warning(f"{PLUGIN_NAME}: Failed to find callers.")
                return

        # --- Find Callees and Referenced Functions (Main Thread) ---
        visited_callees = set()
        if callee_depth > 0:
            callee_result_container = [set()]
            visited_callee_container = [set()]

            def run_find_multi_callees_main(container, visited_set_container, edges, allowed_types):
                combined_callees = set()
                try:
                    vtables = find_vtables()
                    for start_ea in start_func_eas:
                        found = find_callees_recursive(start_ea, 1, callee_depth, visited_set_container[0], edges=edges, vtables=vtables, allowed_types=allowed_types)
                        combined_callees.update(found)
                    container[0] = combined_callees
                    return 1
                except Exception as e:
                    print(f"  [run_find_multi_callees_main] Error: {e}")
                    traceback.print_exc()
                    container[0] = set()
                    return 0

            sync_status = ida_kernwin.execute_sync(
                lambda: run_find_multi_callees_main(callee_result_container, visited_callee_container, edges, xref_types),
                ida_kernwin.MFF_READ
            )

            if sync_status == 1:
                total_callee_ref_eas = callee_result_container[0]
                visited_callees = visited_callee_container[0]
                all_nodes |= visited_callees
                all_nodes.update(total_callee_ref_eas)
                print(f"CodeDumper: [dump_task] Found {len(total_callee_ref_eas)} total unique callees/refs.")
            else:
                print("CodeDumper Error: [dump_task] Failed to find callees/refs in main thread.")
                ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])
                ida_kernwin.warning(f"{PLUGIN_NAME}: Failed to find callees/refs.")
                return

        total_nodes = len(all_nodes)
        print(f"CodeDumper: [dump_task] Total unique nodes/functions: {total_nodes}")
        if total_nodes == 0:
            print("CodeDumper: [dump_task] No functions/nodes found.")
            ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])
            ida_kernwin.warning(f"{PLUGIN_NAME}: No functions/nodes found.")
            return

        if mode == 'code':
            # --- Decompile Functions (Main Thread) ---
            decompiled_results = {}
            decomp_result_container = [{}]

            def run_decompile_main(container):
                try:
                    container[0] = decompile_functions_main(all_nodes)
                    return 1
                except Exception as e:
                    print(f"  [run_decompile_main] Error: {e}")
                    traceback.print_exc()
                    container[0] = {}
                    return 0

            sync_status = ida_kernwin.execute_sync(
                lambda: run_decompile_main(decomp_result_container),
                ida_kernwin.MFF_WRITE
            )

            if sync_status == 1:
                decompiled_results = decomp_result_container[0]
                print(f"CodeDumper: [dump_task] Decompilation finished. Received {len(decompiled_results)} results.")
                if len(decompiled_results) != total_nodes:
                     print(f"CodeDumper Warning: [dump_task] Mismatch between expected ({total_nodes}) and decompiled ({len(decompiled_results)}).")
            else:
                print("CodeDumper Error: [dump_task] Failed to decompile functions in main thread.")
                ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])
                ida_kernwin.warning(f"{PLUGIN_NAME}: Failed during decompilation.")
                return

            ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])

            # --- Write to File (Background Thread) ---
            num_written = write_code_file(
                output_file_path,
                decompiled_results,
                start_func_eas,
                caller_depth,
                callee_depth,
                edges,
                max_chars=max_chars
            )
        elif mode == 'graph':
            ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])

            # --- Write to File (Background Thread) ---
            num_written = write_dot_file(
                output_file_path,
                edges,
                all_nodes,
                start_func_eas,
                caller_depth,
                callee_depth
            )

        if num_written > 0:
            type_str = "functions" if mode == 'code' else "nodes"
            final_message = f"{PLUGIN_NAME}: Successfully dumped {num_written} {type_str} (from {len(start_func_eas)} starting points) to:\n{output_file_path}"
            def show_final_info_sync(msg):
                ida_kernwin.info(msg)
                return 1
            ida_kernwin.execute_sync(lambda msg=final_message: show_final_info_sync(msg), ida_kernwin.MFF_WRITE)

    except Exception as e:
        print(f"CodeDumper Error: [dump_task] Unexpected error in background task: {e}")
        traceback.print_exc()
        ida_kernwin.execute_ui_requests([lambda: ida_kernwin.warning(f"{PLUGIN_NAME}: An unexpected error occurred.")])
        ida_kernwin.execute_ui_requests([ida_kernwin.hide_wait_box])

    finally:
        with g_dump_lock:
            if len(start_func_eas) == 1:
                g_dump_in_progress.discard(list(start_func_eas)[0])
            else:
                g_multi_dump_active = False
        print(f"CodeDumper: [dump_task] Background task finished.")


# --- IDA Plugin Integration ---

class DumpCtxActionHandler(ida_kernwin.action_handler_t):
    """Handles the activation of the context menu action for code dump."""
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        global g_dump_in_progress, g_multi_dump_active
        widget = ctx.widget
        widget_type = ida_kernwin.get_widget_type(widget)

        if widget_type != ida_kernwin.BWN_PSEUDOCODE:
            return 1

        vu = ida_hexrays.get_widget_vdui(widget)
        if not vu or not vu.cfunc:
            print("CodeDumper Error: [activate Ctx] Could not get vdui or cfunc.")
            ida_kernwin.warning(f"{PLUGIN_NAME}: Decompilation not available for this function.")
            return 1

        start_func_ea = vu.cfunc.entry_ea
        start_func_ea_str = f"0x{start_func_ea:X}"
        start_func_name = ida_funcs.get_func_name(start_func_ea) or f"sub_{start_func_ea_str}"

        with g_dump_lock:
            if start_func_ea in g_dump_in_progress:
                ida_kernwin.warning(f"{PLUGIN_NAME}: Dump already running for {start_func_name}. Please wait.")
                return 1
            if g_multi_dump_active:
                ida_kernwin.warning(f"{PLUGIN_NAME}: A multi-function dump is currently running. Please wait.")
                return 1
            g_dump_in_progress.add(start_func_ea)

        # --- Get User Input (Main Thread via execute_sync) ---
        input_results = {"caller_depth": -1, "callee_depth": -1, "output_file": None, "xref_types": None, "max_chars": 0}
        input_container = [input_results]

        def get_inputs_main(container):
            try:
                c_depth = ida_kernwin.ask_long(0, "Enter Caller Depth (e.g., 0, 1, 2)")
                if c_depth is None:
                    return 0
                container[0]["caller_depth"] = int(c_depth) if c_depth >= 0 else 0

                ca_depth = ida_kernwin.ask_long(1, "Enter Callee/Ref Depth (e.g., 0, 1, 2)")
                if ca_depth is None:
                    return 0
                container[0]["callee_depth"] = int(ca_depth) if ca_depth >= 0 else 0

                xref_types_str = ida_kernwin.ask_str("all", 0, "Enter comma-separated xref types to include (or 'all'):\ndirect_call,indirect_call,data_ref,immediate_ref,tail_call_push_ret,virtual_call,jump_table")
                if xref_types_str is None:
                    return 0
                if xref_types_str.strip().lower() == 'all':
                    container[0]["xref_types"] = set(['direct_call', 'indirect_call', 'data_ref', 'immediate_ref', 'tail_call_push_ret', 'virtual_call', 'jump_table'])
                else:
                    container[0]["xref_types"] = set([t.strip() for t in xref_types_str.split(',') if t.strip()])

                m_chars = ida_kernwin.ask_long(0, "Enter maximum characters for the output file (0 for no limit)")
                if m_chars is None:
                    return 0
                container[0]["max_chars"] = int(m_chars) if m_chars >= 0 else 0

                default_filename = f"{start_func_name}_dump_callers{c_depth}_callees{ca_depth}.c"
                default_filename = re.sub(r'[<>:"/\\|?*]', '_', default_filename)
                output_file = ida_kernwin.ask_file(True, default_filename, "Select Output C File")
                if not output_file:
                    return 0
                container[0]["output_file"] = output_file
                return 1
            except Exception as e:
                print(f"  [get_inputs_main Ctx] Error: {e}")
                traceback.print_exc()
                return -1

        sync_status = ida_kernwin.execute_sync(
            lambda: get_inputs_main(input_container),
            ida_kernwin.MFF_WRITE
        )

        final_inputs = input_container[0]
        caller_depth = final_inputs["caller_depth"]
        callee_depth = final_inputs["callee_depth"]
        output_file_path = final_inputs["output_file"]
        xref_types = final_inputs["xref_types"]
        max_chars = final_inputs["max_chars"]

        if sync_status != 1 or caller_depth < 0 or callee_depth < 0 or not output_file_path or not xref_types:
            with g_dump_lock:
                g_dump_in_progress.discard(start_func_ea)
            return 1

        # --- Start Background Task ---
        task_thread = threading.Thread(
            target=dump_task,
            args=(set([start_func_ea]), caller_depth, callee_depth, output_file_path, 'code', xref_types, max_chars)
        )
        task_thread.start()

        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            vu = ida_hexrays.get_widget_vdui(ctx.widget)
            if vu and vu.cfunc:
                return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

class DumpDotCtxActionHandler(ida_kernwin.action_handler_t):
    """Handles the activation of the context menu action for DOT graph."""
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        global g_dump_in_progress, g_multi_dump_active
        widget = ctx.widget
        widget_type = ida_kernwin.get_widget_type(widget)

        if widget_type != ida_kernwin.BWN_PSEUDOCODE:
            return 1

        vu = ida_hexrays.get_widget_vdui(widget)
        if not vu or not vu.cfunc:
            print("CodeDumper Error: [activate Dot Ctx] Could not get vdui or cfunc.")
            ida_kernwin.warning(f"{PLUGIN_NAME}: Not available for this function.")
            return 1

        start_func_ea = vu.cfunc.entry_ea
        start_func_ea_str = f"0x{start_func_ea:X}"
        start_func_name = ida_funcs.get_func_name(start_func_ea) or f"sub_{start_func_ea_str}"

        with g_dump_lock:
            if start_func_ea in g_dump_in_progress:
                ida_kernwin.warning(f"{PLUGIN_NAME}: Operation already running for {start_func_name}. Please wait.")
                return 1
            if g_multi_dump_active:
                ida_kernwin.warning(f"{PLUGIN_NAME}: A multi-function operation is currently running. Please wait.")
                return 1
            g_dump_in_progress.add(start_func_ea)

        # --- Get User Input (Main Thread via execute_sync) ---
        input_results = {"caller_depth": -1, "callee_depth": -1, "output_file": None, "xref_types": None, "max_chars": 0}
        input_container = [input_results]

        def get_inputs_main(container):
            try:
                c_depth = ida_kernwin.ask_long(0, "Enter Caller Depth (e.g., 0, 1, 2)")
                if c_depth is None:
                    return 0
                container[0]["caller_depth"] = int(c_depth) if c_depth >= 0 else 0

                ca_depth = ida_kernwin.ask_long(1, "Enter Callee/Ref Depth (e.g., 0, 1, 2)")
                if ca_depth is None:
                    return 0
                container[0]["callee_depth"] = int(ca_depth) if ca_depth >= 0 else 0

                xref_types_str = ida_kernwin.ask_str("all", 0, "Enter comma-separated xref types to include (or 'all'):\ndirect_call,indirect_call,data_ref,immediate_ref,tail_call_push_ret,virtual_call,jump_table")
                if xref_types_str is None:
                    return 0
                if xref_types_str.strip().lower() == 'all':
                    container[0]["xref_types"] = set(['direct_call', 'indirect_call', 'data_ref', 'immediate_ref', 'tail_call_push_ret', 'virtual_call', 'jump_table'])
                else:
                    container[0]["xref_types"] = set([t.strip() for t in xref_types_str.split(',') if t.strip()])

                m_chars = ida_kernwin.ask_long(0, "Enter maximum characters for the output file (0 for no limit)")
                if m_chars is None:
                    return 0
                container[0]["max_chars"] = int(m_chars) if m_chars >= 0 else 0

                default_filename = f"{start_func_name}_graph_callers{c_depth}_callees{ca_depth}.dot"
                default_filename = re.sub(r'[<>:"/\\|?*]', '_', default_filename)
                output_file = ida_kernwin.ask_file(True, default_filename, "Select Output DOT File")
                if not output_file:
                    return 0
                container[0]["output_file"] = output_file
                return 1
            except Exception as e:
                print(f"  [get_inputs_main Dot Ctx] Error: {e}")
                traceback.print_exc()
                return -1

        sync_status = ida_kernwin.execute_sync(
            lambda: get_inputs_main(input_container),
            ida_kernwin.MFF_WRITE
        )

        final_inputs = input_container[0]
        caller_depth = final_inputs["caller_depth"]
        callee_depth = final_inputs["callee_depth"]
        output_file_path = final_inputs["output_file"]
        xref_types = final_inputs["xref_types"]
        max_chars = final_inputs["max_chars"]

        if sync_status != 1 or caller_depth < 0 or callee_depth < 0 or not output_file_path or not xref_types:
            with g_dump_lock:
                g_dump_in_progress.discard(start_func_ea)
            return 1

        # --- Start Background Task ---
        task_thread = threading.Thread(
            target=dump_task,
            args=(set([start_func_ea]), caller_depth, callee_depth, output_file_path, 'graph', xref_types, max_chars)
        )
        task_thread.start()

        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            vu = ida_hexrays.get_widget_vdui(ctx.widget)
            if vu and vu.cfunc:
                return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

def perform_multi_dump(mode):
    global g_dump_in_progress, g_multi_dump_active
    with g_dump_lock:
        if g_multi_dump_active:
            ida_kernwin.warning(f"{PLUGIN_NAME}: A multi-function operation is already running. Please wait.")
            return
        if g_dump_in_progress:
            ida_kernwin.warning(f"{PLUGIN_NAME}: One or more single function operations are running. Please wait.")
            return
        g_multi_dump_active = True

    # --- Get User Input (Main Thread via execute_sync) ---
    input_results = {"start_eas": set(), "caller_depth": -1, "callee_depth": -1, "output_file": None, "xref_types": None, "max_chars": 0}
    input_container = [input_results]

    def get_multi_inputs_main(container, mode):
        try:
            func_list_str = ida_kernwin.ask_str("", 0, "Enter comma-separated function names or addresses (e.g., sub_123, 0x401000, MyFunc)")
            if not func_list_str:
                return 0

            start_eas = set()
            unresolved = []
            items = [item.strip() for item in func_list_str.split(',') if item.strip()]
            if not items:
                ida_kernwin.warning(f"{PLUGIN_NAME}: No function names or addresses provided.")
                return 0

            for item in items:
                ea = idaapi.BADADDR
                if item.lower().startswith("0x"):
                    try:
                        ea = int(item, 16)
                    except ValueError:
                        pass
                elif item.isdigit():
                    try:
                        ea = int(item)
                    except ValueError:
                        pass

                if ea == idaapi.BADADDR:
                    ea = ida_name.get_name_ea(idaapi.BADADDR, item)

                if ea != idaapi.BADADDR and ida_funcs.get_func(ea):
                    start_eas.add(ea)
                else:
                    unresolved.append(item)

            if unresolved:
                ida_kernwin.warning(f"{PLUGIN_NAME}: Could not resolve or find functions for:\n" + "\n".join(unresolved))

            if not start_eas:
                ida_kernwin.warning(f"{PLUGIN_NAME}: No valid functions found from the provided list.")
                return 0

            container[0]["start_eas"] = start_eas

            c_depth = ida_kernwin.ask_long(0, "Enter Caller Depth (e.g., 0, 1, 2)")
            if c_depth is None: return 0
            container[0]["caller_depth"] = int(c_depth) if c_depth >= 0 else 0

            ca_depth = ida_kernwin.ask_long(1, "Enter Callee/Ref Depth (e.g., 0, 1, 2)")
            if ca_depth is None: return 0
            container[0]["callee_depth"] = int(ca_depth) if ca_depth >= 0 else 0

            xref_types_str = ida_kernwin.ask_str("all", 0, "Enter comma-separated xref types to include (or 'all'):\ndirect_call,indirect_call,data_ref,immediate_ref,tail_call_push_ret,virtual_call,jump_table")
            if xref_types_str is None:
                return 0
            if xref_types_str.strip().lower() == 'all':
                container[0]["xref_types"] = set(['direct_call', 'indirect_call', 'data_ref', 'immediate_ref', 'tail_call_push_ret', 'virtual_call', 'jump_table'])
            else:
                container[0]["xref_types"] = set([t.strip() for t in xref_types_str.split(',') if t.strip()])

            m_chars = ida_kernwin.ask_long(0, "Enter maximum characters for the output file (0 for no limit)")
            if m_chars is None:
                return 0
            container[0]["max_chars"] = int(m_chars) if m_chars >= 0 else 0

            first_func_ea = sorted(list(start_eas))[0]
            first_func_name = ida_funcs.get_func_name(first_func_ea) or f"sub_{first_func_ea:X}"
            if mode == 'code':
                default_filename = f"multi_dump_{first_func_name}_etc_callers{c_depth}_callees{ca_depth}.c"
                title = "Select Output C File"
            else:
                default_filename = f"multi_graph_{first_func_name}_etc_callers{c_depth}_callees{ca_depth}.dot"
                title = "Select Output DOT File"
            default_filename = re.sub(r'[<>:"/\\|?*]', '_', default_filename)
            output_file = ida_kernwin.ask_file(True, default_filename, title)
            if not output_file: return 0
            container[0]["output_file"] = output_file
            return 1
        except Exception as e:
            print(f"  [get_multi_inputs_main] Error: {e}")
            traceback.print_exc()
            return -1

    sync_status = ida_kernwin.execute_sync(
        lambda: get_multi_inputs_main(input_container, mode),
        ida_kernwin.MFF_WRITE
    )

    final_inputs = input_container[0]
    start_eas = final_inputs["start_eas"]
    caller_depth = final_inputs["caller_depth"]
    callee_depth = final_inputs["callee_depth"]
    output_file_path = final_inputs["output_file"]
    xref_types = final_inputs["xref_types"]
    max_chars = final_inputs["max_chars"]

    if sync_status != 1 or not start_eas or caller_depth < 0 or callee_depth < 0 or not output_file_path or not xref_types:
        with g_dump_lock:
            g_multi_dump_active = False
        return

    # --- Start Background Task ---
    task_thread = threading.Thread(
        target=dump_task,
        args=(start_eas, caller_depth, callee_depth, output_file_path, mode, xref_types, max_chars)
    )
    task_thread.start()


class DumpCodeMultiActionHandler(ida_kernwin.action_handler_t):
    """Handles the activation of the multi-function code dump action."""
    def activate(self, ctx):
        perform_multi_dump('code')
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class DumpDotMultiActionHandler(ida_kernwin.action_handler_t):
    """Handles the activation of the multi-function DOT graph action."""
    def activate(self, ctx):
        perform_multi_dump('graph')
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class DumpHooks(ida_kernwin.UI_Hooks):
    """Hooks into IDA's UI to add context menu items."""
    def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
        """Adds menu items to the widget's context menu."""
        widget_type = ida_kernwin.get_widget_type(widget)
        if widget_type == ida_kernwin.BWN_PSEUDOCODE:
            try:
                ida_kernwin.attach_action_to_popup(
                    widget, popup_handle, ACTION_ID_CTX, MENU_PATH_CTX, ida_kernwin.SETMENU_INS
                )
                ida_kernwin.attach_action_to_popup(
                    widget, popup_handle, ACTION_ID_DOT_CTX, MENU_PATH_CTX, ida_kernwin.SETMENU_INS
                )
            except Exception as e:
                print(f"CodeDumper Error: [Hooks] Exception attaching context actions to popup: {e}")
                traceback.print_exc()


class CodeDumperPlugin(idaapi.plugin_t):
    """The main IDA Pro plugin class."""
    # We no longer use PLUGIN_HIDE. The plugin's menu entry will now
    # act as the container for our multi-dump actions.
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_FIX
    comment = "Dumps decompiled code or generates DOT graphs for function(s) and their callers/callees/references"
    help = "Use the actions within this plugin's submenu (Edit->Plugins->...) or right-click in Pseudocode view"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    hooks = None

    def init(self):
        print("-" * 60)
        print(f"CodeDumper: {self.wanted_name} plugin initializing...")

        # ... (the rest of the init function is IDENTICAL to your last version, no changes needed there)
        # It correctly uses MENU_PATH_MULTI which we've now redefined.

        if not ida_hexrays.init_hexrays_plugin():
            print("CodeDumper Error: [init] Hex-Rays decompiler is not available.")
            print("-" * 60)
            return idaapi.PLUGIN_SKIP
        print("CodeDumper: [init] Hex-Rays initialized.")

        # Register Context Actions
        action_desc_ctx = ida_kernwin.action_desc_t(
            ACTION_ID_CTX, ACTION_LABEL_CTX, DumpCtxActionHandler(), self.wanted_hotkey, ACTION_TOOLTIP_CTX, 199
        )
        if not ida_kernwin.register_action(action_desc_ctx):
            print(f"CodeDumper Error: [init] Failed to register action '{ACTION_ID_CTX}'.")
            print("-" * 60)
            return idaapi.PLUGIN_SKIP

        action_desc_dot_ctx = ida_kernwin.action_desc_t(
            ACTION_ID_DOT_CTX, ACTION_LABEL_DOT_CTX, DumpDotCtxActionHandler(), self.wanted_hotkey, ACTION_TOOLTIP_DOT_CTX, 199
        )
        if not ida_kernwin.register_action(action_desc_dot_ctx):
            print(f"CodeDumper Error: [init] Failed to register action '{ACTION_ID_DOT_CTX}'.")
            ida_kernwin.unregister_action(ACTION_ID_CTX)
            print("-" * 60)
            return idaapi.PLUGIN_SKIP

        # Register Multi-Function Actions
        action_desc_code_multi = ida_kernwin.action_desc_t(
            ACTION_ID_CODE_MULTI, ACTION_LABEL_CODE_MULTI, DumpCodeMultiActionHandler(), None, ACTION_TOOLTIP_CODE_MULTI, 199
        )
        if not ida_kernwin.register_action(action_desc_code_multi):
            print(f"CodeDumper Error: [init] Failed to register action '{ACTION_ID_CODE_MULTI}'.")
            ida_kernwin.unregister_action(ACTION_ID_CTX)
            ida_kernwin.unregister_action(ACTION_ID_DOT_CTX)
            print("-" * 60)
            return idaapi.PLUGIN_SKIP

        action_desc_dot_multi = ida_kernwin.action_desc_t(
            ACTION_ID_DOT_MULTI, ACTION_LABEL_DOT_MULTI, DumpDotMultiActionHandler(), None, ACTION_TOOLTIP_DOT_MULTI, 199
        )
        if not ida_kernwin.register_action(action_desc_dot_multi):
            print(f"CodeDumper Error: [init] Failed to register action '{ACTION_ID_DOT_MULTI}'.")
            ida_kernwin.unregister_action(ACTION_ID_CTX)
            ida_kernwin.unregister_action(ACTION_ID_DOT_CTX)
            ida_kernwin.unregister_action(ACTION_ID_CODE_MULTI)
            print("-" * 60)
            return idaapi.PLUGIN_SKIP

        # Attach multi-function actions to main menu
        # This will now correctly create a submenu under our plugin's name.
        print(f"CodeDumper: [init] Attaching multi-function actions to {MENU_PATH_MULTI}...")
        ida_kernwin.attach_action_to_menu(MENU_PATH_MULTI, ACTION_ID_CODE_MULTI, ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_menu(MENU_PATH_MULTI, ACTION_ID_DOT_MULTI, ida_kernwin.SETMENU_APP)

        # Install Hooks for Context Menu
        self.hooks = DumpHooks()
        if not self.hooks.hook():
            print("CodeDumper Error: [init] Failed to install UI hooks.")
            # ... (cleanup is the same)
            ida_kernwin.unregister_action(ACTION_ID_CTX)
            ida_kernwin.unregister_action(ACTION_ID_DOT_CTX)
            ida_kernwin.unregister_action(ACTION_ID_CODE_MULTI)
            ida_kernwin.unregister_action(ACTION_ID_DOT_MULTI)
            self.hooks = None
            print("-" * 60)
            return idaapi.PLUGIN_SKIP
        print("CodeDumper: [init] UI hooks installed.")

        print(f"CodeDumper: {self.wanted_name} initialization complete.")
        print("-" * 60)
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        # This method is now effectively obsolete, as the menu entry
        # is a submenu. It won't be called. We leave it here for
        # compliance with the plugin_t interface.
        pass

    def term(self):
        # ... (the term function is also IDENTICAL, no changes needed)
        print("-" * 60)
        print(f"CodeDumper: {self.wanted_name} plugin terminating...")

        if self.hooks:
            try:
                self.hooks.unhook()
            except Exception as e:
                print(f"CodeDumper Error: [term] Exception during unhooking: {e}")
            self.hooks = None

        # Detach actions from main menu
        ida_kernwin.detach_action_from_menu(MENU_PATH_MULTI, ACTION_ID_CODE_MULTI)
        ida_kernwin.detach_action_from_menu(MENU_PATH_MULTI, ACTION_ID_DOT_MULTI)

        # Unregister actions
        ida_kernwin.unregister_action(ACTION_ID_CTX)
        ida_kernwin.unregister_action(ACTION_ID_DOT_CTX)
        ida_kernwin.unregister_action(ACTION_ID_CODE_MULTI)
        ida_kernwin.unregister_action(ACTION_ID_DOT_MULTI)

        with g_dump_lock:
            g_dump_in_progress.clear()
            global g_multi_dump_active
            g_multi_dump_active = False

        print(f"CodeDumper: {self.wanted_name} termination complete.")
        print("-" * 60)

# --- Plugin Entry Point ---

def PLUGIN_ENTRY():
    return CodeDumperPlugin()

# --- End of Script ---
print("CodeDumper: Script loaded.")
