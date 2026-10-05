cmake_minimum_required(VERSION 3.27)
project(codedump LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# ── Linker selection ────────────────────────────────────────────────────
if(APPLE)
    add_link_options(-Wl,-ld_new)
elseif(NOT WIN32)
    find_program(MOLD_LINKER mold)
    if(MOLD_LINKER)
        message(STATUS "Using mold linker: ${MOLD_LINKER}")
        add_link_options("-fuse-ld=${MOLD_LINKER}")
    endif()
endif()

# ── idax dependency (pulls ida-sdk, builds idax::idax static lib) ───────
include(FetchContent)

# Don't re-check upstream on every reconfigure — much faster local rebuilds.
# Run `cmake --fresh` (or delete the build dir) to force a refresh.
set(FETCHCONTENT_UPDATES_DISCONNECTED ON CACHE BOOL
    "Do not re-check FetchContent remotes on every build" FORCE)

FetchContent_Declare(
    idax
    GIT_REPOSITORY https://github.com/19h/idax.git
    GIT_TAG        master
)

# Populate first so the patches land before idax's own CMake runs.
# CMP0169 stays OLD: this file's minimum is 3.27, and Populate is how the
# patch is applied to a tree that is not yet a subdirectory.
if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
endif()
FetchContent_GetProperties(idax)
if(NOT idax_POPULATED)
    FetchContent_Populate(idax)
endif()

# Current ida-sdk main has no ida-cmake submodule. The in-tree package is
# src/cmake/idasdkConfig.cmake. patches/idax-cmake-bootstrap.patch teaches
# today's idax master to accept that. Skip once the fetched CMakeLists
# already mentions it.
file(READ "${idax_SOURCE_DIR}/CMakeLists.txt" _idax_cmake_text)
if(NOT _idax_cmake_text MATCHES "idasdkConfig\\.cmake")
    execute_process(
        COMMAND git apply "${CMAKE_CURRENT_SOURCE_DIR}/patches/idax-cmake-bootstrap.patch"
        WORKING_DIRECTORY "${idax_SOURCE_DIR}"
        RESULT_VARIABLE _idax_cmake_patch_result
        ERROR_VARIABLE _idax_cmake_patch_error
    )
    if(NOT _idax_cmake_patch_result EQUAL 0)
        message(FATAL_ERROR
            "idax cannot see the in-tree IDA SDK package, and "
            "patches/idax-cmake-bootstrap.patch did not apply.\n"
            "${_idax_cmake_patch_error}")
    endif()
endif()

# idax calls init_hexrays_plugin() and reads cexpr_t::m. Teach that library the
# 9.4/9.5 handshake in src/common. A fresh fetch of today's idax master does not
# have the probe yet; patches/idax-hexrays-abi.patch adds it. Once idax itself
# carries src/detail/hexrays_probe.hpp, the patch is skipped.
set(_idax_probe "${idax_SOURCE_DIR}/src/detail/hexrays_probe.hpp")
if(NOT EXISTS "${_idax_probe}")
    execute_process(
        COMMAND git apply "${CMAKE_CURRENT_SOURCE_DIR}/patches/idax-hexrays-abi.patch"
        WORKING_DIRECTORY "${idax_SOURCE_DIR}"
        RESULT_VARIABLE _idax_patch_result
        ERROR_VARIABLE _idax_patch_error
    )
    if(NOT _idax_patch_result EQUAL 0)
        message(FATAL_ERROR
            "idax has no Hex-Rays 9.4/9.5 probe, and patches/idax-hexrays-abi.patch "
            "did not apply. That patch matches the idax snapshot codedump fetched "
            "(the tree that still calls init_hexrays_plugin() directly).\n"
            "${_idax_patch_error}")
    endif()
endif()
if(NOT EXISTS "${_idax_probe}")
    message(FATAL_ERROR
        "idax is missing src/detail/hexrays_probe.hpp after the ABI patch")
endif()

# MakeAvailable skips add_subdirectory once Populate has already run.
add_subdirectory("${idax_SOURCE_DIR}" "${idax_BINARY_DIR}")

target_compile_definitions(idax PRIVATE CODEDUMP_HEXRAYS_ABI)
target_include_directories(idax PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")

# ── codedump plugin ─────────────────────────────────────────────────────
if(NOT COMMAND ida_add_plugin)
    message(FATAL_ERROR
        "ida_add_plugin not defined — idax should have bootstrapped ida-cmake. "
        "Make sure IDASDK is set or that idax could fetch ida-sdk itself.")
endif()

ida_add_plugin(codedump
    SOURCES
        src/plugin/codedump_plugin.cpp
        src/common/function_filter.cpp
        src/graph/graph_builder.cpp
        src/analysis/function_ranker.cpp
        src/analysis/subsystem_clusterer.cpp
        src/analysis/ctree_analyzer.cpp
        src/analysis/ptn_emitter.cpp
        src/analysis/register_analyzer.cpp
        src/analysis/type_collector.cpp
        src/transfer/metadata.cpp
        src/transfer/metadata_export.cpp
        src/transfer/metadata_apply.cpp
        src/output/code_writer.cpp
        src/output/dot_writer.cpp
        src/output/asm_writer.cpp
        src/output/ptn_writer.cpp
)

target_link_libraries(codedump PRIVATE idax::idax)
target_include_directories(codedump PRIVATE ${CMAKE_CURRENT_LIST_DIR}/src)
target_compile_features(codedump PRIVATE cxx_std_23)

# pro.h poisons snprintf/sprintf/etc. via macros. Several translation units
# include <sstream>/<locale> after pro.h, so libc++'s money.h trips the macro
# (snprintf -> dont_use_snprintf). USE_DANGEROUS_FUNCTIONS is the SDK's
# documented switch that disables those poison macros.
target_compile_definitions(codedump PRIVATE USE_DANGEROUS_FUNCTIONS)

# ida-cmake forces -flto via the propagated ida_compiler_settings interface.
# That requires LLVMgold.so for the bfd linker, which isn't always installed
# (e.g. on Ubuntu without the llvm-gold package). Strip -flto from both the
# compile and link options for our plugin so the build is portable.
set_property(TARGET codedump PROPERTY INTERPROCEDURAL_OPTIMIZATION FALSE)

if(TARGET ida_compiler_settings)
    foreach(_prop INTERFACE_COMPILE_OPTIONS INTERFACE_LINK_OPTIONS)
        get_target_property(_opts ida_compiler_settings ${_prop})
        if(_opts)
            list(FILTER _opts EXCLUDE REGEX "-flto.*")
            set_property(TARGET ida_compiler_settings PROPERTY ${_prop} "${_opts}")
        endif()
    endforeach()
endif()

if(MSVC)
    target_compile_options(codedump PRIVATE /Zc:__cplusplus /permissive-)
else()
    target_compile_options(codedump PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

# ── cdump_bench: headless idalib profiling harness (opt-in) ──────────────
# Reuses the already-fetched idax::idax and links against the *real* IDA
# runtime libs (libidalib.so + libida.so) from $IDADIR to avoid the SDK-stub
# two-level-namespace crash documented in idax's findings.
#
#   cmake -B build -DCODEDUMP_BUILD_BENCH=ON
#   cmake --build build --target cdump_bench
#   IDADIR=/path/to/ida ./build/cdump_bench <idb> --name sub_18000DE0
option(CODEDUMP_BUILD_BENCH "Build the headless idalib benchmark harness" OFF)

if(CODEDUMP_BUILD_BENCH)
    if(WIN32)
        set(_ida_runtime_dir "$ENV{IDADIR}")
        set(_idalib_name "idalib.lib")
        set(_ida_name "ida.lib")
    elseif(APPLE)
        set(_ida_runtime_dir "$ENV{IDADIR}")
        set(_idalib_name "libidalib.dylib")
        set(_ida_name "libida.dylib")
    else()
        set(_ida_runtime_dir "$ENV{IDADIR}")
        set(_idalib_name "libidalib.so")
        set(_ida_name "libida.so")
    endif()

    if(NOT _ida_runtime_dir OR NOT EXISTS "${_ida_runtime_dir}/${_idalib_name}")
        message(FATAL_ERROR
            "CODEDUMP_BUILD_BENCH=ON but IDADIR is unset or has no ${_idalib_name}. "
            "Set IDADIR to the IDA install dir (the one containing ${_ida_name}).")
    endif()

    add_executable(cdump_bench
        harness/cdump_bench.cpp
        src/common/function_filter.cpp
        src/graph/graph_builder.cpp
    )
    target_link_libraries(cdump_bench PRIVATE
        idax::idax
        "${_ida_runtime_dir}/${_idalib_name}"
        "${_ida_runtime_dir}/${_ida_name}"
    )
    target_include_directories(cdump_bench PRIVATE ${CMAKE_CURRENT_LIST_DIR}/src)
    target_compile_features(cdump_bench PRIVATE cxx_std_23)
    target_compile_definitions(cdump_bench PRIVATE
        USE_DANGEROUS_FUNCTIONS USE_STANDARD_FILE_FUNCTIONS __IDP__)
    set_property(TARGET cdump_bench PROPERTY INTERPROCEDURAL_OPTIMIZATION FALSE)
    set_target_properties(cdump_bench PROPERTIES
        BUILD_RPATH "${_ida_runtime_dir}"
        INSTALL_RPATH "${_ida_runtime_dir}"
    )
    if(NOT MSVC)
        target_compile_options(cdump_bench PRIVATE -Wall -Wextra -Wno-unused-parameter)
    endif()
endif()

# ── cdump: headless idalib CLI for full function+type dumps (like idalib-dump) ─
#   cmake -B build
#   cmake --build build --target cdump
#   IDADIR=... ./build/cdump -f 0x123,sub_foo --ptn --regs -o out.c mybin.i64
#
# Walks exactly the requested functions (or *all* if -f omitted) and emits the
# same style of output as the UI (code + resolved types that are actually used).
# PTN is off by default (use --ptn); supports all UI toggles via flags.
option(CODEDUMP_BUILD_CLI "Build the headless idalib cdump CLI tool" ON)
option(CODEDUMP_CLI_USE_IDADIR_RUNTIME
    "Link cdump against runtime libraries from IDADIR instead of SDK import libraries" OFF)

if(CODEDUMP_BUILD_CLI)
    if(WIN32)
        set(_ida_runtime_dir "$ENV{IDADIR}")
        set(_idalib_name "idalib.lib")
        set(_ida_name "ida.lib")
    elseif(APPLE)
        set(_ida_runtime_dir "$ENV{IDADIR}")
        set(_idalib_name "libidalib.dylib")
        set(_ida_name "libida.dylib")
    else()
        set(_ida_runtime_dir "$ENV{IDADIR}")
        set(_idalib_name "libidalib.so")
        set(_ida_name "libida.so")
    endif()

    if(CODEDUMP_CLI_USE_IDADIR_RUNTIME AND
       (NOT _ida_runtime_dir OR NOT EXISTS "${_ida_runtime_dir}/${_idalib_name}"))
        message(FATAL_ERROR
            "CODEDUMP_CLI_USE_IDADIR_RUNTIME=ON but IDADIR is unset or has no "
            "${_idalib_name}. Set IDADIR to the IDA install dir containing "
            "${_idalib_name} and ${_ida_name}.")
    endif()

    add_executable(cdump
        harness/cdump.cpp
        src/common/function_filter.cpp
        src/graph/graph_builder.cpp
        src/analysis/function_ranker.cpp
        src/analysis/subsystem_clusterer.cpp
        src/analysis/ctree_analyzer.cpp
        src/analysis/ptn_emitter.cpp
        src/analysis/register_analyzer.cpp
        src/analysis/type_collector.cpp
        src/output/code_writer.cpp
        src/output/dot_writer.cpp
        src/output/asm_writer.cpp
        src/output/ptn_writer.cpp
    )
    target_link_libraries(cdump PRIVATE idax::idax)
    if(CODEDUMP_CLI_USE_IDADIR_RUNTIME)
        target_link_libraries(cdump PRIVATE
            "${_ida_runtime_dir}/${_ida_name}"
            "${_ida_runtime_dir}/${_idalib_name}"
        )
    else()
        target_link_libraries(cdump PRIVATE idasdk::idalib)
    endif()
    target_include_directories(cdump PRIVATE ${CMAKE_CURRENT_LIST_DIR}/src)
    target_compile_features(cdump PRIVATE cxx_std_23)
    target_compile_definitions(cdump PRIVATE
        USE_DANGEROUS_FUNCTIONS USE_STANDARD_FILE_FUNCTIONS __IDP__)
    set_property(TARGET cdump PROPERTY INTERPROCEDURAL_OPTIMIZATION FALSE)
    if(CODEDUMP_CLI_USE_IDADIR_RUNTIME)
        set_target_properties(cdump PROPERTIES
            BUILD_RPATH "${_ida_runtime_dir}"
            INSTALL_RPATH "${_ida_runtime_dir}"
        )
    elseif(APPLE)
        set_target_properties(cdump PROPERTIES
            BUILD_WITH_INSTALL_RPATH TRUE
            INSTALL_RPATH "@loader_path"
        )
    elseif(NOT WIN32)
        set_target_properties(cdump PROPERTIES
            BUILD_WITH_INSTALL_RPATH TRUE
            INSTALL_RPATH "$ORIGIN"
        )
    endif()
    if(APPLE)
        target_link_options(cdump PRIVATE -Wl,-flat_namespace)
    endif()
    if(NOT MSVC)
        target_compile_options(cdump PRIVATE -Wall -Wextra -Wno-unused-parameter)
    endif()
endif()

# Host-side checks for the 9.4/9.5 decompiler decisions. No IDA runtime.
enable_testing()
add_executable(codedump_hexrays_abi_test tests/hexrays_abi_test.cpp)
target_include_directories(codedump_hexrays_abi_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_compile_features(codedump_hexrays_abi_test PRIVATE cxx_std_23)
if(NOT MSVC)
    target_compile_options(codedump_hexrays_abi_test PRIVATE -Wall -Wextra -Wpedantic)
endif()
add_test(NAME codedump.hexrays_abi COMMAND codedump_hexrays_abi_test)
