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
FetchContent_MakeAvailable(idax)

# ── codedump plugin ─────────────────────────────────────────────────────
if(NOT COMMAND ida_add_plugin)
    message(FATAL_ERROR
        "ida_add_plugin not defined — idax should have bootstrapped ida-cmake. "
        "Make sure IDASDK is set or that idax could fetch ida-sdk itself.")
endif()

ida_add_plugin(codedump
    SOURCES
        src/plugin/codedump_plugin.cpp
        src/graph/graph_builder.cpp
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
