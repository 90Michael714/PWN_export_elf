cmake_minimum_required(VERSION 3.16)
project(elf-tui VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 编译选项
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-g -O0 -Wall -Wextra)
else()
    add_compile_options(-O2 -march=native)
endif()

# 查找依赖
find_library(NOTCURSES_CORE_LIB notcurses-core REQUIRED)
find_library(NOTCURSES_LIB notcurses REQUIRED)
find_library(CAPSTONE_LIB capstone REQUIRED)
find_library(SQLITE3_LIB sqlite3 REQUIRED)

# 头文件路径
include_directories(
    ${PROJECT_SOURCE_DIR}/include
)

# ELF 解析器源文件
set(ELF_PARSER_SOURCES
    lib/elf_parser/elf_parser.c
    lib/elf_parser/strings.c
    lib/elf_parser/ehdr.c
    lib/elf_parser/phdr.c
    lib/elf_parser/shdr.c
    lib/elf_parser/symtab.c
    lib/elf_parser/dynamic.c
    lib/elf_parser/rela.c
    lib/elf_parser/note.c
    lib/elf_parser/version.c
    lib/elf_parser/registers.c
    lib/elf_parser/security.c
    lib/elf_parser/disasm.c
    lib/elf_parser/danger.c
    lib/elf_parser/callgraph.c
    lib/elf_parser/cfg_view.c
    lib/elf_parser/xref.c
    lib/elf_parser/hexdump.c
    lib/elf_parser/seg_perm.c
    lib/elf_parser/mem_layout.c
    lib/elf_parser/init_array.c
    lib/elf_parser/got_plt.c
    lib/elf_parser/attack_surface.c
    lib/elf_parser/gadget.c
    lib/elf_parser/func_boundary.c
    lib/elf_parser/strings_xref.c
    lib/elf_parser/eh_frame.c
    lib/elf_parser/search.c
    lib/elf_parser/expr_eval.c
    lib/elf_parser/syscall_ctx.c
    lib/elf_parser/one_gadget.c
    lib/elf_parser/bp_condition.c
    lib/elf_parser/vmmap_live.c
    lib/elf_parser/symbol_resolve.c
    lib/elf_parser/backtrace.c
    lib/elf_parser/telescope.c
    lib/elf_parser/hw_breakpoint.c
    lib/elf_parser/taint.c
    lib/elf_parser/rop_chain.c
    lib/elf_parser/translate_insn.c
    lib/elf_parser/translate_vuln.c
    lib/elf_parser/stack_view.c
    lib/elf_parser/dataflow.c
    lib/elf_parser/dataflow_inter.c
    lib/elf_parser/trace_view.c
    lib/elf_parser/decompile.c
)

# Core 源文件 (Worker 线程池 + 结果缓存)
set(CORE_SOURCES
    lib/core/worker.c
    lib/core/cache.c
    lib/core/debug_worker.c
    lib/core/reg_view.c
    lib/core/query.c
    lib/core/struct_out.c
    lib/core/mem_search.c
    lib/core/fuzz_engine.c
    lib/core/fuzz_mutate.c
    lib/core/process_launcher.c
    lib/core/reg_diff.c
    lib/core/db.c
    lib/core/heap_analyzer.c
    lib/core/heap_ptmalloc.c
    lib/core/heap_jemalloc.c
    lib/core/heap_trace.c
    lib/core/heap_replay.c
    lib/core/ir_analysis.c
    lib/core/pt_trace.c
    lib/core/bindiff.c
    lib/core/symbolic_bridge.c
    lib/core/rt_resolver.c
    lib/core/dwarf_reader.c
)

# TUI 源文件
set(TUI_SOURCES
    lib/tui/tui.c
    lib/tui/tui_status.c
    lib/tui/tui_input.c
    lib/tui/tui_left.c
    lib/tui/tui_middle.c
    lib/tui/tui_right.c
    lib/tui/buttons/btn_dispatch.c
    lib/tui/buttons/btn_common.c
    lib/tui/buttons/btn_disasm.c
    lib/tui/buttons/btn_gotplt.c
    lib/tui/buttons/btn_gotplt_dyn.c
    lib/tui/buttons/btn_hexdump.c
    lib/tui/buttons/btn_funcmap.c
    lib/tui/buttons/btn_hardening.c
    lib/tui/buttons/btn_dangerfunc.c
    lib/tui/buttons/btn_ropgadget.c
    lib/tui/buttons/btn_initarray.c
    lib/tui/buttons/btn_search.c
    lib/tui/buttons/btn_export.c
    lib/tui/buttons/btn_keyhelp.c
    lib/tui/buttons/btn_about.c
    lib/tui/buttons/btn_history.c
    lib/tui/buttons/btn_vmmap.c
    lib/tui/buttons/btn_symresolve.c
    lib/tui/buttons/btn_backtrace.c
    lib/tui/buttons/btn_telescope.c
    lib/tui/buttons/btn_hwbp.c
    lib/tui/buttons/btn_onegadget.c
    lib/tui/buttons/btn_syscall.c
    lib/tui/buttons/btn_expreval.c
    lib/tui/buttons/btn_bpcond.c
    lib/tui/buttons/btn_taint.c
    lib/tui/buttons/btn_ropchain.c
    lib/tui/buttons/btn_memsearch.c
    lib/tui/buttons/btn_trans_insn.c
    lib/tui/buttons/btn_trans_vuln.c
    lib/tui/buttons/btn_fuzzer.c
    lib/tui/buttons/btn_stack.c
    lib/tui/buttons/btn_dbview.c
    lib/tui/buttons/btn_vulnscan.c
    lib/tui/buttons/btn_heap.c
    lib/tui/buttons/btn_new_features.c
)

# 主程序
add_executable(elf-tui
    src/main.c
    ${CORE_SOURCES}
    ${ELF_PARSER_SOURCES}
    ${TUI_SOURCES}
)

# 链接库
target_link_libraries(elf-tui
    ${NOTCURSES_LIB}
    ${NOTCURSES_CORE_LIB}
    ${CAPSTONE_LIB}
    ${SQLITE3_LIB}
    pthread
    m
)

# 安装
install(TARGETS elf-tui DESTINATION bin)
