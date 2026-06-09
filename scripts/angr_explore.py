#!/usr/bin/env python3
"""
angr_explore.py — 符号执行探索脚本 (由 elf-tui symbolic_bridge.c 调用)

用法:
  python3 angr_explore.py <elf_path> <target_addr> <avoid_addr> <timeout>
  python3 angr_explore.py <elf_path> <func_addr> 0 <timeout> mode=input nargs=N

输出: JSON 行协议
  {"type": "PATH_FOUND", "addr": "0x...", "depth": N}
  {"type": "CONSTRAINT", "expr": "<Z3 expression>"}
  {"type": "INPUT", "stdin": "..."}
  {"type": "ERROR", "msg": "..."}
  {"type": "STATE", "msg": "..."}
  {"type": "RESULT", "paths": N, "time": S}
"""

import sys
import json
import time

def main():
    if len(sys.argv) < 4:
        print(json.dumps({"type": "ERROR", "msg": "Usage: angr_explore.py <elf> <target> <avoid> [timeout]"}))
        sys.exit(1)

    elf_path   = sys.argv[1]
    target_str = sys.argv[2]
    avoid_str  = sys.argv[3]
    timeout    = int(sys.argv[4]) if len(sys.argv) > 4 else 60
    mode       = "explore"
    nargs      = 0

    # 解析额外参数
    for a in sys.argv[5:]:
        if a.startswith("mode="):
            mode = a.split("=")[1]
        elif a.startswith("nargs="):
            nargs = int(a.split("=")[1])

    try:
        import angr
        import claripy
    except ImportError:
        print(json.dumps({"type": "ERROR", "msg": "angr not installed. Run: pip3 install angr"}))
        sys.exit(1)

    target_addr = int(target_str, 16)
    avoid_addr  = int(avoid_str, 16) if avoid_str != "0" else None

    print(json.dumps({"type": "STATE", "msg": f"Loading {elf_path}..."}), flush=True)

    try:
        proj = angr.Project(elf_path, auto_load_libs=False)
    except Exception as e:
        print(json.dumps({"type": "ERROR", "msg": f"Failed to load ELF: {e}"}))
        sys.exit(1)

    if mode == "input":
        # 输入发现模式: 对指定函数探索输入约束
        _explore_inputs(proj, target_addr, nargs, timeout)
    else:
        # 路径探索模式: 从 entry 到 target
        _explore_paths(proj, target_addr, avoid_addr, timeout)

def _explore_paths(proj, target, avoid, timeout):
    """从 entry point 探索到 target 的路径"""
    print(json.dumps({"type": "STATE", "msg": f"Exploring to 0x{target:x}..."}), flush=True)

    state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(state)

    t0 = time.time()

    # 设置探索目标
    find_addrs = [target]
    avoid_addrs = []
    if avoid:
        avoid_addrs.append(avoid)

    # 防止过度探索: 限制步数和活跃状态数
    simgr.use_technique(angr.exploration_techniques.LoopSeer(bound=100))

    try:
        simgr.explore(find=find_addrs[0], avoid=avoid_addrs, num_find=5)

        elapsed = time.time() - t0

        if simgr.found:
            for i, found_state in enumerate(simgr.found[:5]):
                path_len = found_state.history.depth
                print(json.dumps({
                    "type": "PATH_FOUND",
                    "idx": i,
                    "addr": f"0x{found_state.addr:x}",
                    "depth": path_len
                }), flush=True)

                # 尝试提取 stdin 约束
                try:
                    stdin_var = found_state.posix.stdin
                    if hasattr(found_state.solver, 'eval'):
                        concrete_input = found_state.solver.eval(stdin_var, cast_to=bytes)
                        if concrete_input:
                            print(json.dumps({
                                "type": "INPUT",
                                "stdin_len": len(concrete_input),
                                "stdin_hex": concrete_input[:64].hex()
                            }), flush=True)
                except Exception:
                    pass

            print(json.dumps({
                "type": "RESULT",
                "paths": len(simgr.found),
                "time": f"{elapsed:.1f}s",
                "active": len(simgr.active)
            }), flush=True)
        else:
            print(json.dumps({
                "type": "RESULT",
                "paths": 0,
                "time": f"{elapsed:.1f}s",
                "active": len(simgr.active),
                "deadended": len(simgr.deadended),
                "errored": len(simgr.errored)
            }), flush=True)
    except Exception as e:
        print(json.dumps({"type": "ERROR", "msg": f"Exploration failed: {e}"}), flush=True)

def _explore_inputs(proj, func_addr, nargs, timeout):
    """对指定函数做输入约束推断"""
    print(json.dumps({"type": "STATE", "msg": f"Input discovery for func @ 0x{func_addr:x}"}), flush=True)

    # 创建调用状态: 所有参数为符号变量
    args = []
    arg_names = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

    if nargs <= 0:
        nargs = 4  # 默认探查 4 个参数

    for i in range(min(nargs, 6)):
        # 创建符号位向量
        bv = claripy.BVS(arg_names[i], 64)
        args.append(bv)

    try:
        state = proj.factory.call_state(func_addr, *args,
                                         base_state=proj.factory.entry_state())

        print(json.dumps({
            "type": "STATE",
            "msg": f"Symbolic args: {nargs} x 64-bit"
        }), flush=True)

        simgr = proj.factory.simulation_manager(state)

        # 运行几步
        simgr.step(until=lambda sm: len(sm.active) == 0,  n=200)

        # 提取约束
        for i, active_state in enumerate(simgr.active[:3]):
            constraints = active_state.solver.constraints
            print(json.dumps({
                "type": "CONSTRAINT",
                "idx": i,
                "count": len(constraints),
                "addr": f"0x{active_state.addr:x}"
            }), flush=True)

            # 对每个参数尝试求解
            for j, arg in enumerate(args[:nargs]):
                try:
                    val = active_state.solver.eval(arg)
                    print(json.dumps({
                        "type": "INPUT",
                        f"arg{j}": f"0x{val:x}",
                        f"arg{j}_dec": str(val)
                    }), flush=True)
                except Exception:
                    print(json.dumps({
                        "type": "INPUT",
                        f"arg{j}": "<unconstrained>"
                    }), flush=True)
    except Exception as e:
        print(json.dumps({"type": "ERROR", "msg": f"Input discovery failed: {e}"}), flush=True)

if __name__ == "__main__":
    main()
