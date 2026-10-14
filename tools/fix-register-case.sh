#!/usr/bin/env bash
# 把旧版 QTrace 输出的 trace 归一化成 trace-ui 可用的格式。
#
# 旧版 QTrace 直接打印 QBDI 的 OperandAnalysis.regName（来自 LLVM MCRegisterInfo，
# 是大写：X0/W0/SP/FP/LR/XZR/NZCV），而反汇编文本是小写（x0/sp/x29/x30）。
# trace-ui 用反汇编里的寄存器名精确匹配注解中的 "name=0xHEX" 取寄存器/内存值，
# 大小写不一致会让 mem_op.value 全为 None -> get_memory 返回全 0。
#
# 用法:
#   ./fix-register-case.sh trace.log            # 生成 trace.log.fixed
#   ./fix-register-case.sh trace.log out.log    # 指定输出文件
#
# 只替换 "寄存器名=0x" 形式（反汇编文本里不会出现这种模式），因此对指令文本安全。
set -euo pipefail

in="${1:?usage: $0 <trace.log> [out.log]}"
out="${2:-${in}.fixed}"

sed -E 's/\b(X[0-9]{1,2}|W[0-9]{1,2}|SP|FP|LR|XZR|WZR|NZCV)=0x/\L\1=0x/g' "$in" > "$out"
echo "written: $out"
