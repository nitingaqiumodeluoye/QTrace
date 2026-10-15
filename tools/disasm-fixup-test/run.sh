#!/usr/bin/env bash
# DisasmFixup 单元测试 / 离线回归 —— 不需要 cmake 的构建脚本
#
#   ./run.sh                      只跑单元测试(91 项断言)
#   ./run.sh <trace文件>          额外在真实 trace 上跑离线回归
#
# 编译的是仓库里真实的 hook/DisasmFixup.cpp,不是重写版 —— 保证测的就是
# CI 会编出来的那份代码。需要 g++(C++17)。
set -e
cd "$(dirname "$0")"

CPP="$(cd ../../nativelib/src/main/cpp && pwd)"
OUT="build-local"
BIN="$OUT/test_disasm_fixup"

if [ ! -f "$CPP/hook/DisasmFixup.cpp" ]; then
    echo "找不到 $CPP/hook/DisasmFixup.cpp" >&2
    exit 1
fi

mkdir -p "$OUT"
echo "编译 $CPP/hook/DisasmFixup.cpp + test_disasm_fixup.cpp ..."
g++ -std=c++17 -Wall -Wextra -O2 \
    -I"$CPP/include" -I"$CPP" \
    "$CPP/test/test_disasm_fixup.cpp" "$CPP/hook/DisasmFixup.cpp" \
    -o "$BIN"

echo
"$BIN" "$@"