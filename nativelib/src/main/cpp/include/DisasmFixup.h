//
// DisasmFixup.h — 反汇编文本规范化(见 DisasmFixup.cpp 顶部说明)
//
#pragma once
#include <cstdint>
#include <cstddef>

/* 助记符的最后一个操作数是否为 PC 相对立即数;is_adrp 单独标出(公式不同)。 */
bool is_pcrel_imm_mnemonic(const char *m, const char *line, bool *out_is_adrp);

/* PC 相对分支/寻址目标 → 绝对地址,结果写入 out。 */
void fixup_pcrel_immediates(const char *in, uint64_t pc, char *out, size_t out_size);

/* #0xN(N 为单个十六进制位)→ #N,对齐 capstone 的十进制打印。 */
void fixup_small_immediates(char *line);

/* TAB → 空格,去首尾空白。 */
void normalize_disasm(char *s);
