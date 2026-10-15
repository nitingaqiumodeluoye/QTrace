# DisasmFixup 单元测试 / 离线回归

验证 `nativelib/src/main/cpp/hook/DisasmFixup.cpp` —— 把 LLVM 的 AArch64
反汇编文本改写成 capstone/GumTrace 风格的那四个函数。

## 为什么需要它

Android 工程只能在 CI 上编译,这几个函数却极度敏感:

| 函数 | 改错的后果 |
| --- | --- |
| `normalize_disasm` | LLVM 用 TAB 分隔助记符,trace-ui 按第一个**空格**切 → 指令分类失败,`bl`/`svc` 的 call 注解全成孤儿行被隐藏 |
| `fixup_pcrel_immediates` | LLVM 打的是**相对量**、capstone 打**绝对地址**。不改 trace-ui 的调用树全错;改错公式(例如把 `adrp` 的页基址当成 `pc+imm`)同样全错 |
| `fixup_small_immediates` | 单数字立即数要打十进制(`#1`),否则与 GumTrace 对拍不一致 |

以前只能"改一行 → 推 fork → 等一轮 CI → 抓真机 trace"才能发现问题。
这四个函数是纯函数(不依赖 QBDI / JNI / Android),所以这里**直接编译同一份
真实实现**在宿主机上跑 —— 测的就是 CI 会编出来的那份代码,不是重写版。

## 跑法

```bash
# 不需要 cmake
./run.sh                          # 单元测试（91 项断言）
./run.sh <trace文件>              # 额外在真实 trace 上跑离线回归

# 或者用 cmake
cmake -B build && cmake --build build
./build/test_disasm_fixup
```

需要 g++(C++17)。

## 单元测试覆盖什么

- 空白规范化:TAB → 空格、去首尾空白、幂等
- 小立即数:`#0x1`→`#1`,但 `#0x1f`/`#0x10` 不动(后面还有十六进制位)
- 助记符判定:`b.cond`/`cbz`/`tbz`/`adrp` 命中;`br`/`blr` 不命中;
  字面量 `ldr x0, #0x1234` 命中而 `ldr x0, [x1, #0x10]` **不命中**(内存偏移必须原样)
- PCREL 公式:分支用 `pc+imm`、adrp 用 `(pc & ~0xfff)+imm`;负偏移;
  只改最后一个 `#`(`tbz w9, #0x1, #0x30` 的位号不动)
- 回归:绝对地址比位移长,必须写独立缓冲(旧实现原地改写被截断成 `#0x792`)

## 离线回归检查的六条不变量

在真实 trace(上百万行)上检查"修好之后必须成立"的性质:

| # | 不变量 | 说明 |
| --- | --- | --- |
| I1 | 规范化幂等 | 再跑一次 `normalize_disasm` 结果不变(无 TAB、无首尾空白) |
| I2 | 小立即数已改写 | 无残留 `#0xN`(N 为一个十六进制位) |
| I3 | 分支目标正确 | `b`/`bl` 目标 == 下一行 PC;条件分支 == 下一行 PC(跳了)或 `pc+4`(没跳) |
| I4 | adrp 目标正确 | == 写回寄存器的值 |
| I5 | 内存偏移未被误改 | base 寄存器值 + 偏移 == `mem_r`/`mem_w` 注解地址 |
| I6 | PCREL 往返一致 | 把绝对地址反解回位移、重跑 `fixup_pcrel_immediates`,得到同一行文本 |

**I6 是唯一真正跑实现的引用式检查**(其余五条只看文本不变量,理论上实现改坏了
也可能通过)。它反解公式为 `位移 = 目标 - (adrp ? pc & ~0xfff : pc)`,然后用
独立推导出的位移重跑实现,比对是否还原 —— 公式错会立刻暴露。

真机 trace 实测(1,118,740 指令行):

```
I1 规范化幂等               1118740/1118740 ✅
I2 无残留 #0x单数字         1118740/1118740 ✅
I3 分支目标(跳 60921 / 未跳 24212 / 异常 0) ✅
I4 adrp 目标==写回值        42744/42744 ✅
I5 内存偏移 base+disp==mem  218960/218960 (跳过 1069) ✅
I6 PCREL 往返一致           127877/127877 ✅
```

## 检出能力已验证

把实现故意改坏,离线回归必须变红:

| 注入的缺陷 | 结果 |
| --- | --- |
| `adrp` 用 `pc+imm`(早期错误实现) | 单元测试 5 项失败;I6 85134/127877 ❌ |
| 分支用 `(pc & ~0xfff)+imm` | I6 42892/127877 ❌ |
| 去掉独立缓冲(还原 `snprintf` 截断 bug) | 单元测试 15 项失败 |

## 改动 DisasmFixup.cpp 时

改完请跑 `./run.sh`(外加一个有 trace 的离线回归)。这四个函数的行为是
trace-ui 能否解析的前提,改动前先想清楚 `is_pcrel_imm_mnemonic` 的名单依据
(LLVM `AArch64InstrFormats.td` 的 `OPERAND_PCREL`)。