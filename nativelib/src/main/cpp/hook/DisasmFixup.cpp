//
// DisasmFixup.cpp — LLVM AArch64 反汇编文本 → capstone/GumTrace 风格
//
// 这四个函数原先内联在 vm.cpp 里,现在单独成文件是为了让宿主机可以直接
// 编译并跑单元测试(nativelib_example 下的 test_disasm_fixup),不必依赖
// Android NDK / QBDI —— 它们都是纯函数,没有任何 QBDI 或 JNI 依赖。
//
// 改动这些函数时请同步跑:
//     cd QTrace/tools/disasm-fixup-test && cmake -B build && cmake --build build
//     ./build/test_disasm_fixup
//
// 构建接入:CMakeLists.txt 用 aux_source_directory(hook ...) 收集源文件,
// 本文件放在 hook/ 下会被自动纳入,无需改 CMakeLists。
//
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cinttypes>
#include <cstdlib>      /* strtoull */
#include <strings.h>   /* strcasecmp */
#include "DisasmFixup.h"

/* 哪些助记符的最后一个操作数是 PC 相对的立即数（需要改写成绝对地址）。
 *
 * 名单依据 LLVM 的 AArch64InstrFormats.td（均已核对 OperandType）：
 *   bl/b、cbz/cbnz、tbz/tbnz → BranchTarget / am_brcond：OPERAND_PCREL
 *   adr / adrp               → adrlabel / adrplabel：OPERAND_PCREL
 *   ldr* / prfm 字面量形式     → am_ldrlit：OPERAND_PCREL
 * 不含 br/blr（它们是寄存器形式，无立即数）。
 *
 * 日志里不区分 adrp：它确实也是 OPERAND_PCREL，单独处理的原因不是标志位，
 * 而是【公式不同（页基址而非 PC）且打印格式不同（十进制而非十六进制）】。
 *
 * 字面量加载（ldr x0, #label）与普通内存形式（ldr x0, [x1, #0x10]）
 * 靠有无方括号区分：只处理没有 '[' 的。真机 trace 里字面量形式 0 条，
 * 加上是为了以后换目标也不静默出错，不影响已验证的路径。
 */
bool is_pcrel_imm_mnemonic(const char *m, const char *line, bool *out_is_adrp)
{
    *out_is_adrp = false;
    if (m == nullptr) {
        return false;
    }
    if (strcasecmp(m, "adrp") == 0) {
        *out_is_adrp = true;
        return true;
    }
    if (strcasecmp(m, "adr") == 0)  { return true; }
    if (strcasecmp(m, "bl") == 0)   { return true; }
    if (strcasecmp(m, "cbz") == 0)  { return true; }
    if (strcasecmp(m, "cbnz") == 0) { return true; }
    if (strcasecmp(m, "tbz") == 0)  { return true; }
    if (strcasecmp(m, "tbnz") == 0) { return true; }
    // b / b.<cond>
    if ((m[0] == 'b' || m[0] == 'B') && (m[1] == '\0' || m[1] == '.')) {
        return true;
    }
    // 字面量加载 / 预取：没有方括号才是字面量形式
    if (line != nullptr && strchr(line, '[') == nullptr) {
        if (strncmp(m, "ldr", 3) == 0 || strcmp(m, "prfm") == 0) {
            return true;
        }
    }
    return false;
}

/* 把 PC 相对的分支/寻址目标改写成绝对地址，结果写到 out（容量 out_size）。
 *
 * 背景（均经真实 trace 实测）：LLVM 的 AArch64 打印器打的是**相对量**，
 * capstone（GumTrace 用的）打的是**绝对地址**：
 *     现在: bl #-0x1107c        b.ls #0x304       adrp x8, #339968（十进制，字节）
 *     应  : bl #0x7927a3e7d8    b.ls #0x7927a60ed4  adrp x8, #0x7927aa2000
 * 验证依据：113/113 条无条件分支满足 pc+imm == 下一行地址；
 *          adrp 的 339968 = 0x53000 字节，(pc&~0xfff)+0x53000 == 注解里的 x8 值。
 *
 * 不修正的后果：
 * - trace-ui 把 BL 的立即数当目标地址用（scan_unified/chunk_scan 的 CallTree），
 *   会直接建出错误的调用树节点
 * - QTrace 自己的符号级 call func 拿这个值查符号表，永远命不中
 *   （实测：18089 条 bl # 指令，0 条后面跟 call func:）
 *
 * 【为什么不用 OPERANDFLAG_PCREL 判定】该标志确实准确（BranchTarget / am_brcond /
 * adrlabel / adrplabel / am_ldrlit 在 .td 里都声明了 OPERAND_PCREL），
 * 但我们还需要区分【adrp 的页基址公式】与【分支的 PC 公式】、
 * 以及【字面量 ldr 与内存 ldr】—— 这两项用标志位都区分不了，用助记符反而更精确：
 * "ldr x0, [x1, #0x10]" 里的 # 偏移必须保持原样，已在真机 trace 上验证
 * 18209/18209 条内存偏移原封不动（本轮全量回归则是 312426/312426）。
 *
 * 因为绝对地址比原始位移长（"#0x304" -> "#0x7927a60ed4"，6 字节变 13 字节），
 * 不能原地改写，必须写到独立缓冲，否则会被截断成 "#0x792" 这种错地址。
 */
void fixup_pcrel_immediates(const char *in, uint64_t pc, char *out, size_t out_size)
{
    if (in == nullptr || out == nullptr || out_size == 0) {
        return;
    }
    snprintf(out, out_size, "%s", in);   // 默认原样

    // 助记符直接从文本里取第一个 token（和 trace-ui 的做法一致）：
    // 这样不依赖 QBDI 的 ANALYSIS_INSTRUCTION，也避免 "b.<cond>" 这类
    // 条件分支助记符是否带后缀的歧义。
    char mnem[16];
    size_t mi = 0;
    for (const char *s = in; *s != '\0' && *s != ' ' && *s != '\t' && mi + 1 < sizeof(mnem); ++s) {
        mnem[mi++] = *s;
    }
    mnem[mi] = '\0';

    bool is_adrp = false;
    if (!is_pcrel_imm_mnemonic(mnem, in, &is_adrp)) {
        return;
    }

    // PC 相对的目标一定是操作数列表里的最后一个，取最后一个 '#'
    const char *hash = strrchr(in, '#');
    if (hash == nullptr) {
        return;
    }
    const size_t prefix = (size_t)(hash - in);
    if (prefix + 1 >= out_size) {
        return;
    }

    // 解析数值（可带负号；adrp 打印的是十进制，分支是十六进制 —— 两种都能解析）
    const char *p = hash + 1;
    bool negative = false;
    if (*p == '-') { negative = true; ++p; }
    int base = 10;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) { base = 16; p += 2; }
    char *endp = nullptr;
    unsigned long long mag = strtoull(p, &endp, base);
    if (endp == p) {
        return;   // 没解析到数字（例如已经被改写过），不处理
    }
    int64_t imm = negative ? -(int64_t)mag : (int64_t)mag;

    uint64_t target;
    if (is_adrp) {
        // adrp 的立即数是相对**页基址**的字节偏移
        target = (pc & ~(uint64_t)0xfff) + (uint64_t)imm;
    } else {
        // 分支/adr 的立即数是相对**当前 PC** 的字节偏移
        target = pc + (uint64_t)imm;
    }

    // 保留 # 之后可能存在的非数字后缀
    char suffix[24];
    size_t si = 0;
    while (*endp != '\0' && si + 1 < sizeof(suffix)) {
        suffix[si++] = *endp++;
    }
    suffix[si] = '\0';

    snprintf(out + prefix, out_size - prefix, "#0x%" PRIx64 "%s", target, suffix);
}

/* 把 LLVM 的 #0xN（N 为单个十六进制位）改成 capstone 的十进制 #N。
 *
 * 实测 capstone（GumTrace 用的）的规则：立即数值 <= 9 打印十进制，>= 10 打印十六进制，
 *     add x0, x1, #1 / #9 / #0xa / #0x10 / #0x80
 * 而 LLVM 设了 PrintImmHex 后一律打十六进制：
 *     add x0, x1, #0x1 / #0x9 / #0xa / #0x10 / #0x80
 * 所以只有“单数字”这一种情况需要改（real trace 里占 15.9% 的行）。
 *
 * 对 trace-ui 而言这是纯文本差异（parse_imm 两种都认，内存地址又取自
 * mem_r=/mem_w= 注解），但对“与 GumTrace 对拍”影响很大。
 * 只作用于 `#` 开头的立即数，且要求后面不再是十六进制位，不会碰到寄存器名。
 */
void fixup_small_immediates(char *line)
{
    if (line == nullptr) {
        return;
    }
    char *r = line;
    char *w = line;
    while (*r != '\0') {
        if (r[0] == '#' && r[1] == '0' && (r[2] == 'x' || r[2] == 'X') &&
            r[3] >= '0' && r[3] <= '9' &&
            !((r[4] >= '0' && r[4] <= '9') || (r[4] >= 'a' && r[4] <= 'f') ||
              (r[4] >= 'A' && r[4] <= 'F'))) {
            // #0xN  ->  #N   (N = 0..9)
            *w++ = '#';
            *w++ = r[3];
            r += 4;
            continue;
        }
        *w++ = *r++;
    }
    *w = '\0';
}

/* LLVM 的 AArch64 打印器用 TAB 分隔助记符与操作数（"\tsub\tsp, sp, #0x40"），
 * 而 GumTrace/capstone 用空格（"sub sp, sp, #0x40"）。
 * trace-ui 按「第一个空格」切分助记符，TAB 会让它取到 "sub\tsp," 这种错误助记符，
 * 于是指令分类失败 → bl/br/svc 的 call 注解全部挂不上、变成孤儿行被隐藏。
 * 因此在缓存时就规范化为单空格并去掉首尾空白。 */
void normalize_disasm(char *s)
{
    if (s == nullptr) {
        return;
    }
    // TAB → 空格
    char *w = s;
    for (const char *r = s; *r != '\0'; ++r) {
        *w++ = (*r == '\t') ? ' ' : *r;
    }
    *w = '\0';
    // 去首部空白
    char *p = s;
    while (*p == ' ' || *p == '\n' || *p == '\r') {
        ++p;
    }
    if (p != s) {
        memmove(s, p, strlen(p) + 1);
    }
    // 去尾部空白
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[--n] = '\0';
    }
}

