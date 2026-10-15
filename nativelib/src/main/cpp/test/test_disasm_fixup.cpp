//
// test_disasm_fixup.cpp — DisasmFixup.cpp 的宿主机单元测试
//
// 为什么放在这里:DisasmFixup.cpp 里的四个函数是把 LLVM 的 AArch64 反汇编文本
// 改写成 capstone/GumTrace 风格的关键(PC 相对立即数改绝对地址、单数字立即数改
// 十进制、TAB 去空格),而 Android 工程只能在 CI 上编译,改一行要等一整轮 CI
// 才能知道对不对。它们是纯函数,所以在宿主机上直接编译同一份**真实实现**
// (不是重写版)来验证 —— 这样测的就是将来 CI 编出来的那份代码。
//
// 跑法:
//     cd QTrace/tools/disasm-fixup-test
//     cmake -B build && cmake --build build
//     ./build/test_disasm_fixup        (Windows: build\test_disasm_fixup.exe)
//
// 期望值来源:
//  * 分支/adr 用 pc+imm,adrp 用 (pc&~0xfff)+imm —— 由真机 trace 实测确认
//    (113/113 条无条件分支满足 pc+imm == 下一行地址;adrp 42312/42312 条
//     目标 == 写回寄存器值)
//  * 单数字立即数改十进制 —— 与 capstone 输出对拍得出
//  * TAB → 空格 —— trace-ui 按第一个空格切助记符,TAB 会让注释挂不上
//
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>
#include "DisasmFixup.h"

static int g_pass = 0;
static int g_fail = 0;

static void check_str(const char *what, const char *got, const char *want)
{
    if (strcmp(got, want) == 0) {
        ++g_pass;
    } else {
        ++g_fail;
        printf("  [FAIL] %s\n          got  = \"%s\"\n          want = \"%s\"\n",
               what, got, want);
    }
}

static void check_bool(const char *what, bool got, bool want)
{
    if (got == want) {
        ++g_pass;
    } else {
        ++g_fail;
        printf("  [FAIL] %s: got=%d want=%d\n", what, (int)got, (int)want);
    }
}

/* ---------- normalize_disasm ---------- */

static void test_normalize(void)
{
    printf("[1] normalize_disasm (TAB -> 空格, 去首尾空白)\n");
    struct { const char *in; const char *want; } cases[] = {
        // LLVM 的打印器用 TAB 分隔,capstone 用空格
        {"\tsub\tsp, sp, #0x40",  "sub sp, sp, #0x40"},
        {"\tbl\t#-0x1107c",       "bl #-0x1107c"},
        {"  \tret\t",             "ret"},
        // 已经是正常形式的不能被改动
        {"mov x0, x1",            "mov x0, x1"},
        // 无操作数指令(后面补空格是 vm.cpp 的事,这里只规范空白)
        {"ret",                   "ret"},
        // 多个 TAB / 混合空白
        {"\tldr\tx0, [x1, #0x10] ", "ldr x0, [x1, #0x10]"},
        // 空串和全空白
        {"",                      ""},
        {"\t \t",                 ""},
    };
    for (auto &c : cases) {
        char buf[128];
        snprintf(buf, sizeof(buf), "%s", c.in);
        normalize_disasm(buf);
        check_str(c.in, buf, c.want);
    }
}

/* ---------- fixup_small_immediates ---------- */

static void test_small_imm(void)
{
    printf("[2] fixup_small_immediates (#0xN -> #N, N 为单个十六进制位)\n");
    struct { const char *in; const char *want; } cases[] = {
        // 只改单数字:0..9 打印成十进制,与 capstone 一致
        {"add x0, x1, #0x1",          "add x0, x1, #1"},
        {"add x0, x1, #0x9",          "add x0, x1, #9"},
        {"add x0, x1, #0x0",          "add x0, x1, #0"},
        // 两位及以上不动(#0xa 以上 capstone 也打十六进制)
        {"add x0, x1, #0xa",          "add x0, x1, #0xa"},
        {"add x0, x1, #0x10",         "add x0, x1, #0x10"},
        {"add x0, x1, #0x80",         "add x0, x1, #0x80"},
        // 关键边界:#0x1f 不能被误当成"单数字"(后面还是十六进制位)
        {"mov w0, #0x1f",             "mov w0, #0x1f"},
        // 内存操作数里的偏移同样适用
        {"ldr x0, [x1, #0x8]",        "ldr x0, [x1, #8]"},
        {"str q1, [sp, #0x20]",       "str q1, [sp, #0x20]"},
        // 移位形式
        {"lsl x0, x1, #0x3",          "lsl x0, x1, #3"},
        // 没有立即数的不动
        {"ret",                       "ret"},
        {"br x17",                    "br x17"},
        // 寄存器名里含 "x0" 不能被误改(没有 '#' 前缀)
        {"mov x0, x1",                "mov x0, x1"},
        // '#' 后面不是 0x 的不动
        {"mov w0, #5",                "mov w0, #5"},
    };
    for (auto &c : cases) {
        char buf[128];
        snprintf(buf, sizeof(buf), "%s", c.in);
        fixup_small_immediates(buf);
        check_str(c.in, buf, c.want);
    }
}

/* ---------- is_pcrel_imm_mnemonic ---------- */

static void test_pcrel_mnemonic(void)
{
    printf("[3] is_pcrel_imm_mnemonic (助记符判定)\n");
    struct { const char *m; const char *line; bool want; bool want_adrp; } cases[] = {
        // adrp 单独标出(公式不同)
        {"adrp",  "adrp x8, #339968",           true,  true},
        // 分支
        {"bl",    "bl #-0x1107c",               true,  false},
        {"b",     "b #0x304",                   true,  false},
        {"b.ls",  "b.ls #0x304",                true,  false},
        {"b.eq",  "b.eq #0x1c",                 true,  false},
        {"cbz",   "cbz x0, #0x40",              true,  false},
        {"cbnz",  "cbnz w8, #0x24",             true,  false},
        {"tbz",   "tbz w9, #0x1, #0x30",        true,  false},
        {"tbnz",  "tbnz x2, #0x3f, #0x18",      true,  false},
        {"adr",   "adr x0, #0x1234",            true,  false},
        // 字面量加载:没有方括号才是 PC 相对
        {"ldr",   "ldr x0, #0x1234",            true,  false},
        {"prfm",  "prfm pldl1keep, #0x100",     true,  false},
        // 内存形式有方括号 -> 不是 PC 相对(偏移必须保持原样)
        {"ldr",   "ldr x0, [x1, #0x10]",        false, false},
        {"ldr",   "ldr q0, [sp, #0x20]",        false, false},
        {"str",   "str x0, [x1, #0x8]",         false, false},
        {"ldrb",  "ldrb w0, [x1, #0x1]",        false, false},
        // 寄存器形式:没有立即数
        {"br",    "br x17",                     false, false},
        {"blr",   "blr x8",                     false, false},
        {"ret",   "ret",                        false, false},
        // 其它普通指令
        {"add",   "add x0, x1, #0x1",           false, false},
        {"mov",   "mov x0, x1",                 false, false},
        {"svc",   "svc #0",                     false, false},
        // 大/小写
        {"BL",    "BL #0x100",                  true,  false},
        {"ADRP",  "ADRP x8, #0x1000",           true,  true},
        // 以 b 开头但不是分支的助记符不能被误判
        {"bfi",   "bfi x0, x1, #0x1, #0x2",     false, false},
        {"bl",    nullptr,                      true,  false},
        {"brk",   "brk #0",                     false, false},
    };
    for (auto &c : cases) {
        bool is_adrp = true;
        bool got = is_pcrel_imm_mnemonic(c.m, c.line, &is_adrp);
        char what[128];
        snprintf(what, sizeof(what), "mnemonic '%s' @ \"%s\"", c.m,
                 c.line ? c.line : "(null)");
        check_bool(what, got, c.want);
        if (got) {
            char w2[160];
            snprintf(w2, sizeof(w2), "%s -> is_adrp", what);
            check_bool(w2, is_adrp, c.want_adrp);
        }
    }
    // nullptr 助记符不能崩
    bool a = false;
    check_bool("mnemonic == nullptr", is_pcrel_imm_mnemonic(nullptr, "bl #0x1", &a), false);
}

/* ---------- fixup_pcrel_immediates ---------- */

static std::string pcrel(const char *in, uint64_t pc)
{
    char buf[256];
    fixup_pcrel_immediates(in, pc, buf, sizeof(buf));
    return std::string(buf);
}

static void test_pcrel(void)
{
    printf("[4] fixup_pcrel_immediates (PC 相对 -> 绝对地址)\n");
    struct { const char *in; uint64_t pc; const char *want; const char *why; } cases[] = {
        // 分支:目标 = pc + imm(真机 113/113 条实测印证)
        {"bl #-0x1107c", 0x7927a3e7d8ULL, "bl #0x7927a2d75c",
         "向后跳:pc 减"},
        {"bl #0x9eb0",   0x707c59b678ULL, "bl #0x707c5a5528",
         "真机 trace 实测样例"},
        {"b #0x304",     0x7927a60bd0ULL, "b #0x7927a60ed4",
         "向前提:pc 加"},
        {"b.ls #0x304",  0x7927a60bd0ULL, "b.ls #0x7927a60ed4",
         "条件分支同样处理"},
        {"cbz x0, #0x40", 0x1000ULL,      "cbz x0, #0x1040",
         "带寄存器的分支"},
        {"tbz w9, #0x1, #0x30", 0x2000ULL, "tbz w9, #0x1, #0x2030",
         "只改最后一个 #(位号 #0x1 保持)"},
        {"adr x0, #0x1234", 0x3000ULL,    "adr x0, #0x4234",
         "adr 用 pc 公式(不是页基址)"},
        // adrp:目标 = (pc & ~0xfff) + imm,imm 打印为十进制
        {"adrp x8, #339968", 0x7927a5af40ULL, "adrp x8, #0x7927aad000",
         "页基址公式;339968=0x53000,页基址 0x7927a5a000 + 0x53000 = 0x7927aad000"},
        {"adrp x8, #0x53000", 0x7927a5af40ULL, "adrp x8, #0x7927aad000",
         "十六进制形式也能解析"},
        {"adrp x1, #0",      0x7927a5af40ULL, "adrp x1, #0x7927a5a000",
         "imm=0 时结果就是页基址"},
        // 负偏移
        {"adrp x8, #-4096",  0x7927a5af40ULL, "adrp x8, #0x7927a59000",
         "负十进制偏移"},
        // 没有方括号的字面量加载
        {"ldr x0, #0x1234",  0x4000ULL,      "ldr x0, #0x5234",
         "字面量形式改写成绝对地址"},
        // 有方括号的内存形式绝对不能改
        {"ldr x0, [x1, #0x10]",  0x5000ULL,  "ldr x0, [x1, #0x10]",
         "内存偏移保持原样(真机 312426/312426)"},
        {"str q1, [sp, #0x20]",  0x6000ULL,  "str q1, [sp, #0x20]",
         "SIMD 存储偏移保持原样"},
        {"ldrb w0, [x1, #0x1]",  0x7000ULL,  "ldrb w0, [x1, #0x1]",
         "字节加载偏移保持原样"},
        // 不走 PCREL 的助记符原样输出
        {"br x17",       0x8000ULL,          "br x17",
         "寄存器跳转无立即数"},
        {"blr x8",       0x9000ULL,          "blr x8", "同上"},
        {"ret",          0xa000ULL,          "ret",   "无操作数"},
        {"add x0, x1, #0x1", 0xb000ULL,      "add x0, x1, #0x1",
         "普通算术立即数不动"},
        {"mov x0, x1",   0xc000ULL,          "mov x0, x1", "无立即数"},
        {"svc #0",       0xd000ULL,          "svc #0", "svc 不动"},
        // 没有 '#' 的助记符在名单里也要安全返回
        {"bl",           0xe000ULL,          "bl", "无操作数不崩"},
    };
    for (auto &c : cases) {
        std::string got = pcrel(c.in, c.pc);
        char what[192];
        snprintf(what, sizeof(what), "%s @ 0x%llx (%s)", c.in,
                 (unsigned long long)c.pc, c.why);
        check_str(what, got.c_str(), c.want);
    }

    // 【回归】绝对地址比位移长,必须写到独立缓冲。
    // 旧实现用 snprintf(buf, strlen(buf)+1, ...) 原地改写,结果被截断成 "#0x792"。
    {
        const char *in = "b #0x304";
        std::string got = pcrel(in, 0x7927a60bd0ULL);
        check_bool("长结果未被截断(独立缓冲区)",
                   got.find("#0x7927a60ed4") != std::string::npos, true);
        check_bool("结果长度合理", got.size() > strlen(in), true);
    }

    // 【回归】保留 # 之后的非数字后缀(若有)
    {
        std::string got = pcrel("adrp x8, #339968", 0x7927a5af40ULL);
        check_str("adrp 输出为绝对页地址", got.c_str(), "adrp x8, #0x7927aad000");
    }

    // 输出缓冲为 0 时不能崩
    {
        char tiny[1];
        fixup_pcrel_immediates("bl #0x100", 0x1000ULL, tiny, 0);
        ++g_pass;
    }
}

/* ==================================================================
 * 离线回归:在真实 trace 上检查不变量
 *
 * 用法:  test_disasm_fixup <trace文件>
 *
 * 单元测试用手写样本,只能覆盖我想到的情况;真实 trace 上百万行,能覆盖到
 * 想不到的指令组合。这里不重新跑 fixup(输入已是修好的文本,再跑一次 PCREL
 * 会把绝对地址当成位移再换算一次),而是检查**修好之后必须成立的不变量**:
 *
 *   I1 规范化幂等      -> 无 TAB / 无首尾空白(再跑一次 normalize 结果不变)
 *   I2 小立即数已改写  -> 无残留 "#0xN"(N 为单个十六进制位)
 *   I3 分支目标正确    -> b/bl 目标 == 下一行 PC;条件分支 == 下一行 PC(跳了)
 *                          或 pc+4(没跳)
 *   I4 adrp 目标正确   -> == 写回寄存器的值
 *   I5 内存偏移未被误改 -> base寄存器值 + 偏移 == mem_r/mem_w 注解地址
 *   I6 往返一致        -> 把绝对地址反解回位移、重跑 fixup_pcrel_immediates,
 *                          必须得到同一行文本
 *
 * I6 是唯一真正在跑实现的引用式检查(其余五条只看文本)。没有它的话,
 * 谁把 DisasmFixup.cpp 的公式改错,离线回归也发现不了 —— 因为输入已经是
 * 修好的文本。反解公式: 位移 = 目标 - (adrp ? pc&~0xfff : pc)。
 *
 * I3/I5 是重点:前者决定 trace-ui 的调用树,后者能立刻抓出"把内存偏移当成
 * PC 相对立即数改掉"这类错误(历史上真机出现过 312426 条全部原样,是证据)。
 * ================================================================== */

#include <vector>

struct Insn {
    uint64_t pc = 0;
    std::string disasm;
    std::string annot;
};

static bool starts_with(const std::string &s, const char *p)
{
    return s.compare(0, strlen(p), p) == 0;
}

/* 分支类助记符(会改变控制流,目标是"下一条执行的指令")。
 * 注意 adr/adrp/字面量 ldr 也是 PC 相对,但不是控制流,不能参与 I3。 */
static bool is_branch_mnemonic(const std::string &m)
{
    if (m == "b" || m == "bl") return true;
    if (m.size() > 2 && m[0] == 'b' && m[1] == '.') return true;   // b.cond
    if (m == "cbz" || m == "cbnz" || m == "tbz" || m == "tbnz") return true;
    return false;
}

static bool is_unconditional_branch(const std::string &m)
{
    return m == "b" || m == "bl";
}

/* "[mod] 0xPC!0xOFF <disasm>[;<annot>]" */
static bool parse_line(const std::string &raw, Insn *out)
{
    if (raw.empty() || raw[0] != '[') return false;
    size_t rb = raw.find(']');
    if (rb == std::string::npos) return false;
    size_t p = raw.find("0x", rb);
    if (p == std::string::npos) return false;
    char *endp = nullptr;
    uint64_t pc = strtoull(raw.c_str() + p + 2, &endp, 16);
    if (endp == raw.c_str() + p + 2) return false;
    size_t bang = raw.find('!', p);
    if (bang == std::string::npos) return false;
    size_t sp = raw.find(' ', bang);
    if (sp == std::string::npos) return false;

    std::string rest = raw.substr(sp + 1);
    size_t semi = rest.find(';');
    std::string dis = semi == std::string::npos ? rest : rest.substr(0, semi);
    while (!dis.empty() && (dis.back() == ' ' || dis.back() == '\t')) dis.pop_back();
    if (dis.empty()) return false;

    out->pc = pc;
    out->disasm = dis;
    out->annot = semi == std::string::npos ? std::string() : rest.substr(semi + 1);
    return true;
}

static std::string mnemonic_of(const std::string &dis)
{
    size_t sp = dis.find_first_of(" \t");
    return sp == std::string::npos ? dis : dis.substr(0, sp);
}

/* 取文本里最后一个 "#0x..." 的数值(PCREL 目标一定是最后一个)。
 * 修好之后不应再有负位移,出现负号说明没改写到。 */
static bool last_hash_value(const std::string &s, uint64_t *out)
{
    size_t h = s.rfind('#');
    if (h == std::string::npos) return false;
    const char *p = s.c_str() + h + 1;
    if (p[0] == '-') return false;
    if (!(p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))) return false;
    char *endp = nullptr;
    uint64_t v = strtoull(p + 2, &endp, 16);
    if (endp == p + 2) return false;
    *out = v;
    return true;
}

/* 从 "reg=0x..." 取值;要求 key 出现在词首。 */
static bool reg_value(const std::string &s, const char *reg, uint64_t *out)
{
    std::string key = std::string(reg) + "=0x";
    size_t pos = s.find(key);
    if (pos == std::string::npos) return false;
    if (pos != 0 && s[pos - 1] != ' ' && s[pos - 1] != ';') return false;
    char *endp = nullptr;
    uint64_t v = strtoull(s.c_str() + pos + key.size(), &endp, 16);
    if (endp == s.c_str() + pos + key.size()) return false;
    *out = v;
    return true;
}

/* 内存地址注解 mem_r= / mem_w= */
static bool mem_value(const std::string &s, uint64_t *out)
{
    return reg_value(s, "mem_r", out) || reg_value(s, "mem_w", out);
}

/* 解析 "[xN, #0xdisp]"(只支持立即数偏移,寄存器偏移/pre-index 返回 false) */
static bool parse_mem_operand(const std::string &dis, std::string *base, uint64_t *disp)
{
    size_t lb = dis.find('[');
    if (lb == std::string::npos) return false;
    size_t rb = dis.find(']', lb);
    if (rb == std::string::npos) return false;
    std::string inside = dis.substr(lb + 1, rb - lb - 1);
    if (inside.find('!') != std::string::npos) return false;
    size_t comma = inside.find(',');
    if (comma == std::string::npos) {
        *base = inside;
        *disp = 0;
        // 排除 "[0x1234]" 这种绝对地址形式,以及空串
        return !inside.empty() && !starts_with(inside, "0x");
    }
    std::string b = inside.substr(0, comma);
    while (!b.empty() && b.back() == ' ') b.pop_back();
    std::string d = inside.substr(comma + 1);
    while (!d.empty() && d.front() == ' ') d.erase(d.begin());
    if (d.size() < 4 || d[0] != '#' || d[1] != '0' || (d[2] != 'x' && d[2] != 'X')) return false;
    char *endp = nullptr;
    uint64_t v = strtoull(d.c_str() + 3, &endp, 16);
    if (endp == d.c_str() + 3) return false;
    *base = b;
    *disp = v;
    return true;
}

static int run_trace_regression(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { printf("打不开 %s\n", path); return 2; }

    long long n_insn = 0, n_i1 = 0, n_i2 = 0;
    long long n_br = 0, n_br_taken = 0, n_br_fall = 0, n_br_bad = 0;
    long long n_adrp = 0, n_adrp_ok = 0;
    long long n_mem = 0, n_mem_ok = 0, n_mem_skip = 0, n_mem_bad = 0;
    long long n_rt = 0, n_rt_ok = 0;
    int bad_br_shown = 0, bad_mem_shown = 0, bad_rt_shown = 0;
    Insn prev;
    bool have_prev = false;

    std::vector<char> buf(1 << 16);
    while (fgets(buf.data(), (int)buf.size(), f)) {
        std::string line = buf.data();
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();

        Insn cur;
        if (!parse_line(line, &cur)) continue;
        ++n_insn;
        std::string mn = mnemonic_of(cur.disasm);

        /* I1: 规范化幂等 */
        {
            std::string t = cur.disasm;
            normalize_disasm(&t[0]);
            if (t == cur.disasm) ++n_i1;
        }
        /* I2: 无残留 #0x单数字 */
        {
            std::string t = cur.disasm;
            fixup_small_immediates(&t[0]);
            if (t == cur.disasm) ++n_i2;
        }
        /* I4: adrp 目标 == 写回值(独立于 I3,因为 adrp 不改控制流) */
        {
            bool is_adrp = false;
            if (is_pcrel_imm_mnemonic(mn.c_str(), cur.disasm.c_str(), &is_adrp) && is_adrp) {
                uint64_t tgt = 0;
                if (last_hash_value(cur.disasm, &tgt)) {
                    /* 写回值取 "-> xN=0x..." 里的第一个 "=0x..." */
                    size_t arrow = cur.annot.find("->");
                    size_t eq = arrow == std::string::npos
                                ? std::string::npos : cur.annot.find("=0x", arrow);
                    if (eq != std::string::npos) {
                        uint64_t got = strtoull(cur.annot.c_str() + eq + 3, nullptr, 16);
                        ++n_adrp;
                        if (got == tgt) ++n_adrp_ok;
                        else printf("  [I4 违规] pc=0x%llx \"%s\" 目标 0x%llx != 写回 0x%llx\n",
                                    (unsigned long long)cur.pc, cur.disasm.c_str(),
                                    (unsigned long long)tgt, (unsigned long long)got);
                    }
                }
            }
        }
        /* I3: 分支目标(用上一条指令的目标比对当前 PC) */
        if (have_prev && is_branch_mnemonic(mnemonic_of(prev.disasm))) {
            uint64_t tgt = 0;
            if (last_hash_value(prev.disasm, &tgt)) {
                std::string pmn = mnemonic_of(prev.disasm);
                ++n_br;
                /* 条件分支没跳时,下一条执行的就是 pc+4 */
                if (tgt == cur.pc) ++n_br_taken;
                else if (!is_unconditional_branch(pmn) && cur.pc == prev.pc + 4) ++n_br_fall;
                else {
                    ++n_br_bad;
                    if (bad_br_shown < 5) {
                        ++bad_br_shown;
                        printf("  [I3 违规] pc=0x%llx \"%s\" 目标 0x%llx, 下一行 0x%llx (pc+4=0x%llx)\n",
                               (unsigned long long)prev.pc, prev.disasm.c_str(),
                               (unsigned long long)tgt, (unsigned long long)cur.pc,
                               (unsigned long long)(prev.pc + 4));
                    }
                }
            }
        }
        /* I5: 内存偏移未被误改 */
        {
            bool is_mem = starts_with(mn, "ldr") || starts_with(mn, "str") ||
                          starts_with(mn, "ldur") || starts_with(mn, "stur");
            std::string base;
            uint64_t disp = 0;
            if (is_mem && parse_mem_operand(cur.disasm, &base, &disp)) {
                /* 只在 "->" 之前(读取部分)找寄存器值:写回的是新值,不是基址 */
                size_t arrow = cur.annot.find("->");
                std::string read_part = arrow == std::string::npos
                                        ? cur.annot : cur.annot.substr(0, arrow);
                uint64_t bv = 0, mem = 0;
                if (reg_value(read_part, base.c_str(), &bv) && mem_value(read_part, &mem)) {
                    ++n_mem;
                    if (bv + disp == mem) ++n_mem_ok;
                    else {
                        ++n_mem_bad;
                        if (bad_mem_shown < 5) {
                            ++bad_mem_shown;
                            printf("  [I5 违规] pc=0x%llx \"%s\": %s=0x%llx + 0x%llx != mem 0x%llx\n",
                                   (unsigned long long)cur.pc, cur.disasm.c_str(),
                                   base.c_str(), (unsigned long long)bv,
                                   (unsigned long long)disp, (unsigned long long)mem);
                        }
                    }
                } else {
                    ++n_mem_skip;
                }
            }
        }

        /* I6: 往返一致 —— 反解位移后重跑 fixup,应还原出同一行。
         * 这是唯一真正执行 DisasmFixup.cpp 公式的引用式检查。 */
        {
            bool is_adrp = false;
            if (is_pcrel_imm_mnemonic(mn.c_str(), cur.disasm.c_str(), &is_adrp)) {
                uint64_t tgt = 0;
                size_t h = cur.disasm.rfind('#');
                if (h != std::string::npos && last_hash_value(cur.disasm, &tgt)) {
                    uint64_t base = is_adrp ? (cur.pc & ~(uint64_t)0xfff) : cur.pc;
                    /* 反解出原始位移(与真实现无关,只用 I3/I4 已验证的公式) */
                    char disp[48];
                    if (tgt >= base) snprintf(disp, sizeof(disp), "0x%llx",
                                              (unsigned long long)(tgt - base));
                    else snprintf(disp, sizeof(disp), "-0x%llx",
                                  (unsigned long long)(base - tgt));
                    std::string rewritten = cur.disasm.substr(0, h + 1) + disp;
                    char out[512];
                    fixup_pcrel_immediates(rewritten.c_str(), cur.pc, out, sizeof(out));
                    ++n_rt;
                    if (cur.disasm == out) ++n_rt_ok;
                    else if (bad_rt_shown < 5) {
                        ++bad_rt_shown;
                        printf("  [I6 违规] pc=0x%llx \"%s\": 反解\"%s\" 重跑得 \"%s\"\n",
                               (unsigned long long)cur.pc, cur.disasm.c_str(),
                               rewritten.c_str(), out);
                    }
                }
            }
        }

        prev = cur;
        have_prev = true;
    }
    fclose(f);

    printf("\n=== 离线回归: %s ===\n", path);
    printf("  指令行数                    %lld\n", n_insn);
    printf("  I1 规范化幂等               %lld/%lld %s\n", n_i1, n_insn,
           n_i1 == n_insn ? "✅" : "❌");
    printf("  I2 无残留 #0x单数字         %lld/%lld %s\n", n_i2, n_insn,
           n_i2 == n_insn ? "✅" : "❌");
    printf("  I3 分支目标(跳 %lld / 未跳 %lld / 异常 %lld) %s\n",
           n_br_taken, n_br_fall, n_br_bad, n_br_bad == 0 ? "✅" : "❌");
    printf("  I4 adrp 目标==写回值        %lld/%lld %s\n", n_adrp_ok, n_adrp,
           n_adrp_ok == n_adrp ? "✅" : "❌");
    printf("  I5 内存偏移 base+disp==mem  %lld/%lld (跳过 %lld) %s\n",
           n_mem_ok, n_mem, n_mem_skip, n_mem_bad == 0 ? "✅" : "❌");
    printf("  I6 PCREL 往返一致           %lld/%lld %s\n", n_rt_ok, n_rt,
           n_rt == n_rt_ok ? "✅" : "❌");

    int fail = 0;
    if (n_i1 != n_insn) fail |= 1;
    if (n_i2 != n_insn) fail |= 2;
    if (n_br_bad) fail |= 4;
    if (n_adrp != n_adrp_ok) fail |= 8;
    if (n_mem_bad) fail |= 16;
    if (n_rt != n_rt_ok) fail |= 32;
    printf("\n%s\n", fail == 0 ? "全部不变量成立 ✅" : "存在违规 ❌");
    return fail == 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc >= 2) {
        return run_trace_regression(argv[1]);
    }
    printf("=== DisasmFixup 单元测试 ===\n");
    printf("(编译的是 hook/DisasmFixup.cpp 真实实现,非重写版)\n\n");
    test_normalize();
    test_small_imm();
    test_pcrel_mnemonic();
    test_pcrel();
    printf("\n通过 %d 项, 失败 %d 项\n", g_pass, g_fail);
    printf("\n传一个 trace 文件作为参数可跑离线回归: %s <trace>\n", argv[0]);
    return g_fail == 0 ? 0 : 1;
}