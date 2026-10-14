//
// Created by fang on 23-12-19.
//
#include "fstream"
#include <iostream>
#include <iomanip>
#include <cassert>
#include <atomic>
#include <sstream>
#include <unordered_map>
#include <sys/uio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <cstring>
#include <strings.h>
#include <cstdio>
#include <cinttypes>
#include <cstddef>
#include <sstream>
#include <string>
#include <QBDI/Callback.h>
#include "vm.h"
#include "logger.h"
#include "qbdihook.h"
#include "jnitrace.h"
#include "libctrace.h"
#include "Symbols.h"
#include "SyscallTable.h"
#include "TraceLogger.h"
#include "TraceUtils.h"
#include "HookUtils.h"
#include "shadowhook.h"
using namespace std;
using namespace QBDI;
g_trace_data* _g_trace_data = nullptr;
int bufsize = 0x1000000;
bool debugInsn = false;

/* trace-ui GumTrace 模块名 — 由 native_main 安装时设置 */
static const char* g_trace_module_name = "du_anon";
void set_trace_module_name(const char* name) {
    if (name && *name) g_trace_module_name = name;
}
static const char* trace_module_name() { return g_trace_module_name; }

func_arg_8 ori_arg8{};


void setBufferSize(int size)
{
    bufsize = size;
}

void enableDebugInsn(bool enable)
{
    debugInsn = enable;
}

void sync_regs(size_t* regs, size_t pc,QBDI::GPRState* qbdi_state)
{
    for(int i=0;i<31;i++)
    {
        QBDI_GPR_SET(qbdi_state,i,regs[i]);
    }
    qbdi_state->pc = pc;
}

static inline uintptr_t get_current_sp() {
    uintptr_t sp;
    __asm__ __volatile__("mov %0, sp" : "=r"(sp)); // 读取SP寄存器到sp变量
    return sp;
}

uintptr_t inline get_current_x30() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x30" : "=r"(reg));
    return reg;
}
// pending:暂存上一条指令待补全的信息
struct PendingInst {
    bool valid = false;
    char line[4096];
    int  lineLen = 0;
    /* 待补全的写寄存器（GPR 与 SIMD/FPR 混排，索引空间不同需区分） */
    struct WriteReg {
        uint8_t is_fpr;
        uint8_t idx;
        uint8_t size;      // 字节；GPR 固定 8，FPR 取 QBDI 的 op.size
        char    name[12];  // 已按反汇编写法对齐（如 v0 / q1 / d2）
    };
    WriteReg writes[12];
    int  numWrite = 0;
    char memInfo[1024];      // 内存访问行(可能多条)
    int  memLen = 0;
    char annot[8192];        // GumTrace 风格调用注解(call func/args/hexdump)
    int  annotLen = 0;
    bool hasCall = false;    // 该指令是否为已识别的调用(决定是否输出 ret)
    /* JNI 调用的事后处理（返回值只有调用返回后才知道） */
    bool isJniCall = false;
    char jniName[48];
    uint64_t jniPreArgs[8];
};

static PendingInst pending;

/* libc/JNI/自定义 hook 在 annot 模式下把特殊行写到这里，
 * 由 flushPending 在对应指令行之后输出（GumTrace 的 call func 语义）。 */
bool g_annot_mode = false;

void pending_annot_append(const char *str, size_t len) {
    if (str == nullptr || len == 0) {
        return;
    }
    int room = (int)sizeof(pending.annot) - pending.annotLen - 1;
    if (room <= 0) {
        return;
    }
    if ((int)len > room) {
        len = (size_t)room;
    }
    memcpy(pending.annot + pending.annotLen, str, len);
    pending.annotLen += (int)len;
    pending.annot[pending.annotLen] = '\0';
}

/* QBDI/LLVM 的寄存器名是大写(X0/W0/SP/FP/LR/XZR/NZCV)，
 * 而反汇编文本是小写(x0/sp/x29/x30)。trace-ui 用反汇编里的小写名
 * 精确匹配注解中的 "name=0xHEX"，所以这里必须转小写，
 * 否则寄存器值与内存值都取不到(get_memory 全 0)。 */
static void lower_reg_name(char *dst, size_t dst_size, const char *src) {
    if (dst_size == 0) {
        return;
    }
    if (src == nullptr) {
        dst[0] = '\0';
        return;
    }
    size_t i = 0;
    for (; src[i] != '\0' && i + 1 < dst_size; ++i) {
        char c = src[i];
        dst[i] = (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    }
    dst[i] = '\0';
}

// 把 pending(上一条指令)用当前寄存器状态补全并输出。
// 输出顺序与 GumTrace 一致:
//   [mod] abs!off asm; 读寄存器 mem_r/w=地址 -> 写寄存器
//   call func: name(args) / argsN: ... / hexdump ... / ret: 0x...
/* SIMD/FPR 寄存器值：QBDI 的 FPRState 里 v0..v31 连续存放（16 字节 × 32）。
 * 用 static_assert 锁住布局，避免 QBDI 升级后静默错位。 */
static_assert(offsetof(QBDI::FPRState, v1) == 16, "QBDI FPRState layout changed (v1)");
static_assert(offsetof(QBDI::FPRState, fpcr) == 32 * 16, "QBDI FPRState layout changed (fpcr)");

// 128-bit 十六进制（无前导零，与 GumTrace 的 format_uint128_hex 一致）
static void format_u128_hex(char *dst, size_t dst_size, __uint128_t v)
{
    uint64_t hi = (uint64_t)(v >> 64);
    uint64_t lo = (uint64_t)v;
    if (hi != 0) {
        snprintf(dst, dst_size, "%" PRIx64 "%016" PRIx64, hi, lo);
    } else {
        snprintf(dst, dst_size, "%" PRIx64, lo);
    }
}

// 取出第 idx 个 SIMD 寄存器值，按 size（字节）截断后格式化为十六进制
static void simd_value_hex(char *dst, size_t dst_size,
                           const QBDI::FPRState *fprState, int idx, uint8_t size)
{
    if (dst_size == 0) {
        return;
    }
    dst[0] = '\0';
    if (fprState == nullptr || idx < 0 || idx >= 32) {
        return;
    }
    __uint128_t raw = 0;
    memcpy(&raw, reinterpret_cast<const uint8_t *>(fprState) + (size_t)idx * 16, sizeof(raw));
    if (size == 0 || size > 16) {
        size = 16;
    }
    if (size < 16) {
        raw &= (((__uint128_t)1 << (size * 8)) - 1);
    }
    format_u128_hex(dst, dst_size, raw);
}

/* 反汇编文本里的 SIMD 寄存器 token（v0/q1/d2/s3/h4/b5，可带 .16b 之类的排列说明）。
 * 必要性：QBDI 一律给 LLVM 的 MC 名（"Q0"），但反汇编里可能写作 "v0.16b"；
 * 而 trace-ui 严格按反汇编里的写法去注解中找 "名字=0x值"。
 * 实测：ld1 {q2}, [x0] 配 "v2=0x..." 取不到值，配 "q2=0x..." 才行。 */
struct SimdRegToken {
    char name[8];
    int  num;
    bool used;
};

static int collect_disasm_simd_tokens(const char *text, SimdRegToken *out, int max)
{
    int n = 0;
    if (text == nullptr || out == nullptr) {
        return 0;
    }
    for (const char *p = text; *p != '\0'; ++p) {
        char c = *p;
        if (c != 'v' && c != 'q' && c != 'd' && c != 's' && c != 'h' && c != 'b') {
            continue;
        }
        // 前一个字符必须是分隔符，避免把 "ld1" 的 d1、"add" 的 d 当成寄存器
        if (p != text) {
            char prev = *(p - 1);
            if ((prev >= 'a' && prev <= 'z') || (prev >= 'A' && prev <= 'Z') ||
                (prev >= '0' && prev <= '9')) {
                continue;
            }
        }
        const char *d = p + 1;
        if (*d < '0' || *d > '9') {
            continue;
        }
        int num = *d - '0';
        int digits = 1;
        if (d[1] >= '0' && d[1] <= '9') {
            num = num * 10 + (d[1] - '0');
            digits = 2;
        }
        if (num > 31) {
            continue;
        }
        if (n < max) {
            snprintf(out[n].name, sizeof(out[n].name), "%c%d", c, num);
            out[n].num = num;
            out[n].used = false;
            n++;
        }
        p = d + digits - 1;
    }
    return n;
}

// 为第 idx 个 SIMD 寄存器取名字：优先反汇编写法（编号一致），否则退回 QBDI 名（小写）。
// 同一个寄存器可能在一条指令里出现多次（如 eor v0.16b, v0.16b, v1.16b），
// 因此 token 不做“消费”，按编号复用即可（trace-ui 允许重复的 name=0x）。
static const char *simd_operand_name(SimdRegToken *tokens, int num_tokens,
                                     const char *qbdi_name, int idx,
                                     char *buf, size_t buf_size)
{
    for (int i = 0; i < num_tokens; ++i) {
        if (tokens[i].num == idx) {
            tokens[i].used = true;
            lower_reg_name(buf, buf_size, tokens[i].name);
            return buf;
        }
    }
    lower_reg_name(buf, buf_size, qbdi_name);
    return buf;
}

// 把 pending(上一条指令)用当前寄存器状态补全并输出。
// 输出顺序与 GumTrace 一致:
//   [mod] abs!off asm; 读寄存器 mem_r/w=地址 -> 写寄存器
//   call func: name(args) / argsN: ... / hexdump ... / ret: 0x...
static void flushPending(QBDI::GPRState *gprState, QBDI::FPRState *fprState)
{
    if (!pending.valid) return;

    appendlog_n(pending.line, pending.lineLen);   // 上一条的 "[mod] abs!off asm ; 读"

    /* 内存访问注解为 mem_r=/mem_w= 前缀 (内联在指令行尾, trace-ui 格式)。
     * 不加额外前导空格：前面的内容（读寄存器段或 "; "）总是已以空格结尾，
     * GumTrace 也是单空格（如 "sp=0x... mem_w=0x..."）。 */
    if (pending.memLen > 0) {
        appendlog_n(pending.memInfo, pending.memLen);
    }

    if (pending.numWrite > 0) {
        char wbuf[512];
        int woff = 0;
        for (int i = 0; i < pending.numWrite; ++i) {
            const PendingInst::WriteReg &w = pending.writes[i];
            char vhex[40];
            if (w.is_fpr) {
                // 此刻 = 上一条执行后的值
                simd_value_hex(vhex, sizeof(vhex), fprState, w.idx, w.size);
            } else {
                uint64_t gv = (uint64_t)QBDI_GPR_GET(gprState, w.idx);
                if (w.size == 4) {
                    gv &= 0xFFFFFFFFULL;
                }
                snprintf(vhex, sizeof(vhex), "%" PRIx64, gv);
            }
            int n = snprintf(wbuf + woff, sizeof(wbuf) - woff, "%s=0x%s ", w.name, vhex);
            if (n > 0) woff += ((size_t)n < sizeof(wbuf) - woff) ? n : (int)(sizeof(wbuf) - woff - 1);
            if (woff >= (int)sizeof(wbuf) - 48) { break; }
        }
        appendlog("-> ");
        appendlog_n(wbuf, woff);
    }
    appendlogendl();

    /* JNI 调用的事后处理：此刻寄存器 = 该 JNI 调用执行后，x0 是返回值
     * （jclass / jmethodID / jfieldID），用来建立名称映射并把解析结果
     * 以 argsN: 行补进注解（trace-ui 只显示 call func/argsN/ret/hexdump）。 */
    if (pending.isJniCall && pending.jniName[0] != '\0') {
        g_annot_mode = true;
        jni_after_call(pending.jniName, pending.jniPreArgs, (uint64_t)QBDI_GPR_GET(gprState, 0));
        g_annot_mode = false;
    }

    /* GumTrace 风格调用注解：紧跟在指令行之后，trace-ui 会把它关联到该分支指令 */
    if (pending.annotLen > 0) {
        appendlog_n(pending.annot, pending.annotLen);
        if (pending.annot[pending.annotLen - 1] != '\n') {
            appendlogendl();
        }
    }
    if (pending.hasCall) {
        // 此刻寄存器 = 该调用执行后，x0 即返回值（与 GumTrace 的 ret 语义一致）
        char rbuf[64];
        snprintf(rbuf, sizeof(rbuf), "ret: 0x%" PRIx64 "\n", (uint64_t)QBDI_GPR_GET(gprState, 0));
        appendlog(rbuf);
    }

    pending.valid = false;
    pending.annotLen = 0;
    pending.annot[0] = '\0';
    pending.hasCall = false;
    pending.isJniCall = false;
    pending.jniName[0] = '\0';
}
static void save_regs(size_t* regs)
{
    regs[0] = get_current_x0();
    regs[1] = get_current_x1();
    regs[2] = get_current_x2();
    regs[3] = get_current_x3();
    regs[4] = get_current_x4();
    regs[5] = get_current_x5();
    regs[6] = get_current_x6();
    regs[7] = get_current_x7();
    regs[8] = get_current_x8();
    regs[9] = get_current_x9();
    regs[10] = get_current_x10();
    regs[11] = get_current_x11();
    regs[12] = get_current_x12();
    regs[13] = get_current_x13();
    regs[14] = get_current_x14();
    regs[15] = get_current_x15();
    regs[16] = get_current_x16();
    regs[17] = get_current_x17();
    regs[18] = get_current_x18();
    regs[19] = get_current_x19();
    regs[20] = get_current_x20();
    regs[21] = get_current_x21();
    regs[22] = get_current_x22();
    regs[23] = get_current_x23();
    regs[24] = get_current_x24();
    regs[25] = get_current_x25();
    regs[26] = get_current_x26();
    regs[27] = get_current_x27();
    regs[28] = get_current_x28();
    regs[29] = get_current_x29();
    regs[30] = get_current_x30();
}

size_t trace(size_t regs[31])
{
    size_t function_address = _g_trace_data->start + _g_trace_data->target;
    LOGE("start trace:%p",(void*)function_address);
    shadowhook_unhook(_g_trace_data->hooktask);
    struct timeval start, end;
    gettimeofday(&start, nullptr);
    vm* vm_ = new vm();
    /* 符号表只读 /proc/self/maps 与 ELF 文件，不碰动态链接器锁
     * （dladdr/dl_iterate_phdr 会取锁，在回调里调用有死锁风险）。 */
    symbols_init();
    auto qvm = vm_->init(_g_trace_data->start,_g_trace_data->end);
    auto qbdi_state = qvm.getGPRState();
    initLogger(function_address);
    vm_->base = _g_trace_data->base;
    sync_regs(regs,function_address,qbdi_state);
    //在当前栈上开辟栈，不使用allocateVirtualStack，防止libart中Thread crash
    size_t sp = get_current_sp();
    size_t stack_size = 0x4000;
    QBDI_GPR_SET(qbdi_state, QBDI::REG_SP, sp - stack_size);
    QBDI_GPR_SET(qbdi_state, QBDI::REG_BP, QBDI_GPR_GET(qbdi_state, QBDI::REG_SP));
    QBDI::rword qbdi_retval;
    LOGE("trace begin");
    bool qbdi_success = qvm.call(&qbdi_retval, (uint64_t)function_address);
    LOGE("trace end");
    flushPending(qbdi_state, qvm.getFPRState());
    if (qbdi_success) {
        writelog();
        LOGE("trace completed successfully %s",_logger->logfile.c_str());
    } else {
        LOGE("trace failed");
    }
    gettimeofday(&end, nullptr);
    long elapsed_sec;
    elapsed_sec = (end.tv_sec - start.tv_sec) +
                  (end.tv_usec - start.tv_usec) / 1000000;
    LOGI("trace time cost:%lds",elapsed_sec);
    deleteLogger();
    delete vm_;
    return qbdi_retval;
}

/* ===== IL(id) 判断 =====
 * IL 的 Object[] 首元素是 Integer(id)。入口用 JNI 读取并判断目标 id。
 * 目标 id 由 GVM_TARGET_ID 指定: 511 = com.shizhuang.duapp.common.net.ncl.ms.f(签名/dhw 计算; 510 为 ms.e, 内部转调 511)
 * 缓存: Integer 类为全局引用(局部引用只在本次 native 调用内有效); intValue 为 jmethodID。
 * 每次调用都会做 JNI, 命中 466 后 trace 一次并卸挂钩, 之后无开销。 */
static const int GVM_TARGET_ID = 511;   /* ms.f: (Z,HttpUrl,HashMap,J,String,scu$a)->String; ms.e 内部转调 ms.f */
static jclass g_integerCls = nullptr;
static jmethodID g_intValueMid = nullptr;
static std::atomic<bool> g_idCacheReady{false};

/* 获取 JavaVM(只查询一次) */
static JavaVM* get_java_vm()
{
    static JavaVM* cached = nullptr;
    if (cached) return cached;
    typedef jint (*JNI_GetCreatedJavaVMs_t)(JavaVM**, jsize, jsize*);
    auto getVMs = (JNI_GetCreatedJavaVMs_t)dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs");
    if (!getVMs) return nullptr;
    JavaVM* vm = nullptr;
    jsize count = 0;
    if (getVMs(&vm, 1, &count) != JNI_OK || count == 0) return nullptr;
    cached = vm;
    return cached;
}

static bool ensureIdCache(JNIEnv* env)
{
    if (g_idCacheReady.load()) return true;
    jclass local = env->FindClass("java/lang/Integer");
    if (env->ExceptionCheck() || !local) { env->ExceptionClear(); return false; }
    jmethodID mid = env->GetMethodID(local, "intValue", "()I");
    if (env->ExceptionCheck() || !mid) { env->ExceptionClear(); env->DeleteLocalRef(local); return false; }
    jclass global = (jclass)env->NewGlobalRef(local);
    env->DeleteLocalRef(local);
    if (!global) return false;
    g_integerCls = global;
    g_intValueMid = mid;
    g_idCacheReady.store(true);
    return true;
}

/* 返回 true 表示 x2 数组首元素的 int 值为 GVM_TARGET_ID。任何失败都返回 false(透传)。 */
static bool il_id_matches(size_t x2)
{
    JNIEnv* env = nullptr;
    JavaVM* vm = get_java_vm();
    if (!vm) return false;
    /* 当前线程的 JNIEnv(IL 在 GameVMP 调用线程上执行, 不能复用 initJni 里 Attach 的 env) */
    if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK || !env) return false;
    if (!ensureIdCache(env)) return false;

    jobjectArray arr = (jobjectArray)x2;
    jsize len = env->GetArrayLength(arr);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
    if (len < 1) return false;
    jobject e0 = env->GetObjectArrayElement(arr, 0);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
    if (!e0) return false;

    jboolean isInt = env->IsInstanceOf(e0, g_integerCls);
    if (env->ExceptionCheck()) { env->ExceptionClear(); env->DeleteLocalRef(e0); return false; }
    if (!isInt) { env->DeleteLocalRef(e0); return false; }

    jint v = env->CallIntMethod(e0, g_intValueMid);
    if (env->ExceptionCheck()) { env->ExceptionClear(); env->DeleteLocalRef(e0); return false; }
    env->DeleteLocalRef(e0);
    return v == GVM_TARGET_ID;
}

size_t hook_and_trace_arg8(size_t x0,size_t x1,size_t x2,size_t x3,size_t x4,size_t x5,size_t x6,size_t x7)
{
    static std::atomic<bool> tracedOnce{false};
    if (tracedOnce.load()) {
        return ori_arg8(x0,x1,x2,x3,x4,x5,x6,x7);
    }
    if (!il_id_matches(x2)) {
        return ori_arg8(x0,x1,x2,x3,x4,x5,x6,x7);
    }
    if (tracedOnce.exchange(true)) {
        return ori_arg8(x0,x1,x2,x3,x4,x5,x6,x7);
    }

    size_t regs[31] = {0};
    save_regs(regs);
    regs[0] = x0; regs[1] = x1; regs[2] = x2; regs[3] = x3;
    regs[4] = x4; regs[5] = x5; regs[6] = x6; regs[7] = x7;
    LOGE("gvm: IL id==%d hit, starting one-shot trace", (int)GVM_TARGET_ID);
    return trace(regs);
}

bool checkAndCallHook(QBDI::VM *vm, QBDI::GPRState *gprState,size_t addr,size_t lastaddr)
{
    auto it = _g_hook_data->hookMap.find(addr);
    if(it != _g_hook_data->hookMap.end())
    {
        if(it->second->ignore != nullptr && it->second->ignorenum != 0)
        {
            for(int i=0;i<it->second->ignorenum;i++)
            {
                if(it->second->ignore[i] == lastaddr)
                {
                    return false;
                }
            }
        }
        it->second->callback(vm,gprState);
        return true;
    }
    return false;
}

bool checkLibcTrace_pre(QBDI::VM *vm, QBDI::GPRState *gprState,size_t target)
{
    auto it = _g_libc_trace->map.find(target);
    if(it != _g_libc_trace->map.end())
    {
        it->second->callback(vm,gprState);
        return true;
    }
    return false;
}

bool checkJniCall_pre(QBDI::VM *vm, QBDI::GPRState *gprState,size_t target)
{
    if(pJFunc == nullptr)
    {
        LOGE("checkJniCall,pJFunc not init");
        return false;
    }
    auto it = _g_jni_trace->map.find(target);
    if(it != _g_jni_trace->map.end())
    {
        it->second->callback(vm,gprState);
        return true;
    }
    return false;
}

static size_t lastAddr = 0;

static unordered_map<uint32_t,char*> disassemblecache;

/* LLVM 的 AArch64 打印器用 TAB 分隔助记符与操作数（"\tsub\tsp, sp, #0x40"），
 * 而 GumTrace/capstone 用空格（"sub sp, sp, #0x40"）。
 * trace-ui 按「第一个空格」切分助记符，TAB 会让它取到 "sub\tsp," 这种错误助记符，
 * 于是指令分类失败 → bl/br/svc 的 call 注解全部挂不上、变成孤儿行被隐藏。
 * 因此在缓存时就规范化为单空格并去掉首尾空白。 */
static void normalize_disasm(char *s)
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

/* ===== 调用注解：SVC 系统调用 / 符号级 call func ===== */

// 计算 BL/BLR/BR 的跳转目标；无法确定返回 0。
// 注意：AArch64 的分支立即数经 LLVM 解码后已是**绝对**目标地址
// （QBDI 的 getFixedOperandValue 直接返回该值，与 disasm 里
//  "bl #0x7522f46438" 显示的一致，也与下一条指令的地址一致）。
static uint64_t branch_target(const QBDI::InstAnalysis *ia, QBDI::GPRState *gprState)
{
    if (ia == nullptr || ia->numOperands <= 0) {
        return 0;
    }
    const QBDI::OperandAnalysis &op = ia->operands[0];
    if (op.type == QBDI::OPERAND_IMM && (op.flag & QBDI::OPERANDFLAG_PCREL)) {
        return (uint64_t)op.value;
    }
    if (op.type == QBDI::OPERAND_GPR && op.regCtxIdx >= 0) {
        return (uint64_t)QBDI_GPR_GET(gprState, op.regCtxIdx);
    }
    return 0;
}

// call func: <name>(0x.., 0x..)
static void emit_call_begin(const char *name, const uint64_t *x, int argc)
{
    char buf[384];
    int off = snprintf(buf, sizeof(buf), "call func: %s(", name);
    if (off < 0) {
        return;
    }
    for (int i = 0; i < argc && off < (int)sizeof(buf) - 24; ++i) {
        int n = snprintf(buf + off, sizeof(buf) - off, "%s0x%" PRIx64,
                         i ? ", " : "", x[i]);
        if (n > 0) {
            off += ((size_t)n < sizeof(buf) - off) ? n : (int)(sizeof(buf) - off - 1);
        }
    }
    snprintf(buf + off, sizeof(buf) - off, ")");
    appendlog(buf);
    appendlogendl();
}

// SVC：按 x8 的系统调用号打印调用注解（等价 GumTrace 的 svc_func_maps 分支）
static bool emit_syscall_call(QBDI::GPRState *gprState)
{
    uint64_t x[8];
    for (int i = 0; i < 8; ++i) {
        x[i] = (uint64_t)QBDI_GPR_GET(gprState, i);
    }
    const char *name = syscall_name(x[8]);
    if (name == nullptr) {
        return false;   // 与 GumTrace 一致：未知系统调用号不产生注解
    }
    emit_call_begin(name, x, syscall_argc(x[8], x));
    known_func_emit_args(name, x);
    return true;
}

// 符号级 call func：跳转目标命中已加载模块的函数符号起始地址
// （等价 GumTrace 的 func_maps 精确匹配）。
// 对匿名区（如 ijiami VM 解包出的 r-x 段）不会有任何符号，自然不产生注解。
static bool emit_symbol_call(const QBDI::InstAnalysis *ia, QBDI::GPRState *gprState)
{
    uint64_t target = branch_target(ia, gprState);
    if (target == 0) {
        return false;
    }
    const char *name = symbols_lookup_exact(target);
    if (name == nullptr) {
        return false;
    }
    uint64_t x[8];
    for (int i = 0; i < 8; ++i) {
        x[i] = (uint64_t)QBDI_GPR_GET(gprState, i);
    }

    /* libc 的 syscall() 包装器：真正调用的系统调用号在 x0，
     * 名字从号解析、参数整体左移一位（等价 GumTrace 的 FuncPrinter::syscall）。 */
    if (strcmp(name, "syscall") == 0) {
        const char *sc = syscall_name(x[0]);
        if (sc == nullptr) {
            return false;
        }
        uint64_t shifted[8];
        for (int i = 0; i < 7; ++i) {
            shifted[i] = x[i + 1];
        }
        shifted[7] = 0;
        emit_call_begin(sc, shifted, syscall_argc(x[0], shifted));
        known_func_emit_args(sc, shifted);
        return true;
    }

    // 未知符号按 GumTrace 的习惯打印 ()，已知函数才打印参数与解码结果
    int argc = known_func_argc(name);
    if (argc < 0) {
        argc = 0;
    }
    emit_call_begin(name, x, argc);
    known_func_emit_args(name, x);
    return true;
}

// 显示指令执行前的寄存器状态
QBDI::VMAction showPreInstruction(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data)
{
    auto thiz = (class vm *)data;

    //上一条指令的信息全部拿到了，写入
    flushPending(gprState, fprState);

    // 注解区归当前指令所有
    pending.annotLen = 0;
    pending.annot[0] = '\0';
    pending.hasCall = false;
    pending.isJniCall = false;
    pending.jniName[0] = '\0';

    // 获取当前指令的分析信息
    const QBDI::InstAnalysis *instAnalysis = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION  | QBDI::ANALYSIS_OPERANDS);
    uint32_t bytecode = *(uint32_t*)instAnalysis->address;

    //用缓存的反汇编，减低开销
    char* disasm;
    auto it = disassemblecache.find(bytecode);
    if (it != disassemblecache.end()) {
        disasm = it->second;
    } else {
        const QBDI::InstAnalysis *full = vm->getInstAnalysis(QBDI::ANALYSIS_DISASSEMBLY);
        size_t len = strlen(full->disassembly) + 1;
        disasm = (char*)malloc(len);
        memcpy(disasm, full->disassembly, len);
        normalize_disasm(disasm);
        disassemblecache.emplace(bytecode, disasm);
    }

    int off = 0;
    /* trace-ui GumTrace 格式: [模块名] 0x绝对地址!0x相对偏移 助记符 操作数; 读寄存器 mem_r/w=地址 -> 写寄存器 */
    off += snprintf(pending.line + off, sizeof(pending.line) - off,
                    "[%s] 0x%lx!0x%lx %s", trace_module_name(),
                    (size_t)instAnalysis->address,
                    (instAnalysis->address - thiz->base), disasm);

    /* GumTrace 总是先输出 "; "（即使没有任何寄存器注解），
     * 否则 trace-ui 的无分号路径会把 "-> " 当成指令文本的一部分 */
    off += snprintf(pending.line + off, sizeof(pending.line) - off, "; ");

    /* SIMD 寄存器名要和反汇编里的写法一致（ld1 {q2} 就得写 q2，ld1 {v0.16b} 就得写 v0）。
     * 注意用缓存的 disasm：instAnalysis->disassembly 在本回调的
     * ANALYSIS_INSTRUCTION|ANALYSIS_OPERANDS 请求下并不保证可用。 */
    SimdRegToken simd_tokens[16];
    int num_simd_tokens = collect_disasm_simd_tokens(disasm, simd_tokens, 16);

    char rbuf[2048];
    int roff = 0;
    for (int i = 0; i < instAnalysis->numOperands; ++i)
    {
        auto& op = instAnalysis->operands[i];
        if (op.regCtxIdx < 0 || op.regName == nullptr) {
            continue;
        }
        const bool readable = (op.regAccess == QBDI::REGISTER_READ || op.regAccess == QBDI::REGISTER_READ_WRITE);
        if (!readable) {
            continue;
        }
        if (op.type == QBDI::OPERAND_GPR) {
            char lname[16];
            lower_reg_name(lname, sizeof(lname), op.regName);
            uint64_t regValue = (uint64_t)QBDI_GPR_GET(gprState, op.regCtxIdx);
            // w 寄存器只取低 32 位（与 GumTrace 的 get_register_value 行为一致）
            if (op.size == 4) {
                regValue &= 0xFFFFFFFFULL;
            }
            int n = snprintf(rbuf + roff, sizeof(rbuf) - roff, "%s=0x%" PRIx64 " ", lname, regValue);
            if (n > 0) roff += ((size_t)n < sizeof(rbuf) - roff) ? n : (int)(sizeof(rbuf) - roff - 1);
        } else if (op.type == QBDI::OPERAND_FPR && op.regCtxIdx < 32) {
            char lname[16];
            const char *nm = simd_operand_name(simd_tokens, num_simd_tokens, op.regName,
                                               op.regCtxIdx, lname, sizeof(lname));
            char vhex[40];
            simd_value_hex(vhex, sizeof(vhex), fprState, op.regCtxIdx, op.size);
            int n = snprintf(rbuf + roff, sizeof(rbuf) - roff, "%s=0x%s ", nm, vhex);
            if (n > 0) roff += ((size_t)n < sizeof(rbuf) - roff) ? n : (int)(sizeof(rbuf) - roff - 1);
        }
        if (roff >= (int)sizeof(rbuf) - 80) {
            break;
        }
    }
    if (roff > 0) {
        // 把读寄存器拼进 pending.line
        int copyLen = roff;
        if (off + copyLen >= (int)sizeof(pending.line)) copyLen = sizeof(pending.line) - off - 2;
        if (copyLen > 0) { memcpy(pending.line + off, rbuf, copyLen); off += copyLen; }
    }

    pending.lineLen = off;

    // ④ 记录当前指令会写哪些寄存器,等下一条 PRE 来补值（GPR 与 SIMD 都要记）
    pending.numWrite = 0;
    for (int i = 0; i < instAnalysis->numOperands; ++i)
    {
        auto& op = instAnalysis->operands[i];
        if (op.regCtxIdx < 0 || op.regName == nullptr) {
            continue;
        }
        if (op.regAccess != REGISTER_WRITE && op.regAccess != REGISTER_READ_WRITE) {
            continue;
        }
        if (pending.numWrite >= (int)(sizeof(pending.writes) / sizeof(pending.writes[0]))) {
            break;
        }
        PendingInst::WriteReg &w = pending.writes[pending.numWrite];
        w.idx = (uint8_t)op.regCtxIdx;
        if (op.type == QBDI::OPERAND_GPR) {
            w.is_fpr = 0;
            w.size = (op.size >= 1 && op.size <= 8) ? op.size : 8;
            lower_reg_name(w.name, sizeof(w.name), op.regName);
        } else if (op.type == QBDI::OPERAND_FPR && op.regCtxIdx < 32) {
            w.is_fpr = 1;
            w.size = (op.size >= 1 && op.size <= 16) ? op.size : 16;
            char lname[16];
            const char *nm = simd_operand_name(simd_tokens, num_simd_tokens, op.regName,
                                               op.regCtxIdx, lname, sizeof(lname));
            snprintf(w.name, sizeof(w.name), "%s", nm);
        } else {
            continue;
        }
        pending.numWrite++;
    }
    pending.memLen = 0;
    pending.memInfo[0] = '\0';
    pending.valid = true;

    /* 执行前的 libc/JNI/自定义 hook。
     * 特殊行先暂存到注解区（g_annot_mode），由 flushPending 在指令行之后写出，
     * 否则特殊行会落在指令行之前，trace-ui 会关联到错误的分支指令。 */
    bool hasCall = false;
    jni_clear_last_call_name();
    g_annot_mode = true;

    //执行前hook
    hasCall = checkAndCallHook(vm,gprState,(instAnalysis->address-thiz->base),(lastAddr - thiz->base));

    if(!hasCall)
    {
        //检查blr
        if(instAnalysis->isCall && !strcmp(instAnalysis->mnemonic,"BLR"))
        {
            for (int i = 0; i < instAnalysis->numOperands; ++i)
            {
                auto op = instAnalysis->operands[i];
                if (op.regAccess == QBDI::REGISTER_READ || op.regAccess == REGISTER_READ_WRITE)
                {
                    if (op.regCtxIdx != -1 && op.type == OPERAND_GPR && op.regCtxIdx != 31)
                    {
                        uint64_t regValue = QBDI_GPR_GET(gprState, op.regCtxIdx);
                        hasCall = checkJniCall_pre(vm,gprState,regValue);
                        break;
                    }
                }
            }
        }
    }

    if(!hasCall)
    {
        //检查br
        if(instAnalysis->isBranch && !strcmp(instAnalysis->mnemonic,"BR") && hasLibctrace())
        {
            for (int i = 0; i < instAnalysis->numOperands; ++i)
            {
                auto& op = instAnalysis->operands[i];
                if (op.regAccess == QBDI::REGISTER_READ || op.regAccess == REGISTER_READ_WRITE)
                {
                    if (op.regCtxIdx != -1 && op.type == OPERAND_GPR && op.regCtxIdx != 31)
                    {
                        uint64_t regValue = QBDI_GPR_GET(gprState, op.regCtxIdx);
                        //br可能是libc调用，也可能是jni调用
                        bool hit = checkLibcTrace_pre(vm,gprState,regValue);
                        if (!hit) {
                            hit = checkJniCall_pre(vm,gprState,regValue);
                        }
                        hasCall = hit;
                        break;
                    }
                }
            }
        }
    }

    /* SVC 系统调用：等价 GumTrace 的 ARM64_INS_SVC 分支 */
    if (!hasCall && instAnalysis->mnemonic != nullptr &&
        strcasecmp(instAnalysis->mnemonic, "svc") == 0) {
        hasCall = emit_syscall_call(gprState);
    }

    /* 符号级 call func：BL/BLR/B/BR 的跳转目标命中模块函数符号时打印
     * （等价 GumTrace 的 func_maps 精确匹配）。放在 hook 之后，
     * 已被 libc/JNI/自定义 hook 命中的调用不会重复注解。 */
    if (!hasCall && instAnalysis->mnemonic != nullptr &&
        (instAnalysis->isCall || instAnalysis->isBranch)) {
        const char *m = instAnalysis->mnemonic;
        if (strcasecmp(m, "bl") == 0 || strcasecmp(m, "blr") == 0 ||
            strcasecmp(m, "b") == 0 || strcasecmp(m, "br") == 0) {
            hasCall = emit_symbol_call(instAnalysis, gprState);
        }
    }

    g_annot_mode = false;
    pending.hasCall = hasCall;

    /* JNI 调用：记下函数名与调用前的参数（返回值要等调用返回才能读，
     * 见 flushPending 里的 jni_after_call） */
    const char *jni_name = jni_last_call_name();
    if (hasCall && jni_name != nullptr) {
        pending.isJniCall = true;
        snprintf(pending.jniName, sizeof(pending.jniName), "%s", jni_name);
        for (int i = 0; i < 8; ++i) {
            pending.jniPreArgs[i] = (uint64_t)QBDI_GPR_GET(gprState, i);
        }
    }

    if(_logger != nullptr && sdslen(_logger->buf) > bufsize)
    {
        writelog();
    }
    lastAddr = instAnalysis->address;
    return QBDI::VMAction::CONTINUE;
}

// 显示指令执行后的寄存器状态 打印字符串 hexdump
QBDI::VMAction showPostInstruction(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data)
{
    auto thiz = (class vm *)data;

    // 获取当前指令的分析信息，包括指令、符号、操作数等
    const QBDI::InstAnalysis *instAnalysis = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_OPERANDS);

    std::stringstream output;
    std::stringstream regOutput;

    // 遍历操作数并记录写入的寄存器状态
    for (int i = 0; i < instAnalysis->numOperands; ++i)
    {
        auto op = instAnalysis->operands[i];
        if (op.regAccess == REGISTER_WRITE || op.regAccess == REGISTER_READ_WRITE)
        {
            if (op.regCtxIdx != -1 && op.type == OPERAND_GPR)
            {
                // 获取寄存器值
                uint64_t regValue = QBDI_GPR_GET(gprState, op.regCtxIdx);
                // 输出寄存器名称和值（小写，与 disasm / trace-ui 一致）
                char lname[16];
                lower_reg_name(lname, sizeof(lname), op.regName);
                output << lname << "=0x" << std::hex << regValue << " ";
                output.flush();
            }
        }
    }

    // 如果有写入的寄存器信息，格式化输出；否则，仅换行
    if (!output.str().empty())
    {
        appendlog("\t => [");
        appendlog(output.str().c_str());
        appendlog("]");
        appendlogendl();
    }
    else
    {
        appendlogendl();
        appendlog(regOutput.str().c_str());
    }
    return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction showMemoryAccess(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data)
{
    const auto& accesses = vm->getInstMemoryAccess();   // 只调一次
    for (const auto &acc : accesses)
    {
        /* trace-ui 只识别 mem_r= / mem_w= 两个前缀（mem_rw= 会被整条丢弃）。
         * QBDI 的 MEMORY_READ_WRITE 归入 mem_w，最终读/写由 trace-ui
         * 按助记符(ld 前缀 / st 前缀)覆盖，与 GumTrace 的行为一致。 */
        const char* tag = (acc.type == MEMORY_READ) ? "mem_r" : "mem_w";
        int room = (int)sizeof(pending.memInfo) - pending.memLen;
        if (room <= 1) {
            break;
        }
        int n = snprintf(pending.memInfo + pending.memLen, (size_t)room,
                         "%s=0x%" PRIx64 " ", tag, (uint64_t)acc.accessAddress);
        if (n <= 0) {
            break;
        }
        pending.memLen += ((size_t)n < (size_t)room) ? n : (room - 1);
    }
    return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction showSyscall(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data)
{
    const QBDI::InstAnalysis *instAnalysis = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION);
    if (instAnalysis->mnemonic && strcasecmp(instAnalysis->mnemonic, "svc") == 0)
    {

    }
    return QBDI::VMAction::CONTINUE;
}

QBDI::VM vm::init(size_t start,size_t end)
{
    uint32_t cid;
    QBDI::GPRState *state;
    QBDI::VM qvm{};
    state = qvm.getGPRState();
    loadMemoryRanges();
    assert(state != nullptr);
    qvm.recordMemoryAccess(QBDI::MEMORY_READ_WRITE);

    //指令前hook
    cid = qvm.addCodeCB(QBDI::PREINST, showPreInstruction, this);
    assert(cid != QBDI::INVALID_EVENTID);

    //指令后hook
    //cid = qvm.addCodeCB(QBDI::POSTINST, showPostInstruction, this);
    //assert(cid != QBDI::INVALID_EVENTID);

    //TODO:syscall trace
    //cid = qvm.addCodeCB(QBDI::PREINST, showSyscall, this);
    //assert(cid != QBDI::INVALID_EVENTID);

    //读写trace
    cid = qvm.addMemAccessCB(MEMORY_READ_WRITE, showMemoryAccess, this);
    assert(cid != QBDI::INVALID_EVENTID);

    /* 匿名区 (ijiami VM 解包代码) 不是 ELF 模块, addInstrumentedModuleFromAddr
     * 会失败 — 直接按地址范围指杆。范围外的跨模块调用 (libc/jni/art) 仍会执行,
     * 只是不记指令; JNI/libc trace 钩子仍能捕获边界。 */
    qvm.addInstrumentedRange(reinterpret_cast<QBDI::rword>(start),
                             reinterpret_cast<QBDI::rword>(end));
    LOGE("init vm success (range %p-%p)", (void*)start, (void*)end);
    return qvm;
}