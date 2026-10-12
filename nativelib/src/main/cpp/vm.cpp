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
#include <sstream>
#include <string>
#include <QBDI/Callback.h>
#include "vm.h"
#include "logger.h"
#include "qbdihook.h"
#include "jnitrace.h"
#include "libctrace.h"
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
    char line[256];
    int  lineLen = 0;
    int  writeRegs[8];
    const char* writeNames[8];
    int  numWrite = 0;
    char memInfo[1024];      // 内存访问行(可能多条)
    int  memLen = 0;
};

static PendingInst pending;

// 把 pending(上一条指令)用当前寄存器状态补全并输出
static void flushPending(QBDI::GPRState *gprState)
{
    if (!pending.valid) return;

    appendlog_n(pending.line, pending.lineLen);   // 上一条的 "[mod] abs!off asm ; 读"

    /* 内存访问注解为 mem_r=/mem_w= 前缀 (内联在指令行尾, trace-ui 格式) */
    if (pending.memLen > 0) {
        /* memInfo 现在是 "mem_r=0x... mem_w=0x..." 空格分隔 */
        appendlog(" ");
        appendlog_n(pending.memInfo, pending.memLen);
    }

    if (pending.numWrite > 0) {
        char wbuf[256];
        int woff = 0;
        for (int i = 0; i < pending.numWrite; ++i) {
            uint64_t v = QBDI_GPR_GET(gprState, pending.writeRegs[i]);  // 此刻 = 上一条执行后的值
            woff += snprintf(wbuf + woff, sizeof(wbuf) - woff, "%s=0x%" PRIx64 " ",
                             pending.writeNames[i], v);
            if (woff >= (int)sizeof(wbuf)) { woff = sizeof(wbuf) - 1; break; }
        }
        appendlog("-> ");
        appendlog_n(wbuf, woff);
    }
    appendlogendl();
    pending.valid = false;
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
    flushPending(qbdi_state);
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

/* ===== IL(466) 判断 =====
 * IL 的 Object[] 首元素是 Integer(id)。入口用 JNI 读取并判断 id==466。
 * 缓存: Integer 类为全局引用(局部引用只在本次 native 调用内有效); intValue 为 jmethodID。
 * 每次调用都会做 JNI, 命中 466 后 trace 一次并卸挂钩, 之后无开销。 */
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

/* 返回 true 表示 x2 数组首元素的 int 值为 466。任何失败都返回 false(透传)。 */
static bool il_id_is_466(size_t x2)
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
    return v == 466;
}

size_t hook_and_trace_arg8(size_t x0,size_t x1,size_t x2,size_t x3,size_t x4,size_t x5,size_t x6,size_t x7)
{
    static std::atomic<bool> tracedOnce{false};
    if (tracedOnce.load()) {
        return ori_arg8(x0,x1,x2,x3,x4,x5,x6,x7);
    }
    if (!il_id_is_466(x2)) {
        return ori_arg8(x0,x1,x2,x3,x4,x5,x6,x7);
    }
    if (tracedOnce.exchange(true)) {
        return ori_arg8(x0,x1,x2,x3,x4,x5,x6,x7);
    }

    size_t regs[31] = {0};
    save_regs(regs);
    regs[0] = x0; regs[1] = x1; regs[2] = x2; regs[3] = x3;
    regs[4] = x4; regs[5] = x5; regs[6] = x6; regs[7] = x7;
    LOGE("gvm: IL id==466 hit, starting one-shot trace");
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

// 显示指令执行前的寄存器状态
QBDI::VMAction showPreInstruction(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data)
{
    auto thiz = (class vm *)data;

    //上一条指令的信息全部拿到了，写入
    flushPending(gprState);

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
        disassemblecache.emplace(bytecode, disasm);
    }

    bool hasCheck = false;
    //执行前hook
    hasCheck = checkAndCallHook(vm,gprState,(instAnalysis->address-thiz->base),(lastAddr - thiz->base));

    if(!hasCheck)
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
                        hasCheck = checkJniCall_pre(vm,gprState,regValue);
                        break;
                    }
                }
            }
        }
    }

    if(!hasCheck)
    {
        //检查br
        if(instAnalysis->isBranch && !strcmp(instAnalysis->mnemonic,"BR") && hasLibctrace())
        {
            for (int i = 0; i < instAnalysis->numOperands; ++i)
            {
                auto op = instAnalysis->operands[i];
                if (op.regAccess == QBDI::REGISTER_READ || op.regAccess == REGISTER_READ_WRITE)
                {
                    if (op.regCtxIdx != -1 && op.type == OPERAND_GPR && op.regCtxIdx != 31)
                    {
                        uint64_t regValue = QBDI_GPR_GET(gprState, op.regCtxIdx);
                        //br可能是libc调用，也可能是jni调用
                        if(!checkLibcTrace_pre(vm,gprState,regValue))
                        {
                            checkJniCall_pre(vm,gprState,regValue);
                        }
                        break;
                    }
                }
            }
        }
    }

    int off = 0;
    /* trace-ui GumTrace 格式: [模块名] 0x绝对地址!0x相对偏移 助记符 操作数; 读寄存器 mem_r/w=地址 -> 写寄存器 */
    off += snprintf(pending.line + off, sizeof(pending.line) - off,
                    "[%s] 0x%lx!0x%lx %s", trace_module_name(),
                    (size_t)instAnalysis->address,
                    (instAnalysis->address - thiz->base), disasm);

    char rbuf[256];
    int roff = 0;
    bool any = false;
    for (int i = 0; i < instAnalysis->numOperands; ++i)
    {
        auto& op = instAnalysis->operands[i];
        if ((op.regAccess == QBDI::REGISTER_READ || op.regAccess == REGISTER_READ_WRITE)
            && op.regCtxIdx != -1 && op.type == OPERAND_GPR)
        {
            uint64_t regValue = QBDI_GPR_GET(gprState, op.regCtxIdx);
            roff += snprintf(rbuf + roff, sizeof(rbuf) - roff, "%s=0x%" PRIx64 " ",
                             op.regName, regValue);
            any = true;
            if (roff >= (int)sizeof(rbuf)) { roff = sizeof(rbuf) - 1; break; }
        }
    }
    if (any) {
        off += snprintf(pending.line + off, sizeof(pending.line) - off, "; ");
        // 把读寄存器拼进 pending.line
        int copyLen = roff;
        if (off + copyLen >= (int)sizeof(pending.line)) copyLen = sizeof(pending.line) - off - 2;
        if (copyLen > 0) { memcpy(pending.line + off, rbuf, copyLen); off += copyLen; }
    }

    pending.lineLen = off;

    // ④ 记录当前指令会写哪些寄存器,等下一条 PRE 来补值
    pending.numWrite = 0;
    for (int i = 0; i < instAnalysis->numOperands; ++i)
    {
        auto& op = instAnalysis->operands[i];
        if ((op.regAccess == REGISTER_WRITE || op.regAccess == REGISTER_READ_WRITE)
            && op.regCtxIdx != -1 && op.type == OPERAND_GPR)
        {
            if (pending.numWrite < 8) {
                pending.writeRegs[pending.numWrite]  = op.regCtxIdx;
                pending.writeNames[pending.numWrite] = op.regName;
                pending.numWrite++;
            }
        }
    }
    pending.memLen = 0;
    pending.valid = true;

    if(sdslen(_logger->buf) > bufsize)
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
                // 输出寄存器名称和值
                output << op.regName << "=0x" << std::hex << regValue << " ";
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
        const char* tag = (acc.type == MEMORY_READ)  ? "mem_r"
                                                     : (acc.type == MEMORY_WRITE) ? "mem_w"
                                                                                  : "mem_rw";
        pending.memLen += snprintf(pending.memInfo + pending.memLen,
                                   sizeof(pending.memInfo) - pending.memLen,
                                   "%s=0x%" PRIx64 " ",
                                   tag,
                                   (uint64_t)acc.accessAddress);
        if (pending.memLen >= (int)sizeof(pending.memInfo)) {
            pending.memLen = sizeof(pending.memInfo) - 1;
            break;
        }
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