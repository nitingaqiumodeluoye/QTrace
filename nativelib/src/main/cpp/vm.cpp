//
// Created by fang on 23-12-19.
//
#include "fstream"
#include <iostream>
#include <iomanip>
#include <cassert>
#include <sstream>
#include <unordered_map>
#include <sys/uio.h>
#include <unistd.h>
#include <cstring>
#include <cctype>
#include <sstream>
#include <string>
#include <atomic>
#include <sys/mman.h>
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

func_arg_8 ori_arg8{};
static std::atomic_flag traceInProgress = ATOMIC_FLAG_INIT;
static TraceFilter traceFilter = nullptr;


void setBufferSize(int size)
{
    constexpr int kMinimumBufferSize = 64 * 1024;
    constexpr int kMaximumBufferSize = 64 * 1024 * 1024;
    if (size < kMinimumBufferSize) size = kMinimumBufferSize;
    if (size > kMaximumBufferSize) size = kMaximumBufferSize;
    bufsize = size;
}

void enableDebugInsn(bool enable)
{
    debugInsn = enable;
}

void setTraceFilter(TraceFilter filter)
{
    traceFilter = filter;
}

void sync_regs(size_t* regs, size_t pc,QBDI::GPRState* qbdi_state)
{
    for(int i=0;i<31;i++)
    {
        QBDI_GPR_SET(qbdi_state,i,regs[i]);
    }
    qbdi_state->pc = pc;
}

// pending:暂存上一条指令待补全的信息
struct PendingInst {
    bool valid = false;
    char line[2048];
    int  lineLen = 0;
    int  writeRegs[8];
    char writeNames[8][16];
    int  numWrite = 0;
    char memInfo[1024];      // GumTrace 格式的内存访问字段
    int  memLen = 0;
    char callInfo[8192];     // trace-ui 可识别的函数调用注解和参数 hexdump
    int  callLen = 0;
};

static PendingInst pending;
static size_t lastAddr = 0;

static void copyLowerName(char* dst, size_t dstSize, const char* src)
{
    if (dst == nullptr || dstSize == 0) return;
    size_t i = 0;
    if (src != nullptr) {
        for (; i + 1 < dstSize && src[i] != '\0'; ++i) {
            dst[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(src[i])));
        }
    }
    dst[i] = '\0';
}

static std::string normalizeDisassembly(const char* source)
{
    std::string normalized;
    if (source == nullptr) return normalized;

    normalized.reserve(strlen(source));
    bool pendingSpace = false;
    for (const unsigned char* cursor = reinterpret_cast<const unsigned char*>(source);
         *cursor != '\0'; ++cursor) {
        if (std::isspace(*cursor)) {
            pendingSpace = !normalized.empty();
            continue;
        }
        if (pendingSpace) {
            normalized.push_back(' ');
            pendingSpace = false;
        }
        normalized.push_back(static_cast<char>(std::tolower(*cursor)));
    }
    return normalized;
}

static void appendPendingCallText(const char* text, size_t length)
{
    if (text == nullptr || length == 0 || pending.callLen < 0) return;
    const size_t available = sizeof(pending.callInfo) - static_cast<size_t>(pending.callLen) - 1;
    const size_t copyLength = std::min(length, available);
    if (copyLength == 0) return;
    memcpy(pending.callInfo + pending.callLen, text, copyLength);
    pending.callLen += static_cast<int>(copyLength);
    pending.callInfo[pending.callLen] = '\0';
}

void appendPendingCallArg(const std::string& index, const std::string& value)
{
    if (pending.callLen <= 0) return;
    std::string sanitized = value;
    for (char& character : sanitized) {
        if (character == '\r' || character == '\n') character = ' ';
    }
    std::string line = "args" + index + ": " + sanitized + "\n";
    appendPendingCallText(line.data(), line.size());
}

void appendPendingCallArg(size_t index, const std::string& value)
{
    appendPendingCallArg(std::to_string(index), value);
}

void appendPendingCallHexdump(uint64_t address, const uint8_t* data, size_t size)
{
    if (pending.callLen <= 0 || data == nullptr || size == 0) return;
    constexpr size_t kMaxDumpSize = 256;
    const size_t dumpSize = std::min(size, kMaxDumpSize);
    char line[160];
    int length = snprintf(line, sizeof(line),
                          "hexdump at address 0x%" PRIx64 " with length 0x%zx:\n",
                          address, dumpSize);
    if (length > 0) appendPendingCallText(line, std::min<int>(length, sizeof(line) - 1));

    for (size_t offset = 0; offset < dumpSize; offset += 16) {
        const size_t rowSize = std::min<size_t>(16, dumpSize - offset);
        int position = snprintf(line, sizeof(line), "%" PRIx64 ": ", address + offset);
        for (size_t i = 0; i < 16 && position > 0 && position < static_cast<int>(sizeof(line)); ++i) {
            position += snprintf(line + position, sizeof(line) - position,
                                 i < rowSize ? "%02x " : "   ",
                                 i < rowSize ? data[offset + i] : 0);
        }
        if (position > 0 && position < static_cast<int>(sizeof(line))) {
            position += snprintf(line + position, sizeof(line) - position, "|");
        }
        for (size_t i = 0; i < rowSize && position > 0 && position + 1 < static_cast<int>(sizeof(line)); ++i) {
            const uint8_t byte = data[offset + i];
            line[position++] = (byte >= 0x20 && byte <= 0x7e) ? static_cast<char>(byte) : '.';
        }
        if (position > 0 && position + 2 < static_cast<int>(sizeof(line))) {
            line[position++] = '|';
            line[position++] = '\n';
            line[position] = '\0';
            appendPendingCallText(line, position);
        }
    }
}

// 把 pending(上一条指令)用当前寄存器状态补全并输出
static void flushPending(QBDI::GPRState *gprState)
{
    if (!pending.valid) return;

    appendlog_n(pending.line, pending.lineLen);

    if (pending.memLen > 0) {
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
    if (pending.callLen > 0) {
        appendlog_n(pending.callInfo, pending.callLen);
        appendformat("ret: 0x%" PRIx64 "\n", QBDI_GPR_GET(gprState, 0));
    }
    pending.valid = false;
}

static void setPendingCallInfo(const char* prefix, const TraceFunc* traceFunc,
                               QBDI::GPRState* gprState)
{
    if (traceFunc == nullptr || gprState == nullptr) return;
    pending.callLen = snprintf(
            pending.callInfo,
            sizeof(pending.callInfo),
            "%s: %s(0x%" PRIx64 ", 0x%" PRIx64 ", 0x%" PRIx64 ", 0x%" PRIx64
            ", 0x%" PRIx64 ", 0x%" PRIx64 ", 0x%" PRIx64 ", 0x%" PRIx64 ")\n",
            prefix,
            traceFunc->name.c_str(),
            QBDI_GPR_GET(gprState, 0),
            QBDI_GPR_GET(gprState, 1),
            QBDI_GPR_GET(gprState, 2),
            QBDI_GPR_GET(gprState, 3),
            QBDI_GPR_GET(gprState, 4),
            QBDI_GPR_GET(gprState, 5),
            QBDI_GPR_GET(gprState, 6),
            QBDI_GPR_GET(gprState, 7));
    if (pending.callLen < 0) pending.callLen = 0;
    if (pending.callLen >= (int)sizeof(pending.callInfo)) {
        pending.callLen = sizeof(pending.callInfo) - 1;
    }
}
static size_t callOriginal(const size_t* regs)
{
    if (ori_arg8 == nullptr) {
        LOGE("original function trampoline is null");
        return 0;
    }
    return ori_arg8(regs[0], regs[1], regs[2], regs[3],
                    regs[4], regs[5], regs[6], regs[7]);
}

static size_t callUnhookedTarget(const size_t* regs)
{
    if (_g_trace_data == nullptr) {
        LOGE("trace target data is null");
        return 0;
    }
    auto target = reinterpret_cast<func_arg_8>(_g_trace_data->start + _g_trace_data->target);
    return target(regs[0], regs[1], regs[2], regs[3],
                  regs[4], regs[5], regs[6], regs[7]);
}

size_t trace(size_t regs[31])
{
    if (_g_trace_data == nullptr || regs == nullptr) {
        LOGE("trace called without target data or registers");
        return 0;
    }
    size_t function_address = _g_trace_data->start + _g_trace_data->target;
    LOGE("start trace:%p",(void*)function_address);
    if (_g_trace_data->hooktask == nullptr || shadowhook_unhook(_g_trace_data->hooktask) != 0) {
        LOGE("failed to temporarily remove trace hook");
        return callOriginal(regs);
    }
    _g_trace_data->hooktask = nullptr;

    auto reinstallHook = []() {
        _g_trace_data->hooktask = shadowhook_hook_func_addr(
                (void*)(_g_trace_data->start + _g_trace_data->target),
                (void*)(hook_and_trace_arg8),
                (void**)&ori_arg8);
        if (_g_trace_data->hooktask == nullptr) {
            LOGE("failed to reinstall trace hook");
        }
    };

    struct timeval start, end;
    gettimeofday(&start, nullptr);
    vm* vm_ = new vm();
    auto qvm = vm_->init(_g_trace_data->start,_g_trace_data->end);
    if (!vm_->initialized) {
        LOGE("QBDI VM initialization failed, falling back to original function");
        delete vm_;
        size_t result = callUnhookedTarget(regs);
        reinstallHook();
        return result;
    }
    auto qbdi_state = qvm.getGPRState();
    if (!initLogger(function_address)) {
        delete vm_;
        size_t result = callUnhookedTarget(regs);
        reinstallHook();
        return result;
    }
    vm_->base = _g_trace_data->base;
    sync_regs(regs,function_address,qbdi_state);

    constexpr size_t kTraceStackSize = 1024 * 1024;
    const long pageSize = sysconf(_SC_PAGESIZE);
    const size_t totalStackSize = pageSize > 0
                                  ? kTraceStackSize + static_cast<size_t>(pageSize) * 2
                                  : 0;
    void* stackMapping = totalStackSize > 0
                         ? mmap(nullptr, totalStackSize, PROT_NONE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
                         : MAP_FAILED;
    if (stackMapping == MAP_FAILED ||
        mprotect(static_cast<uint8_t*>(stackMapping) + pageSize,
                 kTraceStackSize, PROT_READ | PROT_WRITE) != 0) {
        LOGE("failed to allocate guarded trace stack: %s", strerror(errno));
        if (stackMapping != MAP_FAILED) munmap(stackMapping, totalStackSize);
        deleteLogger();
        delete vm_;
        size_t result = callUnhookedTarget(regs);
        reinstallHook();
        return result;
    }
    size_t traceSp = reinterpret_cast<size_t>(stackMapping) + pageSize + kTraceStackSize;
    traceSp &= ~static_cast<size_t>(0xF);
    QBDI_GPR_SET(qbdi_state, QBDI::REG_SP, traceSp);

    pending = PendingInst{};
    lastAddr = 0;
    QBDI::rword qbdi_retval = 0;
    LOGE("trace begin");
    bool qbdi_success = qvm.call(&qbdi_retval, (uint64_t)function_address);
    LOGE("trace end");
    flushPending(qbdi_state);
    if (qbdi_success) {
        if (writelog()) {
            LOGE("trace completed successfully %s",_logger->logfile.c_str());
        } else {
            LOGE("trace completed but writing the log failed");
        }
    } else {
        LOGE("trace failed before executing a block, falling back to original function");
        qbdi_retval = callUnhookedTarget(regs);
    }
    gettimeofday(&end, nullptr);
    long elapsed_sec;
    elapsed_sec = (end.tv_sec - start.tv_sec) +
                  (end.tv_usec - start.tv_usec) / 1000000;
    LOGI("trace time cost:%lds",elapsed_sec);
    munmap(stackMapping, totalStackSize);
    deleteLogger();
    delete vm_;
    reinstallHook();
    return qbdi_retval;
}

extern "C" size_t hook_and_trace_impl(size_t* regs)
{
    if (regs == nullptr) {
        LOGE("trace hook called without registers");
        return 0;
    }
    if (traceFilter != nullptr && !traceFilter(regs)) {
        return callOriginal(regs);
    }
    if (traceInProgress.test_and_set(std::memory_order_acquire)) {
        return callOriginal(regs);
    }
    size_t result = trace(regs);
    traceInProgress.clear(std::memory_order_release);
    return result;
}

__attribute__((naked))
size_t hook_and_trace_arg8(size_t, size_t, size_t, size_t, size_t, size_t, size_t, size_t)
{
    __asm__ __volatile__(
            "sub sp, sp, #256\n"
            "stp x0, x1, [sp, #0]\n"
            "stp x2, x3, [sp, #16]\n"
            "stp x4, x5, [sp, #32]\n"
            "stp x6, x7, [sp, #48]\n"
            "stp x8, x9, [sp, #64]\n"
            "stp x10, x11, [sp, #80]\n"
            "stp x12, x13, [sp, #96]\n"
            "stp x14, x15, [sp, #112]\n"
            "stp x16, x17, [sp, #128]\n"
            "stp x18, x19, [sp, #144]\n"
            "stp x20, x21, [sp, #160]\n"
            "stp x22, x23, [sp, #176]\n"
            "stp x24, x25, [sp, #192]\n"
            "stp x26, x27, [sp, #208]\n"
            "stp x28, x29, [sp, #224]\n"
            "str x30, [sp, #240]\n"
            "mov x0, sp\n"
            "bl hook_and_trace_impl\n"
            "mov x9, x0\n"
            "ldr x30, [sp, #240]\n"
            "add sp, sp, #256\n"
            "mov x0, x9\n"
            "ret\n");
}

bool checkAndCallHook(QBDI::VM *vm, QBDI::GPRState *gprState,size_t addr,size_t lastaddr)
{
    if (_g_hook_data == nullptr) return false;
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
    if (_g_libc_trace == nullptr) return false;
    auto it = _g_libc_trace->map.find(target);
    if(it != _g_libc_trace->map.end())
    {
        setPendingCallInfo("call func", it->second, gprState);
        it->second->callback(vm,gprState);
        return true;
    }
    return false;
}

bool checkJniCall_pre(QBDI::VM *vm, QBDI::GPRState *gprState,size_t target)
{
    if(pJFunc == nullptr || _g_jni_trace == nullptr)
    {
        LOGE("checkJniCall,pJFunc not init");
        return false;
    }
    auto it = _g_jni_trace->map.find(target);
    if(it != _g_jni_trace->map.end())
    {
        setPendingCallInfo("call jni func", it->second, gprState);
        it->second->callback(vm,gprState);
        return true;
    }
    return false;
}

static unordered_map<uint32_t,std::string> disassemblecache;

// 显示指令执行前的寄存器状态
QBDI::VMAction showPreInstruction(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data)
{
    auto thiz = (class vm *)data;

    //上一条指令的信息全部拿到了，写入
    flushPending(gprState);
    pending.callLen = 0;

    // 获取当前指令的分析信息
    const QBDI::InstAnalysis *instAnalysis = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION  | QBDI::ANALYSIS_OPERANDS);
    if (instAnalysis == nullptr || instAnalysis->address == 0 || instAnalysis->mnemonic == nullptr) {
        LOGE("QBDI returned incomplete instruction analysis");
        return QBDI::VMAction::STOP;
    }
    uint32_t bytecode = 0;
    if (!safeReadMemory(instAnalysis->address,
                        reinterpret_cast<uint8_t*>(&bytecode), sizeof(bytecode))) {
        LOGE("failed to read instruction bytes at 0x%lx", instAnalysis->address);
        return QBDI::VMAction::STOP;
    }

    //用缓存的反汇编，减低开销
    const char* disasm;
    auto it = disassemblecache.find(bytecode);
    if (it != disassemblecache.end()) {
        disasm = it->second.c_str();
    } else {
        const QBDI::InstAnalysis *full = vm->getInstAnalysis(QBDI::ANALYSIS_DISASSEMBLY);
        if (full == nullptr || full->disassembly == nullptr) {
            LOGE("QBDI returned no disassembly");
            return QBDI::VMAction::STOP;
        }
        std::string normalized = normalizeDisassembly(full->disassembly);
        if (normalized.empty()) {
            LOGE("QBDI returned empty disassembly");
            return QBDI::VMAction::STOP;
        }
        auto inserted = disassemblecache.emplace(bytecode, std::move(normalized));
        disasm = inserted.first->second.c_str();
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
    const char* moduleName = _g_trace_data->module_name.empty()
                             ? "unknown"
                             : _g_trace_data->module_name.c_str();
    off += snprintf(pending.line + off, sizeof(pending.line) - off,
                    "[%s] 0x%lx!0x%lx %s; ",
                    moduleName,
                    instAnalysis->address,
                    (instAnalysis->address - thiz->base),
                    disasm);
    if (off < 0) off = 0;
    if (off >= (int)sizeof(pending.line)) off = sizeof(pending.line) - 1;

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
            char regName[16];
            copyLowerName(regName, sizeof(regName), op.regName);
            roff += snprintf(rbuf + roff, sizeof(rbuf) - roff, "%s=0x%" PRIx64 " ",
                             regName, regValue);
            any = true;
            if (roff >= (int)sizeof(rbuf)) { roff = sizeof(rbuf) - 1; break; }
        }
    }
    if (any) {
        int copyLen = roff;
        if (off + copyLen >= (int)sizeof(pending.line)) copyLen = sizeof(pending.line) - off - 1;
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
                copyLowerName(pending.writeNames[pending.numWrite],
                              sizeof(pending.writeNames[pending.numWrite]),
                              op.regName);
                pending.numWrite++;
            }
        }
    }
    pending.memLen = 0;
    pending.valid = true;

    if (_logger != nullptr && _logger->buf != nullptr && sdslen(_logger->buf) > bufsize)
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
        const char* tag = (acc.type == MEMORY_WRITE) ? "mem_w" : "mem_r";
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
    ensureMemoryRangesLoaded();
    if (state == nullptr) {
        LOGE("QBDI GPR state is null");
        return qvm;
    }
    qvm.recordMemoryAccess(QBDI::MEMORY_READ_WRITE);

    //指令前hook
    cid = qvm.addCodeCB(QBDI::PREINST, showPreInstruction, this);
    if (cid == QBDI::INVALID_EVENTID) {
        LOGE("failed to register PREINST callback");
        return qvm;
    }

    //指令后hook
    //cid = qvm.addCodeCB(QBDI::POSTINST, showPostInstruction, this);
    //assert(cid != QBDI::INVALID_EVENTID);

    //TODO:syscall trace
    //cid = qvm.addCodeCB(QBDI::PREINST, showSyscall, this);
    //assert(cid != QBDI::INVALID_EVENTID);

    //读写trace
    cid = qvm.addMemAccessCB(MEMORY_READ_WRITE, showMemoryAccess, this);
    if (cid == QBDI::INVALID_EVENTID) {
        LOGE("failed to register memory callback");
        return qvm;
    }

    bool ret = qvm.addInstrumentedModuleFromAddr(reinterpret_cast<QBDI::rword>(start));
    if(!ret)
    {
        LOGE("init vm fail");
        return qvm;
    }
    initialized = true;
    LOGE("init vm success");
    return qvm;
}
