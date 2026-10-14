//
// Created by zgy on 2025/11/12.
//
// libc 调用追踪。输出对齐 GumTrace 的注解格式（trace-ui 可直接解析）：
//   call func: memcpy(0x7a3c050010, 0x7a3c060000, 0x20)
//   hexdump at address 0x7a3c060000 with length 0x20:
//   7a3c060000: 48 74 74 70 ... |Http|
//   ret: 0x7a3c050010
// 其中 `ret:` 由 vm.cpp 的 flushPending 统一补出，这里只负责 call/args/hexdump。
#include "libctrace.h"
#include "dlfcn.h"
#include "logger.h"
#include "HookUtils.h"
#include "TraceUtils.h"
#include <vector>
#include <cstdio>
#include <cinttypes>
#include <cstring>

LibcTraceMap* _g_libc_trace = nullptr;
static bool debug = false;

void enable_libc_trace_debug(bool enable)
{
    debug = enable;
}

void initLibcTrace()
{
    _g_libc_trace = new LibcTraceMap();
    _g_libc_trace->map.reserve(10);
}

bool hasLibctrace()
{
    if(_g_libc_trace == nullptr)
    {
        return false;
    }
    if(_g_libc_trace->map.empty())
    {
        return false;
    }
    return true;
}

void addLibctrace(void* handle,TraceCallBack callback,const char* funcname)
{
    size_t addr = (size_t)dlsym(handle,funcname);
    if(addr == 0)
    {
        LOGE("libc trace : %s find fail",funcname);
        return;
    }
    TraceFunc* func_trace = new TraceFunc();
    func_trace->callback = callback;
    if(_g_libc_trace == nullptr)
    {
        LOGE("libc trace : not init!");
        return;
    }
    auto it = _g_libc_trace->map.find(addr);
    if(it != _g_libc_trace->map.end())
    {
        LOGE("libc trace: %p has installed!",(void*)addr);
        return;
    }
    _g_libc_trace->map[addr] = func_trace;
    LOGE("libc trace: %s:%p install",funcname,(void*)addr);
}

/* ===== GumTrace 风格注解辅助 ===== */

/* 安全读取目标进程的一个 C 字符串（用 process_vm_readv，不会因野指针崩溃） */
static bool safe_read_cstr(uint64_t addr, char* out, size_t out_size)
{
    if (out_size == 0) {
        return false;
    }
    out[0] = '\0';
    // AArch64 合法 userspace 指针通常 > 4GB，小值当整型参数丢弃
    if (addr < 0x100000000ULL) {
        return false;
    }
    std::vector<uint8_t> buf(out_size, 0);
    if (!safeReadMemory(addr, buf.data(), out_size)) {
        return false;
    }
    size_t i = 0;
    for (; i + 1 < out_size && buf[i] != 0; ++i) {
        out[i] = (char)buf[i];
    }
    out[i] = '\0';
    return i > 0;
}

/* call func: name(0x.., 0x..) */
static void call_func_begin(const char* name, const uint64_t* args, int n)
{
    char buf[512];
    int off = 0;
    int w = snprintf(buf + off, sizeof(buf) - off, "call func: %s(", name);
    if (w > 0) off += ((size_t)w < sizeof(buf) - off) ? w : (int)(sizeof(buf) - off - 1);
    for (int i = 0; i < n && off < (int)sizeof(buf) - 32; ++i) {
        w = snprintf(buf + off, sizeof(buf) - off, "%s0x%" PRIx64, i ? ", " : "", args[i]);
        if (w > 0) off += ((size_t)w < sizeof(buf) - off) ? w : (int)(sizeof(buf) - off - 1);
    }
    snprintf(buf + off, sizeof(buf) - off, ")");
    appendlog(buf);
    appendlogendl();
}

/* argsN: <string> */
static void arg_string(int idx, const char* s)
{
    if (s == nullptr || s[0] == '\0') {
        return;
    }
    appendformat("args%d: %s", idx, s);
    appendlogendl();
}

/* 读取寄存器指针并输出 argsN: */
static void arg_string_from_reg(int idx, uint64_t addr)
{
    char tmp[256];
    if (safe_read_cstr(addr, tmp, sizeof(tmp))) {
        arg_string(idx, tmp);
    }
}

void libc_memmove(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    uint64_t x2 = QBDI_GPR_GET(gprState, 2);
    uint64_t args[3] = { x0, x1, x2 };
    call_func_begin("memmove", args, 3);
    // GumTrace: hexdump(src, len)
    hexdump_to_log(x1, (size_t)x2);
    if(debug)
    {
        LOGE("libc memmove: dest 0x%lx,src 0x%lx,len 0x%lx",x0,x1,x2);
    }
}

void libc_memset(QBDI::VM *vm, QBDI::GPRState *gprState) {
    if (_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    uint64_t x2 = QBDI_GPR_GET(gprState, 2);
    uint64_t args[3] = { x0, x1, x2 };
    call_func_begin("memset", args, 3);
}

void libc_memcpy(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if (_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    uint64_t x2 = QBDI_GPR_GET(gprState, 2);
    uint64_t args[3] = { x0, x1, x2 };
    call_func_begin("memcpy", args, 3);
    // GumTrace: hexdump(src, len)
    hexdump_to_log(x1, (size_t)x2);
    if(debug)
    {
        LOGE("libc memcpy: dest 0x%lx,src 0x%lx,len 0x%lx",x0,x1,x2);
    }
}

void libc_access(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    uint64_t args[2] = { x0, x1 };
    call_func_begin("access", args, 2);
    arg_string_from_reg(0, x0);
    if(debug)
    {
        LOGE("libc access:0x%lx",x0);
    }
}

void libc_system_property_get(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("qdbi hook:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    uint64_t args[2] = { x0, x1 };
    call_func_begin("__system_property_get", args, 2);
    arg_string_from_reg(0, x0);
    arg_string_from_reg(1, x1);
    if(debug)
    {
        LOGE("libc _system_property_get:0x%lx",x0);
    }
}

void libc_pthread_create(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("qdbi hook:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    uint64_t x2 = QBDI_GPR_GET(gprState, 2);
    uint64_t args[3] = { x0, x1, x2 };
    call_func_begin("pthread_create", args, 3);
    if(debug)
    {
        LOGE("libc pthread_create:0x%lx",x2);
    }
}

void libc_clock_gettime(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    uint64_t args[2] = { x0, x1 };
    call_func_begin("clock_gettime", args, 2);
    if(debug)
    {
        LOGE("libc clock_gettime:%p",(void*)x1);
    }
}

void libc_exit(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    uint64_t args[1] = { x0 };
    call_func_begin("exit", args, 1);
    if(debug)
    {
        LOGE("libc exit");
    }
}

void libc_abort(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    call_func_begin("abort", nullptr, 0);
    if(debug)
    {
        LOGE("libc abort");
    }
}

void libc_kill(QBDI::VM *vm, QBDI::GPRState *gprState)
{
}

void libc_strlen(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    uint64_t args[1] = { x0 };
    call_func_begin("strlen", args, 1);
    arg_string_from_reg(0, x0);
    if(debug)
    {
        LOGE("libc strlen:0x%lx",x0);
    }
}

void libc_execve(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    uint64_t x2 = QBDI_GPR_GET(gprState, 2);
    uint64_t args[3] = { x0, x1, x2 };
    call_func_begin("execve", args, 3);
    arg_string_from_reg(0, x0);
    if(debug)
    {
        LOGE("libc execv:0x%lx",x0);
        while (true)
        {
            char* arg = *((char **)x1) ;
            if(arg == nullptr)
            {
                break;
            }
            LOGE("[log] libc execv argv:%s",arg);
            x1 += 8;
        }
    }
}

void libc_fstatat(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    uint64_t x2 = QBDI_GPR_GET(gprState, 2);
    uint64_t x3 = QBDI_GPR_GET(gprState, 3);
    uint64_t args[4] = { x0, x1, x2, x3 };
    call_func_begin("fstatat", args, 4);
    // GumTrace: fstatat 的路径在 x1
    arg_string_from_reg(1, x1);
    if(debug)
    {
        LOGE("libc fstatat:0x%lx",x1);
    }
}

void libc_stat(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    uint64_t args[2] = { x0, x1 };
    call_func_begin("stat", args, 2);
    arg_string_from_reg(0, x0);
    if(debug)
    {
        LOGE("libc stat:0x%lx",x0);
    }
}

void libc_lstat(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    uint64_t args[2] = { x0, x1 };
    call_func_begin("lstat", args, 2);
    arg_string_from_reg(0, x0);
    if(debug)
    {
        LOGE("libc lstat:0x%lx",x0);
    }
}

void libc_fopen(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    uint64_t args[2] = { x0, x1 };
    call_func_begin("fopen", args, 2);
    arg_string_from_reg(0, x0);
    arg_string_from_reg(1, x1);
    if(debug)
    {
        LOGE("libc fopen:0x%lx",x0);
    }
}
