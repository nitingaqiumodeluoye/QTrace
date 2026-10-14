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

/* ===== 已知函数/系统调用的参数解码表 =====
 * 对标 GumTrace 的 func_configs（取其高价值子集）。
 * 表项只在「符号级 call func」与「SVC 系统调用」两条路径上使用，
 * 已经被 libc hook 命中的调用不会走到这里。 */
struct KnownFunc {
    const char* name;
    int8_t argc;
    int8_t str1;      // 字符串参数下标（-1 = 无）
    int8_t str2;
    int8_t hex_addr;  // hexdump 地址参数下标（-1 = 无）
    int8_t hex_len;   // hexdump 长度参数下标（-2 = 按字符串长度）
};

static const KnownFunc kKnownFuncs[] = {
    // 字符串
    { "strlen", 1, 0, -1, -1, -1 },
    { "__strlen_chk", 1, 0, -1, -1, -1 },
    { "__strlen_aarch64", 1, 0, -1, -1, -1 },
    { "strcmp", 2, 0, 1, -1, -1 },
    { "strncmp", 2, 0, 1, -1, -1 },
    { "strcasecmp", 2, 0, 1, -1, -1 },
    { "strcpy", 2, 0, 1, -1, -1 },
    { "strncpy", 2, 0, 1, -1, -1 },
    { "strcat", 2, 0, 1, -1, -1 },
    { "strncat", 2, 0, 1, -1, -1 },
    { "strstr", 2, 0, 1, -1, -1 },
    { "strcasestr", 2, 0, 1, -1, -1 },
    { "strchr", 2, 0, -1, -1, -1 },
    { "strrchr", 2, 0, -1, -1, -1 },
    { "strdup", 1, 0, -1, -1, -1 },
    { "strndup", 2, 0, -1, -1, -1 },
    { "strlcpy", 3, 0, 1, -1, -1 },
    { "strlcat", 3, 0, 1, -1, -1 },
    // 内存
    { "memcpy", 3, -1, -1, 1, 2 },
    { "__memcpy_chk", 3, -1, -1, 1, 2 },
    { "__memcpy_aarch64_simd", 3, -1, -1, 1, 2 },
    { "memmove", 3, -1, -1, 1, 2 },
    { "mempcpy", 3, -1, -1, 1, 2 },
    { "memset", 3, -1, -1, -1, -1 },
    { "memcmp", 3, -1, -1, 0, 2 },
    { "memchr", 3, 0, -1, -1, -1 },
    { "memmem", 4, -1, -1, 0, 1 },
    // 文件 / 进程
    { "open", 2, 0, -1, -1, -1 },
    { "openat", 4, 1, -1, -1, -1 },
    { "fopen", 2, 0, 1, -1, -1 },
    { "fopen64", 2, 0, 1, -1, -1 },
    { "read", 3, -1, -1, 1, 2 },
    { "pread64", 4, -1, -1, 1, 2 },
    { "write", 3, -1, -1, 1, 2 },
    { "pwrite64", 4, -1, -1, 1, 2 },
    { "close", 1, -1, -1, -1, -1 },
    { "stat", 2, 0, -1, -1, -1 },
    { "lstat", 2, 0, -1, -1, -1 },
    { "fstat", 2, -1, -1, -1, -1 },
    { "fstatat", 4, 1, -1, -1, -1 },
    { "newfstatat", 4, 1, -1, -1, -1 },
    { "access", 2, 0, -1, -1, -1 },
    { "faccessat", 3, 1, -1, -1, -1 },
    { "readlink", 3, 0, 1, -1, -1 },
    { "readlinkat", 4, 1, 2, -1, -1 },
    { "unlinkat", 3, 1, -1, -1, -1 },
    { "mkdirat", 3, 1, -1, -1, -1 },
    { "opendir", 1, 0, -1, -1, -1 },
    { "popen", 2, 0, 1, -1, -1 },
    { "execve", 3, 0, -1, -1, -1 },
    { "__system_property_get", 2, 0, -1, -1, -1 },
    // 格式化
    { "sprintf", 2, 0, -1, -1, -1 },
    { "snprintf", 3, 0, -1, -1, -1 },
    { "sscanf", 2, 0, 1, -1, -1 },
    { "fgets", 3, 0, -1, -1, -1 },
    // 分配 / 映射
    { "malloc", 1, -1, -1, -1, -1 },
    { "calloc", 2, -1, -1, -1, -1 },
    { "realloc", 2, -1, -1, -1, -1 },
    { "free", 1, -1, -1, -1, -1 },
    { "mmap", 6, -1, -1, -1, -1 },
    { "mmap64", 6, -1, -1, -1, -1 },
    { "mprotect", 3, -1, -1, -1, -1 },
    // 动态链接
    { "dlopen", 2, 0, -1, -1, -1 },
    { "dlsym", 2, 1, -1, -1, -1 },
    { "dlclose", 1, -1, -1, -1, -1 },
};

static const KnownFunc* find_known_func(const char* name)
{
    if (name == nullptr) {
        return nullptr;
    }
    for (const KnownFunc& f : kKnownFuncs) {
        if (strcmp(f.name, name) == 0) {
            return &f;
        }
    }
    return nullptr;
}

int known_func_argc(const char* name)
{
    const KnownFunc* f = find_known_func(name);
    return (f == nullptr) ? -1 : (int)f->argc;
}

void known_func_emit_args(const char* name, const uint64_t* x)
{
    const KnownFunc* f = find_known_func(name);
    if (f == nullptr || x == nullptr) {
        return;
    }
    if (f->str1 >= 0) {
        arg_string_from_reg(f->str1, x[f->str1]);
    }
    if (f->str2 >= 0) {
        arg_string_from_reg(f->str2, x[f->str2]);
    }
    if (f->hex_addr >= 0) {
        size_t len = 0;
        if (f->hex_len == -2) {
            len = 0;   // 按字符串长度（hexdump_to_log 内部处理）
        } else if (f->hex_len >= 0) {
            len = (size_t)x[f->hex_len];
        }
        hexdump_to_log(x[f->hex_addr], len, f->hex_len == -2);
    }
}
