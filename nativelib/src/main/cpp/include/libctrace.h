//
// Created by zgy on 2025/11/12.
//

#ifndef QBDI_LIBCTRACE_H
#define QBDI_LIBCTRACE_H
#include "vm.h"
#include <unordered_map>

struct LibcTraceMap {
    std::unordered_map<size_t, TraceFunc*> map;
};

extern LibcTraceMap* _g_libc_trace;

bool hasLibctrace();
void initLibcTrace();
void addLibctrace(void* handle,TraceCallBack callback,const char* funcname);

void libc_access(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_system_property_get(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_memcpy(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_memmove(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_pthread_create(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_fopen(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_lstat(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_execve(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_clock_gettime(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_stat(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_fstatat(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_kill(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_abort(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_exit(QBDI::VM *vm, QBDI::GPRState *gprState);
void enable_libc_trace_debug(bool enable);

/* ===== 已知函数/系统调用的参数解码（符号级 call func 与 SVC 注解共用） =====
 * 对标 GumTrace 的 func_configs：把字符串参数写成 argsN: 行、
 * 把缓冲区参数写成 hexdump。表只收录高价值的常见函数，
 * 未收录的名字不输出任何参数行（与 GumTrace 对未知符号打印 () 一致）。 */

/* 返回已知参数个数；未收录返回 -1 */
int known_func_argc(const char* name);

/* 按表打印 argsN: / hexdump 注解（未收录则不输出） */
void known_func_emit_args(const char* name, const uint64_t* x);
void libc_strlen(QBDI::VM *vm, QBDI::GPRState *gprState);
void libc_memset(QBDI::VM *vm, QBDI::GPRState *gprState);

#endif //QBDI_LIBCTRACE_H
