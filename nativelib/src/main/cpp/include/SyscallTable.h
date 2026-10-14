//
// aarch64 Linux 系统调用名表（与 GumTrace 的 svc_func_maps 同源），
// 用于 SVC 指令的 `call func: <syscall>(...)` 注解。
//

#ifndef QTRACE_SYSCALL_TABLE_H
#define QTRACE_SYSCALL_TABLE_H

#include <cstdint>

// 按系统调用号取名字；未收录返回 nullptr
const char* syscall_name(uint64_t nr);

// 参数个数（用于注解里打印几个 x 寄存器）。
// 已收录的常见 syscall 返回确切个数；未收录时按「最后一个非零参数」推断，
// 最少 0、最多 6（aarch64 系统调用的 ABI 上限）。
int syscall_argc(uint64_t nr, const uint64_t* x);

#endif // QTRACE_SYSCALL_TABLE_H
