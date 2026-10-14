//
// 符号表（对标 GumTrace 的 func_maps）：把内存地址解析成函数名，
// 用于打印符号级 `call func:` 注解。
//
// 为什么不用 dladdr / dl_iterate_phdr：
//   这些 API 会取动态链接器的锁，而我们的回调运行在**被插桩线程**上。
//   若该线程此刻正持有该锁（例如被插桩代码正从 dlopen 的构造回调里执行），
//   调用它们会直接死锁。因此这里只读 /proc/self/maps 和 ELF 文件本身，
//   全程不触碰链接器锁。
//
// 符号按模块惰性解析：只有真正调用到某个模块时才解析它的符号表，
// 避免在 trace 启动时把几百个模块全读一遍。
//

#ifndef QTRACE_SYMBOLS_H
#define QTRACE_SYMBOLS_H

#include <cstdint>

// 读取 /proc/self/maps 建立模块表（在 trace 开始前调用一次）
void symbols_init();

// 精确匹配：返回起始地址恰好等于 addr 的函数名（等价 GumTrace 的
// func_maps 精确匹配语义）。未命中返回 nullptr。返回的指针为内部存储。
const char* symbols_lookup_exact(uint64_t addr);

// 包含匹配：返回包含 addr 的函数名，并通过 sym_start 回传其起始地址
// （用于 "name+0xoff" 形式）。未命中返回 nullptr。
const char* symbols_lookup_containing(uint64_t addr, uint64_t* sym_start);

#endif // QTRACE_SYMBOLS_H
