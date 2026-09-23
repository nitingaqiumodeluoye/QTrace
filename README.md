中文 | [English](README_en.md)

# QTrace
基于qbdi的安卓arm64真机trace工具,使用android studio构建

# Features
* arm64真机指令trace，内存读写监控
* 自定义函数监控
* 自定义jni函数监控
* 自定义libc函数监控
* 输出兼容 [trace-ui](https://github.com/imj01y/trace-ui) 的 GumTrace 日志格式

# Trace Log Format

指令日志使用 GumTrace 兼容格式，可直接导入 trace-ui：

```
[模块名] 0x绝对地址!0x相对偏移 助记符 操作数; 读寄存器 mem_r=地址 mem_w=地址 -> 写寄存器
```

示例：

```
[libtiny.so] 0x7a3c001890!0x1890 ldr x0, [x1, #0x10]; x1=0x7a3c050000 mem_r=0x7a3c050010 -> x0=0x12345678
[libtiny.so] 0x7a3c001894!0x1894 br x17; x17=0x7a3c100000
call func: memcpy(0x7a3c060000, 0x7a3c050010, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0)
```

# Usage

当前工作分支从 **TrustAttestor nativeRun**（`libTrustAttestor.so`，ELF `0x1A73C0`）启动 QBDI，仅记录设备环境函数 `[0x7097A8,0x742B40)` 内的指令。每进程首轮 nativeRun 调用，日志阈值 2 GiB，不限指令条数。入口校验、限额语义、CI 出包和注入方式见 [TrustAttestor 说明](docs/TrustAttestor.md)。
0.将nativelib\src\main\cpp\qbdi-arm64\lib 目录下的libQBDI.zip解压出libQBDI.a，置于nativelib\src\main\cpp\qbdi-arm64\lib目录下。或去qbdi官方 https://github.com/QBDI/QBDI/releases/ 下载最新的libQBDI.a，注意选择andorid aarch64架构的,置于nativelib\src\main\cpp\qbdi-arm64\lib目录下

1.将trace的目标so push到/data/local/tmp目录下

2.root 环境下执行 setenforce 0

3.在 /nativelib/cpp/native_main.cpp 中，修改void config()中的相关配置

4.在qbdihook.cpp中添加自定义hook，在libctrace.cpp中添加需要trace 的libc函数，在jnitrace.cpp中添加需要trace的jni函数

5.Build-Generate Apks,将自动生成libnativelib.so ,将其 push 到 /data/local/tmp目录下

6.使用第三方工具注入libnativelib.so 到目标进程，可使用项目自带的frida脚本inject.js

# 使用教程
[QTrace：基于QBDI的高稳定，高定制的trace工具](https://bbs.kanxue.com/thread-290574.htm)
