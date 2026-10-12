中文 | [English](README_en.md)

# QTrace
基于qbdi的安卓arm64真机trace工具,使用android studio构建

# Features
* arm64真机指令trace，内存读写监控
* 自定义函数监控
* 自定义jni函数监控
* 自定义libc函数监控

# Usage
0.将nativelib\src\main\cpp\qbdi-arm64\lib 目录下的libQBDI.zip解压出libQBDI.a，置于nativelib\src\main\cpp\qbdi-arm64\lib目录下。或去qbdi官方 https://github.com/QBDI/QBDI/releases/ 下载最新的libQBDI.a，注意选择andorid aarch64架构的,置于nativelib\src\main\cpp\qbdi-arm64\lib目录下

1.将trace的目标so push到/data/local/tmp目录下

2.root 环境下执行 setenforce 0

3.在 /nativelib/cpp/native_main.cpp 中，修改void config()中的相关配置

4.在qbdihook.cpp中添加自定义hook，在libctrace.cpp中添加需要trace 的libc函数，在jnitrace.cpp中添加需要trace的jni函数

5.Build-Generate Apks,将自动生成libnativelib.so ,将其 push 到 /data/local/tmp目录下

6.使用第三方工具注入libnativelib.so 到目标进程，可使用项目自带的frida脚本inject.js

# 使用教程
[QTrace：基于QBDI的高稳定，高定制的trace工具](https://bbs.kanxue.com/thread-290574.htm)