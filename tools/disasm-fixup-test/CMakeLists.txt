cmake_minimum_required(VERSION 3.16)
project(disasm_fixup_test CXX)

# 注意:这里编译的是【仓库里真实的实现文件】
#   nativelib/src/main/cpp/hook/DisasmFixup.cpp
# 不是重写版。它只依赖 C++ 标准库,没有 QBDI / JNI / Android 依赖,
# 所以宿主机编译器就能编 —— 这样测试覆盖的就是 CI 编出来的那份代码。
#
# 之所以要这个测试:Android 工程只能在 CI 上编译,而 DisasmFixup 把 LLVM 的
# 反汇编文本改写成 capstone/GumTrace 风格,改错一个字就会让 trace-ui 解析失败,
# 或把内存偏移误改成绝对地址。以前只能靠跑一整轮 CI + 抓真机 trace 才能发现。
#
# 跑法:
#   cmake -B build && cmake --build build
#   ./build/test_disasm_fixup          (Windows: build\test_disasm_fixup.exe)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 默认开启优化以便发现 UB;需要调试时:cmake -B build -DCMAKE_BUILD_TYPE=Debug
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

get_filename_component(CPP_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../nativelib/src/main/cpp" ABSOLUTE)

if(NOT EXISTS "${CPP_DIR}/hook/DisasmFixup.cpp")
    message(FATAL_ERROR "找不到 ${CPP_DIR}/hook/DisasmFixup.cpp —— 本测试必须编译真实实现")
endif()

add_executable(test_disasm_fixup
    test_disasm_fixup.cpp
    ${CPP_DIR}/hook/DisasmFixup.cpp
)
target_include_directories(test_disasm_fixup PRIVATE ${CPP_DIR}/include ${CPP_DIR})

if(MSVC)
    target_compile_options(test_disasm_fixup PRIVATE /W3)
else()
    target_compile_options(test_disasm_fixup PRIVATE -Wall -Wextra)
endif()

enable_testing()
add_test(NAME disasm_fixup COMMAND test_disasm_fixup)