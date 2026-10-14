//
// Created by zgy on 2025/11/27.
//

#ifndef XPOSEDNHOOK_HEXDUMP_H
#define XPOSEDNHOOK_HEXDUMP_H
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <iostream>
#include <mutex>
#include <unordered_map>
#include <iomanip>
#include <cctype>
#include <algorithm>

#include <sys/mman.h>  // for mincore
#include <unistd.h>    // for sysconf
#include <sys/uio.h>   // for process_vm_readv

#include "logger.h"

// 将内存块按 hexdump 格式输出到日志缓冲区
void hexdump_memory(std::stringstream &logbuf, const uint8_t* data, size_t size, uint64_t address,
                    int64_t header_size = -1) ;

// 安全读取目标内存并按 GumTrace 格式写入日志（用于 call func 注解的 hexdump）
void hexdump_to_log(uint64_t address, size_t count, bool force = false) ;

// 把已在本地的 buffer 按 GumTrace 格式写入日志（display_address 仅用于行首显示）
void hexdump_local_to_log(const uint8_t* data, size_t size, uint64_t display_address) ;
// 地址范围的结构体，用于缓存 maps 文件中的每个模块范围


// 缓存地址范围和已解析的符号信息
std::unordered_map<uint64_t, std::string>& getSymbolCache();

// 从 /proc/self/maps 读取并缓存模块地址范围
void loadMemoryRanges() ;

// 从缓存中查找地址范围内的符号信息
std::string getSymbolFromCache(uint64_t address) ;

// 判断地址是否在有效内存页上
bool isValidAddress(uint64_t address) ;

// 判断内存内容是否为有效的 ASCII 可打印字符串，且不为全空格
bool isAsciiPrintableString(const uint8_t* data, size_t length) ;
// 使用 process_vm_readv 安全读取内存的函数
bool safeReadMemory(uint64_t address, uint8_t* buffer, size_t length) ;

// 确保内存范围已加载（单例模式）
void ensureMemoryRangesLoaded() ;

// 参考vm.cpp的统一参数分析函数 - 自动识别地址/整数并处理
std::string analyzeParameter(const char* name, uint64_t value) ;

// 批量分析多个参数
std::string analyzeParameters(const char* names[], uint64_t values[], int count) ;
#endif //XPOSEDNHOOK_HEXDUMP_H