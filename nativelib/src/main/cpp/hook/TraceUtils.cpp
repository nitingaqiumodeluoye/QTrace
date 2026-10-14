//
// Created by zgy on 2025/11/27.
//
#include "TraceUtils.h"
// 将内存块按 GumTrace 的 hexdump 格式输出到日志缓冲区
// GumTrace 格式:
//   hexdump at address 0x1234 with length 0x10:
//   1234: 48 74 74 70 ... |Http|
// header_size >= 0 时，标题里的 length 用它（用于 GumTrace 的 SPECIAL_32：
// 标题显示传入的原始 count（如 0），而实际打印长度是 strnlen 的结果）。
void hexdump_memory(std::stringstream &logbuf, const uint8_t* data, size_t size, uint64_t address,
                    int64_t header_size) {
    const size_t hdr = (header_size < 0) ? size : (size_t)header_size;
    logbuf << "hexdump at address 0x" << std::hex << address
           << " with length 0x" << std::hex << hdr << ":\n";

    size_t offset = 0;
    while (offset < size) {
        // 输出当前行的基址（GumTrace 不加零填充、不加中间分隔）
        logbuf << std::hex << (address + offset) << ": ";

        std::string ascii("|"); // 暂存 ASCII 字符串
        for (size_t i = 0; i < 16; ++i) {
            if (offset + i < size) {
                uint8_t byte = data[offset + i];
                logbuf << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(byte) << " ";
                ascii += (std::isprint(byte) ? static_cast<char>(byte) : '.');
            } else {
                logbuf << "   "; // 数据不足 16 字节时填充空格
                ascii += " ";
            }
        }
        ascii += "|";
        logbuf << ascii;

        if (offset + 16 < size) {
            logbuf << "\n";
        }
        offset += 16;
    }
}

// 安全地把 [address, address+count) 的内存按 GumTrace 格式写入日志。
/* 安全版的 strnlen：分块读，遇到不可读的页或 NUL 就停。
 * GumTrace 在 SPECIAL_32 分支里是直接 strnlen(bytePtr, 4096)，
 * 指针不可读时会把进程带走；我们用 process_vm_readv 分块读，
 * 语义等价但不会崩（free 的参数正是已释放/即将释放的指针）。 */
static size_t safe_strnlen(uint64_t address, size_t maxlen) {
    if (maxlen == 0) {
        return 0;
    }
    static thread_local std::vector<uint8_t> tmp;

    // 先试一次读完（绝大多数情况都在同一页内）
    tmp.resize(maxlen);
    if (safeReadMemory(address, tmp.data(), maxlen)) {
        size_t n = 0;
        while (n < maxlen && tmp[n] != 0) {
            ++n;
        }
        return n;
    }

    // 跨页/尾部不可读：按 64B 分块，读到不可读的块就停
    tmp.resize(64);
    size_t n = 0;
    while (n < maxlen) {
        size_t want = (maxlen - n < 64) ? (maxlen - n) : 64;
        if (!safeReadMemory(address + n, tmp.data(), want)) {
            if (want <= 1 || !safeReadMemory(address + n, tmp.data(), 1)) {
                break;   // 连 1 字节都读不到，就到此为止
            }
            want = 1;
        }
        for (size_t i = 0; i < want; ++i) {
            if (tmp[i] == 0) {
                return n + i;
            }
        }
        n += want;
    }
    return n;
}

// 用于 call func / call jni func 注解中的 hexdump（GumTrace 的 hexdump 注解）。
void hexdump_to_log(uint64_t address, size_t count, bool force) {
    // AArch64 userspace 合法指针几乎都 > 4GB，小值当作整型参数丢弃
    if (address < 0x100000000ULL) {
        return;
    }

    /* 长度语义对齐 GumTrace::FuncPrinter::hexdump：
     *   count > 0             => 打印 count 字节
     *   count == 0 且 force    => SPECIAL_32，即 strnlen(ptr, 0x1000)
     *                            （free / realloc / gettimeofday 走这条）
     *   其余                   => 不打印
     * 注意标题里的 length 始终是**传入的 count**：GumTrace 也是先把原始
     * count 写进标题，之后才用 strnlen 覆盖局部变量，所以 free 的输出是
     *     hexdump at address 0x... with length 0x0:
     * 后面直接跟按 strnlen 长度切的数据行。 */
    size_t print_len = count;
    if (print_len == 0) {
        if (!force) {
            return;
        }
        print_len = safe_strnlen(address, 0x1000);
    }
    if (print_len > 0x1000) {
        print_len = 0x1000;
    }

    static thread_local std::vector<uint8_t> buf;
    buf.resize(print_len ? print_len : 1);
    if (print_len > 0 && !safeReadMemory(address, buf.data(), print_len)) {
        return;
    }

    std::stringstream ss;
    hexdump_memory(ss, buf.data(), print_len, address, (int64_t)count);
    appendlog(ss.str().c_str());
    appendlogendl();
}

// 缓存地址范围和已解析的符号信息
std::unordered_map<uint64_t, std::string>& getSymbolCache() {
    static std::unordered_map<uint64_t, std::string> symbolCache;
    return symbolCache;
}
struct MemoryRange {
    uint64_t startAddr;
    uint64_t endAddr;
    std::string pathname;
};
std::vector<MemoryRange>& getMemoryRanges() {
    static std::vector<MemoryRange> memoryRanges;
    return memoryRanges;
}

// 把已在本地的 buffer 按 GumTrace 格式写入日志
void hexdump_local_to_log(const uint8_t* data, size_t size, uint64_t display_address) {
    if (data == nullptr || size == 0) {
        return;
    }
    if (size > 0x1000) {
        size = 0x1000;
    }
    std::stringstream ss;
    hexdump_memory(ss, data, size, display_address);
    appendlog(ss.str().c_str());
    appendlogendl();
}

// 从 /proc/self/maps 读取并缓存模块地址范围
void loadMemoryRanges() {
    std::ifstream mapsFile("/proc/self/maps");
    std::string line;
    auto& memoryRanges = getMemoryRanges();

    while (std::getline(mapsFile, line)) {
        std::istringstream iss(line);
        std::string addrRange, perms, offset, dev, inode, pathname;
        uint64_t startAddr, endAddr;

        // 解析 maps 文件的一行内容
        iss >> addrRange >> perms >> offset >> dev >> inode;
        if (!(iss >> pathname)) {
            pathname = ""; // 如果没有路径，将其设为空字符串
        }

        size_t pos = pathname.find_last_of('/');
        std::string filename = (pos == std::string::npos) ? pathname : pathname.substr(pos + 1);

        // 解析地址范围
        std::replace(addrRange.begin(), addrRange.end(), '-', ' ');
        std::istringstream addrStream(addrRange);
        addrStream >> std::hex >> startAddr >> endAddr;

        // 添加到缓存的内存范围
        memoryRanges.push_back({startAddr, endAddr, filename});
    }
}

// 从缓存中查找地址范围内的符号信息
std::string getSymbolFromCache(uint64_t address) {
    auto& symbolCache = getSymbolCache();
    auto& memoryRanges = getMemoryRanges();

    // 检查缓存
    if (symbolCache.find(address) != symbolCache.end()) {
        return symbolCache[address];
    }

    // 遍历已缓存的地址范围
    for (const auto& range : memoryRanges) {
        if (address >= range.startAddr && address < range.endAddr) {
            uint64_t addrOffset = address - range.startAddr;
            std::ostringstream symbolStream;
            symbolStream << range.pathname << "[0x" << std::hex << addrOffset << "]";
            std::string symbol = symbolStream.str();

            // 将结果存入缓存
            symbolCache[address] = symbol;
            return symbol;
        }
    }

    // 未找到时返回空字符串
    symbolCache[address] = "";  // 记录无符号信息，避免重复查找
    return "";
}

// 判断地址是否在有效内存页上
bool isValidAddress(uint64_t address) {
    if (address == 0x7603511e){
//        LOGE("address : %p",address);
//        return false;
    }
    // 获取系统页大小
    long pageSize = sysconf(_SC_PAGESIZE);
    if (pageSize <= 0) {
        return false;
    }

    // 对齐地址到页大小
    void* alignedAddress = reinterpret_cast<void*>(address & ~(pageSize - 1));
    unsigned char vec;

    // 使用 mincore 检查该地址是否为有效内存页
    if (mincore(alignedAddress, pageSize, &vec) == 0) {
        return true;  // 地址有效
    }
    return false;  // 地址无效
}

// 判断内存内容是否为有效的 ASCII 可打印字符串，且不为全空格
bool isAsciiPrintableString(const uint8_t* data, size_t length) {
    if (data == nullptr) {
        LOGD("Error: data is NULL");
        return false;  // 数据为空，返回无效字符串
    }

    bool hasNonSpaceChar = false;  // 标记是否包含非空格字符
    for (size_t i = 0; i < length; ++i) {
        if (data[i] == '\0') {
            return hasNonSpaceChar;  // 如果遇到终止符，且包含非空格字符，则认为是有效字符串
        }
        if (data[i] < 0x20 || data[i] > 0x7E) {
            return false;  // 如果包含非 ASCII 可打印字符，视为无效字符串
        }
        if (data[i] != ' ') {
            hasNonSpaceChar = true;  // 检测到非空格字符
        }
    }
    return hasNonSpaceChar;  // 字符串没有终止符时，检查是否包含非空格字符
}

// 使用 process_vm_readv 安全读取内存的函数
bool safeReadMemory(uint64_t address, uint8_t* buffer, size_t length) {
    struct iovec local_iov;
    struct iovec remote_iov;

    local_iov.iov_base = buffer;
    local_iov.iov_len = length;

    remote_iov.iov_base = reinterpret_cast<void*>(address);
    remote_iov.iov_len = length;

    ssize_t nread = process_vm_readv(getpid(), &local_iov, 1, &remote_iov, 1, 0);
    if (nread == static_cast<ssize_t>(length)) {
        return true;  // 成功读取
    } else {
        // 可以记录错误信息，便于调试
//        LOGE("process_vm_readv failed at address 0x%lx: %s", address, strerror(errno));
        return false;  // 读取失败
    }
}

// 确保内存范围已加载（单例模式）
void ensureMemoryRangesLoaded() {
    static bool rangesLoaded = false;
    if (!rangesLoaded) {
        loadMemoryRanges();
        rangesLoaded = true;
    }
}

// 参考vm.cpp的统一参数分析函数 - 自动识别地址/整数并处理
std::string analyzeParameter(const char* name, uint64_t value) {
    std::stringstream output;
    output << name << "=0x" << std::hex << value;

    if (isValidAddress(value)) {
        size_t maxLen = 256;
        uint8_t buffer[256];
        if (safeReadMemory(value, buffer, maxLen)) {
            if (isAsciiPrintableString(buffer, maxLen)) {
                output << " -> Strings :" << std::string(reinterpret_cast<const char*>(buffer));
            } else {
                // 获取符号信息用于显示相对偏移
                /*  std::string symbol = getSymbolFromCache(value);
                  output << " -> Hexdump for " << name << " at address 0x" << std::hex << value;
                  if (!symbol.empty()) {
                      output << " (" << symbol << ")";
                  }
                  output << ":\n";
                  hexdump_memory(output, buffer, 32, value);*/
            }
        } else {
            output << " -> Invalid memory access at address 0x" << std::hex << value;
        }
    } else if (value != 0) {
        output << " (" << std::dec << value << ")";
    }

    return output.str();
}

// 批量分析多个参数
std::string analyzeParameters(const char* names[], uint64_t values[], int count) {
    std::stringstream output;
    for (int i = 0; i < count; i++) {
        output << analyzeParameter(names[i], values[i]);
        if (i < count - 1) output << ", ";
    }
    return output.str();
}