//
// Created by zgy on 2025/11/12.
//
#include "libctrace.h"
#include "dlfcn.h"
#include "logger.h"
#include "HookUtils.h"
#include "TraceUtils.h"
#include <sstream>
#include <iomanip>
LibcTraceMap* _g_libc_trace = nullptr;
static bool debug = false;

static std::string readStringForTrace(uint64_t address, size_t maxLength = 4096)
{
    std::string value;
    if (!safeReadCString(address, value, maxLength)) {
        std::ostringstream output;
        output << "<unreadable@0x" << std::hex << address << ">";
        return output.str();
    }
    return value;
}

static std::string describeBuffer(uint64_t address, size_t length)
{
    std::vector<uint8_t> bytes;
    if (!safeReadBytes(address, length, bytes, 256)) {
        return "<unreadable>";
    }

    bool printable = !bytes.empty();
    size_t stringLength = 0;
    for (; stringLength < bytes.size(); ++stringLength) {
        if (bytes[stringLength] == 0) break;
        if (bytes[stringLength] < 0x20 || bytes[stringLength] > 0x7e) {
            printable = false;
            break;
        }
    }
    if (printable) {
        return std::string(reinterpret_cast<const char*>(bytes.data()), stringLength);
    }

    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (uint8_t byte : bytes) output << std::setw(2) << static_cast<unsigned>(byte);
    if (length > bytes.size()) output << "...<truncated>";
    return output.str();
}

static void appendStringArg(size_t index, uint64_t address, const std::string& value)
{
    appendPendingCallArg(index, value);
    if (address == 0 || value.rfind("<unreadable", 0) == 0) return;

    std::vector<uint8_t> bytes;
    const size_t requested = std::min<size_t>(value.size() + 1, 256);
    if (safeReadBytes(address, requested, bytes, 256)) {
        appendPendingCallHexdump(address, bytes.data(), bytes.size());
    }
}

static void appendBufferArg(size_t index, uint64_t address, size_t length)
{
    std::vector<uint8_t> bytes;
    if (!safeReadBytes(address, length, bytes, 256)) {
        appendPendingCallArg(index, "<unreadable buffer>");
        return;
    }
    appendPendingCallArg(index, describeBuffer(address, length));
    appendPendingCallHexdump(address, bytes.data(), bytes.size());
}

void enable_libc_trace_debug(bool enable)
{
    debug = enable;
}

void initLibcTrace()
{
    if (_g_libc_trace != nullptr) return;
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
    TraceFunc* func_trace = new TraceFunc();
    func_trace->callback = callback;
    func_trace->name = funcname;
    _g_libc_trace->map[addr] = func_trace;
    LOGE("libc trace: %s:%p install",funcname,(void*)addr);
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
    std::string source = describeBuffer(x1, x2);
    if(debug) LOGE("libc memmove: %s",source.c_str());
    appendBufferArg(1, x1, x2);
    appendPendingCallArg(2, std::to_string(x2));
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
    appendPendingCallArg(1, std::to_string(x1));
    appendPendingCallArg(2, std::to_string(x2));
}

void libc_memcpy(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    uint64_t x2 = QBDI_GPR_GET(gprState, 2);
    std::string source = describeBuffer(x1, x2);
    if(debug) LOGE("libc memcpy: %s",source.c_str());
    appendBufferArg(1, x1, x2);
    appendPendingCallArg(2, std::to_string(x2));
}

void libc_access(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    std::string path = readStringForTrace(x0);
    if(debug)
    {
        LOGE("libc access:%s",path.c_str());
    }
    appendStringArg(0, x0, path);
}

void libc_system_property_get(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("qdbi hook:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    std::string property = readStringForTrace(x0);
    if(debug)
    {
        LOGE("libc _system_property_get:%s",property.c_str());
    }
    appendStringArg(0, x0, property);
}

void libc_pthread_create(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("qdbi hook:logger not init!");
        return;
    }
    uint64_t x2 = QBDI_GPR_GET(gprState, 2);
    if(debug)
    {
        LOGE("libc pthread_create:%lx",x2 - _g_trace_data->base);
    }
    appendPendingCallArg(2, "start_routine+0x" + std::to_string(x2 - _g_trace_data->base));
}

void libc_clock_gettime(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(debug)
    {
        LOGE("libc clock_gettime");
    }
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    appendPendingCallArg(1, std::to_string(x1));
}

void libc_exit(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(debug)
    {
        LOGE("libc exit");
    }
    appendPendingCallArg(0, std::to_string(QBDI_GPR_GET(gprState, 0)));
}

void libc_abort(QBDI::VM *vm, QBDI::GPRState *gprState)
{
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
    std::string value = readStringForTrace(x0);
    if(debug)
    {
        LOGE("libc strlen:%s",value.c_str());
    }
    appendStringArg(0, x0, value);
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
    std::string path = readStringForTrace(x0);
    if(debug)
    {
        LOGE("libc execv:%s",path.c_str());
        for (size_t index = 0; index < 128; ++index)
        {
            uint64_t argAddress = 0;
            if (!safeReadMemory(x1 + index * sizeof(uint64_t),
                                reinterpret_cast<uint8_t*>(&argAddress), sizeof(argAddress)) ||
                argAddress == 0) break;
            std::string argument = readStringForTrace(argAddress);
            LOGE("[log] libc execv argv:%s",argument.c_str());
        }
    }
    appendStringArg(0, x0, path);
    for (size_t index = 0; index < 128; ++index)
    {
        uint64_t argAddress = 0;
        if (!safeReadMemory(x1 + index * sizeof(uint64_t),
                            reinterpret_cast<uint8_t*>(&argAddress), sizeof(argAddress)) ||
            argAddress == 0) break;
        appendStringArg(index + 1, argAddress, readStringForTrace(argAddress));
    }
}

void libc_fstatat(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    std::string path = readStringForTrace(x1);
    if(debug)
    {
        LOGE("libc fstat:%s",path.c_str());
    }
    appendStringArg(1, x1, path);
}

void libc_stat(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    std::string path = readStringForTrace(x0);
    if(debug)
    {
        LOGE("libc stat:%s",path.c_str());
    }
    appendStringArg(0, x0, path);
}

void libc_lstat(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    std::string path = readStringForTrace(x0);
    if(debug)
    {
        LOGE("libc lstat:%s",path.c_str());
    }
    appendStringArg(0, x0, path);
}

void libc_fopen(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(_logger == nullptr)
    {
        LOGE("libc trace:logger not init!");
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState, 0);
    std::string path = readStringForTrace(x0);
    if(debug)
    {
        LOGE("libc fopen:%s",path.c_str());
    }
    appendStringArg(0, x0, path);
}
