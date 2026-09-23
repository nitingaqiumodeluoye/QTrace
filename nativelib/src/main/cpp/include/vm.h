//
// Created by fang on 23-12-19.
//

#ifndef QBDIRECORDER_VM_H
#define QBDIRECORDER_VM_H
#include "QBDI.h"
#include "QBDI/State.h"
#include "logger.h"
#include <sstream>
#include <string>
#include "shadowhook.h"

typedef void (*TraceCallBack)(QBDI::VM *vm, QBDI::GPRState *gprState);
typedef bool (*TraceFilter)(size_t regs[]);

struct TraceFunc {
    TraceCallBack callback;
    std::string name;
};

class vm {
public:
    QBDI::VM init(size_t start,size_t end);
    size_t base;
    bool initialized = false;
private:

};
typedef void (*orig_func_t)(void*);

struct g_trace_data{
    size_t base;
    size_t start;
    size_t end;
    size_t target;
    std::string module_name;
    void* hooktask;
    orig_func_t orig_addr;
};

extern g_trace_data* _g_trace_data;
extern int bufsize ;
extern bool debugInsn;
void setBufferSize(int);
void enableDebugInsn(bool);
void setTraceFilter(TraceFilter filter);
// Limits stop recording, never stop/replay target execution. Zero means unlimited.
void setTraceLimits(size_t instructions, size_t bytes);

void sync_regs(size_t* regs,size_t pc,QBDI::GPRState* qbdi_state);
void appendPendingCallArg(const std::string& index, const std::string& value);
void appendPendingCallArg(size_t index, const std::string& value);
void appendPendingCallHexdump(uint64_t address, const uint8_t* data, size_t size);

typedef size_t (*func_arg_8)(size_t x0,size_t x1,size_t x2,size_t x3,size_t x4,size_t x5,size_t x6,size_t x7);
extern func_arg_8 ori_arg8;
size_t hook_and_trace_arg8(size_t x0,size_t x1,size_t x2,size_t x3,size_t x4,size_t x5,size_t x6,size_t x7);

#endif //QBDIRECORDER_VM_H
