//
// Created by zgy on 2025/10/30.
//

#ifndef QBDI_JNITRACE_H
#define QBDI_JNITRACE_H
#include "vm.h"
#include <jni.h>
#include "unordered_map"

extern const JNINativeInterface* pJFunc;
extern JNIEnv * jniEnv;
void initJni();
void setup_jfunc(JNIEnv * jnienv);
void enable_jni_trace_debug(bool enable);

struct JNITraceMap {
    std::unordered_map<size_t, TraceFunc*> map;
};

extern JNITraceMap* _g_jni_trace;
void addJNITrace(void* target,const char* funcname,TraceCallBack callback);

/* ===== JNI 句柄 → 名称映射（GumTrace 的 jclass/jmethod 等价物） =====
 * trace-ui 不识别 "jclass:"/"jmethod:" 行（未识别的特殊行会被记入 consumed_seqs
 * 而隐藏），因此解析结果统一用 "argsN:" 承载（tooltip/summary/args 都能显示）。
 * 注意：JNI 的返回值只能在调用返回后读到，所以映射在 jni_after_call 里建立，
 * 由 vm.cpp 的 flushPending（下一条指令，此时已回到被插桩区域）调用。 */

/* 最近一次触发的 JNI trace 回调名（由 jni_call_begin 记录），vm.cpp 用它判断
 * 当前这条 BLR/BR 是不是 JNI 调用、以及是哪个 JNI 函数。 */
const char* jni_last_call_name();
void jni_clear_last_call_name();

/* 调用返回后：用返回值 x0 建立 jclass/jmethodID/jfieldID 映射，并把解析结果
 * （args0: <jclass ...> 等）写进当前指令的注解区。 */
void jni_after_call(const char* func_name, const uint64_t* pre_args, uint64_t ret_value);

void trace_FindClass(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_NewStringUTF(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_NewString(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_GetMethodID(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_RegisterNatives(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_GetStringUTFChars(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_GetFieldID(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_GetLongField(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_GetStaticMethodID(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_GetStaticFieldID(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_GetIntField(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_GetByteArrayRegion(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_CallStaticObjectMethodV(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_GetArrayLength(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_GetByteArrayElements(QBDI::VM *vm, QBDI::GPRState *gprState);

#endif //QBDI_JNITRACE_H
