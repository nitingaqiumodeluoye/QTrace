//
// Created by zgy on 2025/10/30.
//

#include <dlfcn.h>
#include "jnitrace.h"
#include "HookUtils.h"
#include "logger.h"
#include "TraceUtils.h"
#include <algorithm>

const JNINativeInterface* pJFunc = nullptr;
 JNIEnv * jniEnv = nullptr;
JNITraceMap* _g_jni_trace = nullptr;
static bool debug = false;

static std::string readJniString(uint64_t address)
{
    std::string value;
    if (!safeReadCString(address, value, 4096)) return "<unreadable>";
    return value;
}

static std::string formatAddress(uint64_t address, const char* label)
{
    std::ostringstream output;
    output << label << "@0x" << std::hex << address;
    return output.str();
}

static void appendJniStringArg(const std::string& index, uint64_t address,
                               const std::string& value)
{
    appendPendingCallArg(index, value);
    if (address == 0 || value == "<unreadable>") return;

    std::vector<uint8_t> bytes;
    const size_t requested = std::min<size_t>(value.size() + 1, 256);
    if (safeReadBytes(address, requested, bytes, 256)) {
        appendPendingCallHexdump(address, bytes.data(), bytes.size());
    }
}

static void appendJniStringArg(size_t index, uint64_t address, const std::string& value)
{
    appendJniStringArg(std::to_string(index), address, value);
}

bool initJni()
{
    LOGE("Find Jni");
    typedef jint (*JNI_GetCreatedJavaVMs_t)(JavaVM**, jsize, jsize*);
    JNI_GetCreatedJavaVMs_t getCreatedVMs = (JNI_GetCreatedJavaVMs_t)dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs");//(JNI_GetCreatedJavaVMs_t)findSymbolInLibArt("libart.so","JNI_GetCreatedJavaVMs");
    JavaVM* jvm = nullptr;
    jsize count = 0;
    if(getCreatedVMs == nullptr)
    {
        LOGE("无法获取 JNI_GetCreatedJavaVMs 符号地址");
        return false;
    }
    jint result = getCreatedVMs(&jvm, 1, &count);

    if (result != JNI_OK || count == 0) {
        LOGE("无法获取 JavaVM 实例");
        return false;
    } else{
        LOGE("get JavaVM success");
    }

    JNIEnv* env = nullptr;
    result = jvm->AttachCurrentThread((JNIEnv **) &env, nullptr);

    if (result != JNI_OK || !env) {
        LOGE("无法获取 JNIEnv 实例");
        return false;
    }
    jint jniVersion = env->GetVersion();
    LOGE("get JNIEnv success:%x",jniVersion);
    setup_jfunc(env);
    return pJFunc != nullptr;
}

void enable_jni_trace_debug(bool enable)
{
    debug = enable;
}

static bool checkSetup()
{
    if(pJFunc == nullptr)
    {
        LOGE("checkJniCall,pJFunc not init");
        return false;
    }
    if(_logger == nullptr)
    {
        LOGE("checkJniCall,_logger not init");
        return false;
    }
    return true;
}

void trace_FindClass(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t classname = QBDI_GPR_GET(gprState, 1);
    std::string className = readJniString(classname);
    if(debug)
    {
        LOGE("JNI FindClass: %s",className.c_str());
    }
    appendJniStringArg(1, classname, className);
}

void trace_GetStringUTFChars(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t jstr = QBDI_GPR_GET(gprState,1);
    uint64_t jbool = QBDI_GPR_GET(gprState,2);
    if(debug)
    {
        LOGE("JNI GetStringUTFChars: jstring:%p,isCopy:%p",(void*)jstr,(void*)jbool);
    }
    appendPendingCallArg(1, formatAddress(jstr, "jstring"));
    appendPendingCallArg(2, formatAddress(jbool, "isCopy"));
}

void trace_GetFieldID(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t name = QBDI_GPR_GET(gprState,2);
    uint64_t sig = QBDI_GPR_GET(gprState,3);
    std::string fieldName = readJniString(name);
    std::string signature = readJniString(sig);
    if(debug)
    {
        LOGE("JNI GetFieldID: name:%s,sig:%s",fieldName.c_str(),signature.c_str());
    }
    appendJniStringArg(2, name, fieldName);
    appendJniStringArg(3, sig, signature);
}

void trace_GetByteArrayElements(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t arr = QBDI_GPR_GET(gprState,1);
    if(debug)
    {
        LOGE("JNI GetByteArrayElements: array:%p",(void*)arr);
    }
    appendPendingCallArg(1, formatAddress(arr, "byteArray"));
}

void trace_GetArrayLength(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t arr = QBDI_GPR_GET(gprState,1);
    if(debug)
    {
        LOGE("JNI GetArrayLength: array:%p",(void*)arr);
    }
    appendPendingCallArg(1, formatAddress(arr, "array"));
}

void trace_GetByteArrayRegion(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t x1 = QBDI_GPR_GET(gprState,1);
    uint64_t x2 = QBDI_GPR_GET(gprState,2);
    uint64_t len = QBDI_GPR_GET(gprState,3);
    uint64_t jbuf = QBDI_GPR_GET(gprState,4);
    if(debug)
    {
        LOGE("JNI GetByteArrayRegion: array:%p,start:%lu,len:%lu,buf:%p",
             (void*)x1,x2,len,(void*)jbuf);
    }
    appendPendingCallArg(1, formatAddress(x1, "byteArray"));
    appendPendingCallArg(2, std::to_string(x2));
    appendPendingCallArg(3, std::to_string(len));
    appendPendingCallArg(4, formatAddress(jbuf, "buffer"));
}

void trace_GetIntField(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t jfield = QBDI_GPR_GET(gprState,2);
    if(debug)
    {
        LOGE("JNI GetIntField: fieldId:%p",(void*)jfield);
    }
    appendPendingCallArg(2, formatAddress(jfield, "fieldId"));
}

void trace_GetStaticFieldID(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t name = QBDI_GPR_GET(gprState,2);
    std::string fieldName = readJniString(name);
    if(debug)
    {
        LOGE("JNI GetStaticFieldID: %s",fieldName.c_str());
    }
    appendJniStringArg(2, name, fieldName);
}

void trace_CallStaticObjectMethodV(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    if(debug)
    {
        LOGE("JNI CallStaticObjectMethodV");
    }
    appendPendingCallArg(1, formatAddress(QBDI_GPR_GET(gprState, 1), "class"));
    appendPendingCallArg(2, formatAddress(QBDI_GPR_GET(gprState, 2), "methodId"));
}
void trace_GetStaticMethodID(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t name = QBDI_GPR_GET(gprState,2);
    std::string methodName = readJniString(name);
    if(debug)
    {
        LOGE("JNI GetStaticMethodID: %s",methodName.c_str());
    }
    appendJniStringArg(2, name, methodName);
    uint64_t signatureAddress = QBDI_GPR_GET(gprState, 3);
    appendJniStringArg(3, signatureAddress, readJniString(signatureAddress));
}
void trace_GetLongField(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t jfield = QBDI_GPR_GET(gprState,2);
    if(debug)
    {
        LOGE("JNI GetLongField: fieldId:%p",(void*)jfield);
    }
    appendPendingCallArg(2, formatAddress(jfield, "fieldId"));
}

void trace_RegisterNatives(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t funcs = QBDI_GPR_GET(gprState,2);
    uint64_t func_num = std::min<uint64_t>(QBDI_GPR_GET(gprState,3), 512);
    for(uint64_t i = 0;i<func_num;i++)
    {
        JNINativeMethod method{};
        if (!safeReadMemory(funcs + i * sizeof(JNINativeMethod),
                            reinterpret_cast<uint8_t*>(&method), sizeof(method))) {
            appendPendingCallArg("2." + std::to_string(i), "<unreadable method table>");
            break;
        }
        std::string signature = readJniString(reinterpret_cast<uint64_t>(method.signature));
        std::string name = readJniString(reinterpret_cast<uint64_t>(method.name));
        if(debug)
        {
            LOGE("JNI RegisterNatives: %s,%s,%p",signature.c_str(),name.c_str(),
                 (void*)((size_t)method.fnPtr - _g_trace_data->base));
        }
        std::ostringstream methodInfo;
        methodInfo << name << signature << " -> " << _g_trace_data->module_name
                   << "+0x" << std::hex << ((size_t)method.fnPtr - _g_trace_data->base);
        appendPendingCallArg("2." + std::to_string(i), methodInfo.str());
        appendJniStringArg("2." + std::to_string(i) + ".name",
                           reinterpret_cast<uint64_t>(method.name), name);
        appendJniStringArg("2." + std::to_string(i) + ".sig",
                           reinterpret_cast<uint64_t>(method.signature), signature);
    }
}

void trace_GetMethodID(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t str = QBDI_GPR_GET(gprState, 2);
    std::string methodName = readJniString(str);
    if(debug)
    {
        LOGE("JNI GetMethodID: %s",methodName.c_str());
    }
    appendJniStringArg(2, str, methodName);
    uint64_t signatureAddress = QBDI_GPR_GET(gprState, 3);
    appendJniStringArg(3, signatureAddress, readJniString(signatureAddress));
}

void trace_NewString(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t str = QBDI_GPR_GET(gprState, 1);
    uint64_t length = QBDI_GPR_GET(gprState, 2);
    if(debug)
    {
        LOGE("JNI NewString: chars:%p,length:%lu",(void*)str,length);
    }
    appendPendingCallArg(1, formatAddress(str, "UTF-16 chars"));
    appendPendingCallArg(2, std::to_string(length));
    std::vector<uint8_t> bytes;
    if (safeReadBytes(str, std::min<uint64_t>(length * sizeof(jchar), 256), bytes, 256)) {
        appendPendingCallHexdump(str, bytes.data(), bytes.size());
    }
}

void trace_NewStringUTF(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t str = QBDI_GPR_GET(gprState, 1);
    std::string value = readJniString(str);
    if(debug)
    {
        LOGE("JNI NewStringUTF: %s",value.c_str());
    }
    appendJniStringArg(1, str, value);
}

void addJNITrace(void* target,const char* funcname,TraceCallBack callback)
{
    if(_g_jni_trace == nullptr)
    {
        LOGE("jnitrace: not init!");
        return;
    }
    auto it = _g_jni_trace->map.find((size_t)target);
    if(it != _g_jni_trace->map.end())
    {
        LOGE("jnitrace: %p has installed!",target);
        return;
    }
    auto* jni_trace_func = new TraceFunc();
    jni_trace_func->callback = callback;
    jni_trace_func->name = funcname;
    _g_jni_trace->map[(size_t)target] = jni_trace_func;
    LOGE("jnitrace: %s,%p install",funcname,target);
}

void setup_jfunc(JNIEnv * jnienv)
{
    jniEnv = jnienv;
    pJFunc = jnienv->functions;
    _g_jni_trace = new JNITraceMap();
    _g_jni_trace->map.reserve(10);
}
