//
// Created by zgy on 2025/10/30.
//
// JNI 调用追踪。输出对齐 GumTrace 的注解格式（trace-ui 可直接解析）：
//   call jni func: GetMethodID(0x78f4342950, 0x799ac3f209, 0x7754328330, 0x77243c0cf0)
//   args2: getBytes
//   args3: (Ljava/lang/String;)[B
//   ret: 0x6fa77db0
// 其中 `ret:` 由 vm.cpp 的 flushPending 统一补出，这里只负责 call/args。
#include <dlfcn.h>
#include "jnitrace.h"
#include "HookUtils.h"
#include "logger.h"
#include "TraceUtils.h"
#include <vector>
#include <string>
#include <cstdio>
#include <cinttypes>
#include <cstring>

const JNINativeInterface* pJFunc = nullptr;
 JNIEnv * jniEnv = nullptr;
JNITraceMap* _g_jni_trace = nullptr;
static bool debug = false;

void initJni()
{
    LOGE("Find Jni");
    typedef jint (*JNI_GetCreatedJavaVMs_t)(JavaVM**, jsize, jsize*);
    JNI_GetCreatedJavaVMs_t getCreatedVMs = (JNI_GetCreatedJavaVMs_t)dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs");//(JNI_GetCreatedJavaVMs_t)findSymbolInLibArt("libart.so","JNI_GetCreatedJavaVMs");
    JavaVM* jvm = nullptr;
    jsize count = 0;
    if((size_t)getCreatedVMs == -1)
    {
        LOGE("无法获取 JNI_GetCreatedJavaVMs 符号地址");
        return;
    }
    jint result = getCreatedVMs(&jvm, 1, &count);

    if (result != JNI_OK || count == 0) {
        LOGE("无法获取 JavaVM 实例");
        return ;
    } else{
        LOGE("get JavaVM success");
    }

    JNIEnv* env = nullptr;
    result = jvm->AttachCurrentThread((JNIEnv **) &env, nullptr);

    if (result != JNI_OK || !env) {
        LOGE("无法获取 JNIEnv 实例");
        return ;
    }
    jint jniVersion = env->GetVersion();
    LOGE("get JNIEnv success:%x",jniVersion);
    setup_jfunc(env);
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

/* ===== GumTrace 风格注解辅助 ===== */

/* ===== JNI 句柄 → 名称映射（GumTrace 的 jclass/jmethod 等价物） =====
 * trace-ui 不识别 "jclass:"/"jmethod:" 行（未识别的特殊行会被记入 consumed_seqs
 * 而隐藏），所以解析结果一律用 "argsN:" 承载：tooltip / summary / args 都能看到。
 * JNI 的返回值只能在调用返回后读到，因此映射在 jni_after_call 里建立。 */
static std::unordered_map<uint64_t, std::string> jni_classes;          // jclass → 类名
static std::unordered_map<uint64_t, std::string> jni_methods;          // jmethodID → 方法名
static std::unordered_map<uint64_t, std::string> jni_methods_classes;  // jmethodID → 类名
static std::unordered_map<uint64_t, std::string> jni_fields;           // jfieldID → 字段名
static std::unordered_map<uint64_t, std::string> jni_obj_classes;      // jobject → 类名

static const char* g_last_call_name = nullptr;

const char* jni_last_call_name() { return g_last_call_name; }
void jni_clear_last_call_name() { g_last_call_name = nullptr; }

static const char* jni_map_get(const std::unordered_map<uint64_t, std::string>& m, uint64_t key)
{
    if (key == 0) {
        return nullptr;
    }
    auto it = m.find(key);
    return (it == m.end()) ? nullptr : it->second.c_str();
}

/* 安全读取一个 C 字符串（process_vm_readv，不用裸指针解引用，避免野指针崩溃） */
static bool jni_read_cstr(uint64_t addr, char* out, size_t out_size)
{
    if (out_size == 0) {
        return false;
    }
    out[0] = '\0';
    if (addr < 0x100000000ULL) {
        return false;
    }
    std::vector<uint8_t> buf(out_size, 0);
    if (!safeReadMemory(addr, buf.data(), buf.size())) {
        return false;
    }
    size_t i = 0;
    for (; i + 1 < out_size && buf[i] != 0; ++i) {
        out[i] = (char)buf[i];
    }
    out[i] = '\0';
    return i > 0;
}

/* 调用返回后：用返回值 x0 建立句柄映射，并把解析结果写成 args0: 行。
 * args0 是空闲槽位（x0 是 JNIEnv*，从不作为参数打印），不会和真实参数冲突。 */
void jni_after_call(const char* func_name, const uint64_t* pre_args, uint64_t ret_value)
{
    if (func_name == nullptr || pre_args == nullptr) {
        return;
    }
    std::string nm = func_name;
    char buf[512];

    if (nm == "FindClass" || nm == "DefineClass") {
        if (ret_value != 0 && jni_read_cstr(pre_args[1], buf, sizeof(buf))) {
            jni_classes[ret_value] = buf;
            appendformat("args0: <jclass %s>", buf);
            appendlogendl();
        }
    } else if (nm == "GetMethodID" || nm == "GetStaticMethodID") {
        if (ret_value != 0 && jni_read_cstr(pre_args[2], buf, sizeof(buf))) {
            jni_methods[ret_value] = buf;
            const char* cls = jni_map_get(jni_classes, pre_args[1]);
            if (cls != nullptr) {
                jni_methods_classes[ret_value] = cls;
                appendformat("args0: <jmethodID %s.%s>", cls, buf);
            } else {
                appendformat("args0: <jmethodID %s>", buf);
            }
            appendlogendl();
        }
    } else if (nm == "GetFieldID" || nm == "GetStaticFieldID") {
        if (ret_value != 0 && jni_read_cstr(pre_args[2], buf, sizeof(buf))) {
            jni_fields[ret_value] = buf;
            const char* cls = jni_map_get(jni_classes, pre_args[1]);
            if (cls != nullptr) {
                appendformat("args0: <jfieldID %s.%s>", cls, buf);
            } else {
                appendformat("args0: <jfieldID %s>", buf);
            }
            appendlogendl();
        }
    } else if (nm == "GetObjectClass") {
        /* 建立 jobject → 类名（比 GumTrace 只看 obj==jclass 的启发式更准） */
        const char* cls = jni_map_get(jni_classes, ret_value);
        if (cls != nullptr && pre_args[1] != 0) {
            jni_obj_classes[pre_args[1]] = cls;
            appendformat("args0: <jclass %s>", cls);
            appendlogendl();
        }
    } else if (nm == "NewStringUTF") {
        if (ret_value != 0 && jni_read_cstr(pre_args[1], buf, sizeof(buf))) {
            appendformat("args0: <jstring \"%s\">", buf);
            appendlogendl();
        }
    }
}

/* Call*Method：把 x1(obj/jclass) 与 x2(mid) 翻译成可读名字 */
static void jni_emit_method_info(int obj_slot, uint64_t obj, int mid_slot, uint64_t mid)
{
    const char* cls = jni_map_get(jni_methods_classes, mid);
    if (cls == nullptr) cls = jni_map_get(jni_classes, obj);
    if (cls == nullptr) cls = jni_map_get(jni_obj_classes, obj);
    if (cls != nullptr) {
        appendformat("args%d: <jclass %s>", obj_slot, cls);
        appendlogendl();
    }
    const char* m = jni_map_get(jni_methods, mid);
    if (m != nullptr) {
        appendformat("args%d: <jmethod %s>", mid_slot, m);
        appendlogendl();
    }
}

/* Get/Set*Field：把 fid 翻译成字段名 */
static void jni_emit_field_info(int slot, uint64_t fid)
{
    const char* f = jni_map_get(jni_fields, fid);
    if (f != nullptr) {
        appendformat("args%d: <jfield %s>", slot, f);
        appendlogendl();
    }
}

/* call jni func: name(0x.., 0x..) */
static void jni_call_begin(const char* name, QBDI::GPRState *gprState, int n)
{
    g_last_call_name = name;
    char buf[512];
    int off = 0;
    int w = snprintf(buf + off, sizeof(buf) - off, "call jni func: %s(", name);
    if (w > 0) off += ((size_t)w < sizeof(buf) - off) ? w : (int)(sizeof(buf) - off - 1);
    for (int i = 0; i < n && off < (int)sizeof(buf) - 32; ++i) {
        w = snprintf(buf + off, sizeof(buf) - off, "%s0x%" PRIx64,
                     i ? ", " : "", (uint64_t)QBDI_GPR_GET(gprState, i));
        if (w > 0) off += ((size_t)w < sizeof(buf) - off) ? w : (int)(sizeof(buf) - off - 1);
    }
    snprintf(buf + off, sizeof(buf) - off, ")");
    appendlog(buf);
    appendlogendl();
}

/* argsN: <C 字符串> */
static void jni_arg_cstr(int idx, uint64_t addr)
{
    char buf[256];
    if (jni_read_cstr(addr, buf, sizeof(buf))) {
        appendformat("args%d: %s", idx, buf);
        appendlogendl();
    }
}

void trace_FindClass(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t classname = QBDI_GPR_GET(gprState, 1);
    jni_call_begin("FindClass", gprState, 2);
    jni_arg_cstr(1, classname);
    if(debug)
    {
        LOGE("JNI FindClass: 0x%lx", classname);
    }
}

void trace_GetStringUTFChars(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t jnienv = QBDI_GPR_GET(gprState,0);
    uint64_t jstr = QBDI_GPR_GET(gprState,1);
    uint64_t jbool = QBDI_GPR_GET(gprState,2);
    jni_call_begin("GetStringUTFChars", gprState, 3);
    const char* str = pJFunc->GetStringUTFChars((JNIEnv*)jnienv,(jstring)jstr,(jboolean*)jbool);
    if (str != nullptr) {
        appendformat("args1: %s", str);
        appendlogendl();
        pJFunc->ReleaseStringUTFChars((JNIEnv*)jnienv, (jstring)jstr, str);
    }
    if(debug)
    {
        LOGE("JNI GetStringUTFChars: 0x%lx", jstr);
    }
}

void trace_GetFieldID(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t name = QBDI_GPR_GET(gprState,2);
    uint64_t sig = QBDI_GPR_GET(gprState,3);
    jni_call_begin("GetFieldID", gprState, 4);
    jni_arg_cstr(2, name);
    jni_arg_cstr(3, sig);
    if(debug)
    {
        LOGE("JNI GetFieldID: 0x%lx,0x%lx",name,sig);
    }
}

void trace_GetByteArrayElements(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t jni = QBDI_GPR_GET(gprState,0);
    uint64_t arr = QBDI_GPR_GET(gprState,1);
    jni_call_begin("GetByteArrayElements", gprState, 3);
    if (arr != 0) {
        jsize size = pJFunc->GetArrayLength(reinterpret_cast<JNIEnv *>(jni), reinterpret_cast<jarray>(arr));
        if (size > 0) {
            // 数组内容本身不在 guest 内存里，需要通过 JNI 拷贝出来
            std::vector<jbyte> bytes((size_t)size, 0);
            pJFunc->GetByteArrayRegion(reinterpret_cast<JNIEnv *>(jni), reinterpret_cast<jbyteArray>(arr), 0, size,
                                       bytes.data());
            char pbuf[64];
            snprintf(pbuf, sizeof(pbuf), "args1: <byteArray 0x%" PRIx64 " len=0x%x>", arr, size);
            appendlog(pbuf);
            appendlogendl();
            hexdump_local_to_log((const uint8_t*)bytes.data(), (size_t)size, arr);
        }
    }
    if(debug)
    {
        LOGE("JNI GetByteArrayElements: arr=0x%lx", arr);
    }
}

void trace_GetArrayLength(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t jni = QBDI_GPR_GET(gprState,0);
    uint64_t arr = QBDI_GPR_GET(gprState,1);
    jni_call_begin("GetArrayLength", gprState, 2);
    if (arr != 0) {
        jsize size = pJFunc->GetArrayLength(reinterpret_cast<JNIEnv *>(jni), reinterpret_cast<jarray>(arr));
        appendformat("args1: <array len=0x%x>", size);
        appendlogendl();
    }
    if(debug)
    {
        LOGE("JNI GetArrayLength: 0x%lx", arr);
    }
}

void trace_GetByteArrayRegion(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t x0 = QBDI_GPR_GET(gprState,0);
    uint64_t x1 = QBDI_GPR_GET(gprState,1);
    uint64_t x2 = QBDI_GPR_GET(gprState,2);
    uint64_t len = QBDI_GPR_GET(gprState,3);
    uint64_t jbuf = QBDI_GPR_GET(gprState,4);
    jni_call_begin("GetByteArrayRegion", gprState, 5);
    std::vector<jbyte> bytes((size_t)(len > 0x1000 ? 0x1000 : len), 0);
    if (len > 0 && x1 != 0) {
        pJFunc->GetByteArrayRegion(reinterpret_cast<JNIEnv *>(x0), reinterpret_cast<jbyteArray>(x1), (jsize)x2,
                                   (jsize)bytes.size(), bytes.data());
        hexdump_local_to_log((const uint8_t*)bytes.data(), bytes.size(), x1);
    }
    if(debug)
    {
        LOGE("JNI GetByteArrayRegion: buf:%lx,%lx",jbuf,len);
    }
}

void trace_GetIntField(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t jnienv = QBDI_GPR_GET(gprState,0);
    uint64_t jobj = QBDI_GPR_GET(gprState,1);
    uint64_t jfield = QBDI_GPR_GET(gprState,2);
    jni_call_begin("GetIntField", gprState, 3);
    appendformat("args2: 0x%" PRIx64, jfield);
    appendlogendl();
    jni_emit_field_info(2, jfield);
    if(debug)
    {
        LOGE("JNI GetIntField: fieldId:0x%lx,obj:0x%lx,env:0x%lx",jfield,jobj,jnienv);
    }
}

void trace_GetStaticFieldID(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t name = QBDI_GPR_GET(gprState,2);
    uint64_t sig = QBDI_GPR_GET(gprState,3);
    jni_call_begin("GetStaticFieldID", gprState, 4);
    jni_arg_cstr(2, name);
    jni_arg_cstr(3, sig);
    if(debug)
    {
        LOGE("JNI GetStaticFieldID: 0x%lx",name);
    }
}

void trace_CallStaticObjectMethodV(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    jni_call_begin("CallStaticObjectMethodV", gprState, 3);
    jni_emit_method_info(1, QBDI_GPR_GET(gprState,1), 2, QBDI_GPR_GET(gprState,2));
    if(debug)
    {
        LOGE("JNI CallStaticObjectMethodV");
    }
}

void trace_GetStaticMethodID(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t name = QBDI_GPR_GET(gprState,2);
    uint64_t sig = QBDI_GPR_GET(gprState,3);
    jni_call_begin("GetStaticMethodID", gprState, 4);
    jni_arg_cstr(2, name);
    jni_arg_cstr(3, sig);
    if(debug)
    {
        LOGE("JNI GetStaticMethodID: 0x%lx",name);
    }
}

void trace_GetLongField(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t jfield = QBDI_GPR_GET(gprState,2);
    jni_call_begin("GetLongField", gprState, 3);
    appendformat("args2: 0x%" PRIx64, jfield);
    appendlogendl();
    jni_emit_field_info(2, jfield);
    if(debug)
    {
        LOGE("JNI GetLongField: fieldId:0x%lx",jfield);
    }
}

void trace_RegisterNatives(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t funcs = QBDI_GPR_GET(gprState,2);
    uint64_t func_num = QBDI_GPR_GET(gprState,3);
    jni_call_begin("RegisterNatives", gprState, 4);
    appendformat("args2: <%llu native methods @0x%" PRIx64 ">", (unsigned long long)func_num, funcs);
    appendlogendl();
    if(debug)
    {
        JNINativeMethod* nativeMethods = (JNINativeMethod*)funcs;
        for(uint64_t i = 0; i < func_num; i++)
        {
            LOGE("JNI RegisterNatives: %s,%s,%p",nativeMethods[i].signature,nativeMethods[i].name,
                 (void*)((size_t)nativeMethods[i].fnPtr - _g_trace_data->base));
        }
    }
}

void trace_GetMethodID(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t str = QBDI_GPR_GET(gprState, 2);
    uint64_t sig = QBDI_GPR_GET(gprState, 3);
    jni_call_begin("GetMethodID", gprState, 4);
    jni_arg_cstr(2, str);
    jni_arg_cstr(3, sig);
    if(debug)
    {
        LOGE("JNI GetMethodID: 0x%lx",str);
    }
}

void trace_NewString(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t str = QBDI_GPR_GET(gprState, 1);
    uint64_t len = QBDI_GPR_GET(gprState, 2);
    jni_call_begin("NewString", gprState, 3);
    appendformat("args1: <jchar* 0x%" PRIx64 " len=0x%" PRIx64 ">", str, len);
    appendlogendl();
    if(debug)
    {
        LOGE("JNI NewString: 0x%lx",str);
    }
}

void trace_NewStringUTF(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t str = QBDI_GPR_GET(gprState, 1);
    jni_call_begin("NewStringUTF", gprState, 2);
    jni_arg_cstr(1, str);
    if(debug)
    {
        LOGE("JNI NewStringUTF: 0x%lx",str);
    }
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
