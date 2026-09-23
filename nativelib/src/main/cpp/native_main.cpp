#include <jni.h>
#include <string>
#include <iostream>
#include <cstdio>
#include <dlfcn.h>
#include <fstream>
#include <unistd.h>
#include "vm.h"
#include "HookUtils.h"
#include "qbdihook.h"
#include "jnitrace.h"
#include "libctrace.h"
#include "shadowhook.h"
#include "TraceUtils.h"
using namespace std;

static void addHooks()
{
    // No libtiny-specific hooks: these offsets do not apply to TrustAttestor.
}

static void addLibctrace()
{
    void * handle = dlopen("libc.so",RTLD_LAZY);
    if(handle == nullptr)
    {
        LOGE("dlopen libc fail");
        return;
    }
    addLibctrace(handle,libc_access,"access");
    addLibctrace(handle,libc_system_property_get,"__system_property_get");
    addLibctrace(handle,libc_memcpy,"memcpy");
    addLibctrace(handle,libc_pthread_create,"pthread_create");
    addLibctrace(handle,libc_fopen,"fopen");
    addLibctrace(handle,libc_lstat,"lstat");
    addLibctrace(handle,libc_stat,"stat");
    addLibctrace(handle,libc_fstatat,"fstatat");
    addLibctrace(handle,libc_execve,"execve");
    addLibctrace(handle,libc_clock_gettime,"clock_gettime");
    addLibctrace(handle,libc_strlen,"strlen");
    addLibctrace(handle,libc_memmove,"memmove");
    addLibctrace(handle,libc_memset,"memset");
    addLibctrace(handle,libc_kill,"kill");
    addLibctrace(handle,libc_abort,"abort");
    addLibctrace(handle,libc_exit,"exit");
    dlclose(handle);
}

static void addJNItrace()
{
    if (pJFunc == nullptr) {
        LOGW("skip JNI trace registration: JNI function table is unavailable");
        return;
    }
    addJNITrace((void*)pJFunc->NewStringUTF,"NewStringUTF",trace_NewStringUTF);
    addJNITrace((void*)pJFunc->GetStringUTFChars,"GetStringUTFChars",trace_GetStringUTFChars);
    addJNITrace((void*)pJFunc->NewString,"NewString",trace_NewString);
    addJNITrace((void*)pJFunc->FindClass,"FindClass",trace_FindClass);
    addJNITrace((void*)pJFunc->GetFieldID,"GetFieldID",trace_GetFieldID);
    addJNITrace((void*)pJFunc->GetMethodID,"GetMethodID",trace_GetMethodID);
    addJNITrace((void*)pJFunc->RegisterNatives,"RegisterNatives",trace_RegisterNatives);
    addJNITrace((void*)pJFunc->GetLongField,"GetLongField",trace_GetLongField);
    addJNITrace((void*)pJFunc->GetStaticMethodID,"GetStaticMethodID",trace_GetStaticMethodID);
    addJNITrace((void*)pJFunc->CallStaticObjectMethodV,"CallStaticObjectMethodV",trace_CallStaticObjectMethodV);
    addJNITrace((void*)pJFunc->GetStaticFieldID,"GetStaticFieldID",trace_GetStaticFieldID);
    addJNITrace((void*)pJFunc->GetIntField,"GetIntField",trace_GetIntField);
    addJNITrace((void*)pJFunc->GetByteArrayRegion,"GetByteArrayRegion",trace_GetByteArrayRegion);
    addJNITrace((void*)pJFunc->GetArrayLength,"GetArrayLength",trace_GetArrayLength);
    addJNITrace((void*)pJFunc->GetByteArrayElements,"GetByteArrayElements",trace_GetByteArrayElements);
}

/* trace的so的名称*/
string libname;

/* 将原始so放在手机的一个目录中，方便FQ读取,
 * FQ将通过这个so文p定位内存中目标so的位置'
 * 因为在maps中的so文件名不总是原始的so名，例如config.arm64_v8a.apk这种
 * */
const char* libdir = "/data/local/tmp/";
string libpath;
/*需要trace的函数地址*/
size_t trace_func = 0;

void config()
{
    libname = "libTrustAttestor.so";

    string localdir(libdir);
    libpath = localdir + libname;

    // TrustAttestor v1.2 (12), arm64: RegisterNatives(nativeRun).
    // ELF virtual address, relative to dlpi_addr (load bias), not a maps base.
    // mov x1,x2; mov x2,x3; b 0x1a92c0
    trace_func = 0x1A73C0;
    setTraceFilter(nullptr);

    //trace buffer 累计多少字节往本地写一次。设置为0表示每trace一条指令就写入本地
    setBufferSize(0x01000000);//每16MiB写一次

    //是否开启逐指令日志，每条指令trace都会输出在logcat中，数据量巨大，用于调试时使用。
    enableDebugInsn(false);

    //是否开启jni trace 日志，可在logcat中查看jni调用
    enable_jni_trace_debug(true);

    //是否开启libc trace 日志，可在logcat中查看libc调用
    enable_libc_trace_debug(true);

}

bool init_shadowhook()
{
    int result = shadowhook_init(SHADOWHOOK_MODE_UNIQUE, true);
    if (result != 0) {
        LOGE("shadowhook initialization failed: %d", result);
        return false;
    }
    shadowhook_set_debuggable(true);
    return true;
}

void trace()
{
    /*trace 配置*/
    config();

    /*JNI Trace*/
    if(initJni()) {
        //添加监控的jni函数
        addJNItrace();
    } else {
        LOGW("JNI trace disabled because JNIEnv initialization failed");
    }

    /*libc Trace*/
    initLibcTrace();
    //添加监控的libc函数
    addLibctrace();

    /*自定义hook监控*/
    initHookData();
    //添加目标so的hook点位
    addHooks();

    auto soinfo = getSoBaseAddress(libpath.c_str(),libname.c_str());
    if(soinfo.start != 0)
    {
        constexpr uint8_t expectedEntry[] = {
            0xe1, 0x03, 0x02, 0xaa, 0xe2, 0x03, 0x03, 0xaa,
            0xbe, 0x07, 0x00, 0x14
        };
        uint8_t entry[sizeof(expectedEntry)] = {};
        if (trace_func >= soinfo.size || sizeof(entry) > soinfo.size - trace_func) {
            LOGE("trace function offset 0x%zx is outside %s (size 0x%zx)",
                 trace_func, libname.c_str(), soinfo.size);
            return;
        }
        if (!safeReadMemory(soinfo.start + trace_func, entry, sizeof(entry)) ||
            memcmp(entry, expectedEntry, sizeof(entry)) != 0) {
            LOGE("nativeRun entry mismatch at %p; check target version and ELF load bias",
                 (void*)(soinfo.start + trace_func));
            return;
        }
        LOGI("TrustAttestorNativeBridge.nativeRun: load_bias=%p, ELF=0x%zx, entry=%p",
             (void*)soinfo.start, trace_func, (void*)(soinfo.start + trace_func));
        _g_trace_data = new g_trace_data();
        _g_trace_data->base = soinfo.start;
        _g_trace_data->start = soinfo.start;
        _g_trace_data->end = soinfo.end;
        _g_trace_data->target = trace_func;
        _g_trace_data->module_name = libname;
        _g_trace_data->hooktask = shadowhook_hook_func_addr((void*)(_g_trace_data->start + _g_trace_data->target),
                                                            (void*)(hook_and_trace_arg8),
                                                            (void**)&ori_arg8);
        if (_g_trace_data->hooktask == nullptr || ori_arg8 == nullptr) {
            LOGE("failed to install entry hook at %p",
                 (void*)(_g_trace_data->start + _g_trace_data->target));
            delete _g_trace_data;
            _g_trace_data = nullptr;
        }
    }
    else
    {
        LOGE("fail to load %s",libname.c_str());
    }
}

void test()
{
    char value[16];
    memset(value,0x10,1);
    int res =  __system_property_get("ro.secure",value);
    LOGE("ro.secure:%d,%s",res,value);
}

__unused __attribute__((constructor)) void init_main() {
    LOGE("Injected!");
    if (init_shadowhook()) trace();
}
