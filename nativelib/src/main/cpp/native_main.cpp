#include <jni.h>
#include <string>
#include <iostream>
#include <cstdio>
#include <dlfcn.h>
#include <unistd.h>
#include <link.h>
#include <atomic>
#include <algorithm>
#include <cstring>
#include "vm.h"
#include "HookUtils.h"
#include "qbdihook.h"
#include "jnitrace.h"
#include "libctrace.h"
#include "shadowhook.h"
#include "TraceUtils.h"
using namespace std;

static std::atomic<bool> g_targetHookInstalled{false};
static std::atomic_flag g_initializing = ATOMIC_FLAG_INIT;

static bool isTargetPath(const char* path)
{
    return path != nullptr && (strcmp(path, "libTrustAttestor.so") == 0 ||
        (strlen(path) >= strlen("/libTrustAttestor.so") &&
         strcmp(path + strlen(path) - strlen("/libTrustAttestor.so"), "/libTrustAttestor.so") == 0));
}

static MapItemInfo targetRange(const dl_phdr_info* info)
{
    MapItemInfo range{};
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const auto& ph = info->dlpi_phdr[i];
        if (ph.p_type == PT_LOAD && (ph.p_flags & PF_X)) {
            range.size = std::max(range.size, static_cast<size_t>(ph.p_vaddr + ph.p_memsz));
        }
    }
    range.start = info->dlpi_addr;
    range.end = range.start + range.size;
    return range;
}

static void tryInstallTargetHook(const MapItemInfo& soinfo);

static int checkLoadedTarget(dl_phdr_info* info, size_t, void*)
{
    if (!isTargetPath(info->dlpi_name)) return 0;
    tryInstallTargetHook(targetRange(info));
    return 1;
}

// Hook the linker entry, preserving caller_addr. Hooking libdl's wrapper would
// change the caller used by Android's namespace selection.
using LoaderOpen = void* (*)(const char*, int, const void*);
using LoaderExt = void* (*)(const char*, int, const void*, const void*);
static LoaderOpen originalLoaderOpen = nullptr;
static LoaderExt originalLoaderExt = nullptr;
static void* loaderOpenStub = nullptr;
static void* loaderExtStub = nullptr;

static void afterLoad(const char* path, void* handle)
{
    if (!handle || g_targetHookInstalled.load()) return;
    if (isTargetPath(path)) LOGI("target loader returned: %s", path);
    // Also covers the target being a dependency of the explicitly loaded ELF.
    dl_iterate_phdr(checkLoadedTarget, nullptr);
}

static void* loaderOpen(const char* path, int flags, const void* caller)
{
    void* handle = originalLoaderOpen(path, flags, caller);
    afterLoad(path, handle);
    return handle;
}

static void* loaderExt(const char* path, int flags, const void* ext, const void* caller)
{
    void* handle = originalLoaderExt(path, flags, ext, caller);
    afterLoad(path, handle);
    return handle;
}

static void installLoaderHooks()
{
    void* linker = shadowhook_dlopen("linker64");
    if (!linker) {
        LOGE("cannot resolve linker64 for loader hooks");
        return;
    }
    void* open = shadowhook_dlsym(linker, "__loader_dlopen");
    void* ext = shadowhook_dlsym(linker, "__loader_android_dlopen_ext");
    shadowhook_dlclose(linker);
    if (open) loaderOpenStub = shadowhook_hook_func_addr(open, (void*)loaderOpen,
                                                        (void**)&originalLoaderOpen);
    if (!loaderOpenStub) LOGE("__loader_dlopen hook failed: %d", shadowhook_get_errno());
    if (ext) loaderExtStub = shadowhook_hook_func_addr(ext, (void*)loaderExt,
                                                     (void**)&originalLoaderExt);
    if (!loaderExtStub) LOGE("__loader_android_dlopen_ext hook failed: %d", shadowhook_get_errno());
    LOGI("loader hooks installed: dlopen=%p android_dlopen_ext=%p", loaderOpenStub, loaderExtStub);
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

/*需要trace的函数地址*/
size_t trace_func = 0;

void config()
{
    libname = "libTrustAttestor.so";

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

static void tryInstallTargetHook(const MapItemInfo& soinfo)
{
    if (g_targetHookInstalled.load() || g_initializing.test_and_set()) return;
    struct Reset { ~Reset() { g_initializing.clear(); } } reset;
    if (g_targetHookInstalled.load()) return;
    constexpr uint8_t expectedEntry[] = {
        0xe1, 0x03, 0x02, 0xaa, 0xe2, 0x03, 0x03, 0xaa,
        0xbe, 0x07, 0x00, 0x14
    };
    uint8_t entry[sizeof(expectedEntry)] = {};
    if (trace_func >= soinfo.size || sizeof(entry) > soinfo.size - trace_func) {
        LOGE("trace function offset 0x%zx is outside %s (size 0x%zx)", trace_func, libname.c_str(), soinfo.size);
        return;
    }
    if (!safeReadMemory(soinfo.start + trace_func, entry, sizeof(entry)) ||
        memcmp(entry, expectedEntry, sizeof(entry)) != 0) {
        LOGE("nativeRun entry mismatch at %p; check target version and ELF load bias", (void*)(soinfo.start + trace_func));
        return;
    }
    {
        if (initJni()) addJNItrace();
        else LOGW("JNI trace disabled because JNIEnv initialization failed");
        initLibcTrace();
        addLibctrace();
        initHookData();
        LOGI("TrustAttestorNativeBridge.nativeRun: load_bias=%p, ELF=0x%zx, entry=%p",
             (void*)soinfo.start, trace_func, (void*)(soinfo.start + trace_func));
        _g_trace_data = new g_trace_data();
        _g_trace_data->base = soinfo.start;
        _g_trace_data->start = soinfo.start;
        _g_trace_data->end = soinfo.end;
        _g_trace_data->target = trace_func;
        _g_trace_data->module_name = libname;
        _g_trace_data->hooktask = shadowhook_hook_func_addr((void*)(soinfo.start + trace_func),
            (void*)(hook_and_trace_arg8), (void**)&ori_arg8);
        if (_g_trace_data->hooktask == nullptr || ori_arg8 == nullptr) {
            LOGE("failed to install entry hook at %p", (void*)(soinfo.start + trace_func));
            g_targetHookInstalled.store(false);
            delete _g_trace_data;
            _g_trace_data = nullptr;
        } else {
            g_targetHookInstalled.store(true);
            LOGI("nativeRun hook installed");
        }
    }
}


void trace()
{
    config();
    // The bundled static ShadowHook omits sh_linker_init(): dl-init callbacks
    // can register successfully without any events. Use address hooks instead.
    installLoaderHooks();
    dl_iterate_phdr(checkLoadedTarget, nullptr);
    if (!g_targetHookInstalled.load()) LOGI("waiting for libTrustAttestor.so load (linker entry hooks)");
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
