#include <jni.h>
#include <string>
#include <iostream>
#include <cstdio>
#include <dlfcn.h>
#include <fstream>
#include <unistd.h>
#include <pthread.h>
#include <cstring>
#include <cctype>
#include <vector>
#include "vm.h"
#include "HookUtils.h"
#include "qbdihook.h"
#include "jnitrace.h"
#include "libctrace.h"
#include "shadowhook.h"
using namespace std;

static void addHooks()
{
    /* 得物: 无自定义 hook 点, 留空; QBDI + JNI/libc trace 已覆盖 */
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

/* ===== 得物 dhw 专用配置 =====
 * 目标不在任何 so 文件里：sg.ra 的 JNI 实现在 ijiami VM 运行时解包的
 * 匿名 r-x 区（上次 dump 基址 0x76ba42e000，大小 0xb000）。
 * 定位方式：扫描 /proc/self/maps 的匿名可执行区，匹配 AES S-box 特征
 * （区+0x7174 处的 16 字节标准 AES S-box 前缀）。
 * trace_func = 0x774 = sg.ra JNI 实现（stp x26,x25 prologue,
 *   内部 GetStringUTFChars/GetArrayLength/GetByteArrayElements +
 *   b64 解码 + AES + 组装 52B 返回值）。
 */
static const uint8_t DU_SBOX_SIG[16] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,
    0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76
};
/* 偏移随会话漂移 (上次 0x7174/0x774, 本次 0x81b4/0x177f) — 全区间搜索 */
static const uint8_t DU_ENTRY_SIG[12] = {      /* 入口 12 字节校验 */
    0xfa,0x67,0xbb,0xa9,0xf8,0x5f,0x01,0xa9,0xf6,0x57,0x02,0xa9
};

static bool safeMemRead(size_t addr, void* buf, size_t len);

/* 在 maps 里找匿名可执行区中含 AES S-box 特征的, 返回区起始地址;
 * 入口偏移通过 out 参数返回 (全区间搜索, 布局随会话漂移) */
static size_t findDuAnonRegion(size_t* entryOffsetOut)
{
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;
    char* line = nullptr;
    size_t len = 0;
    size_t result = 0;
    while (getline(&line, &len, fp) != -1) {
        size_t start = 0, end = 0, off = 0;
        char perms[8] = {0};
        char path[4096] = {0};
        if (sscanf(line, "%lx-%lx %4s %lx %*s %*s %4095[^\n]",
                   &start, &end, perms, &off, path) < 4) continue;
        /* 匿名行尾部可能有空格被 [^\n] 吃进去 — 去尾部空白后判空 */
        for (char* p = path + strlen(path); p > path && isspace((unsigned char)p[-1]); --p) p[-1] = '\0';
        /* 只要可执行 + 匿名 (无路径) + 大小 16K~1M */
        /* perms 如 "r-xp": [0]=r [1]=- [2]=x [3]=p */
        if (perms[0] != 'r' || perms[2] != 'x') continue;
        if (path[0] != '\0') continue;
        size_t size = end - start;
        if (size < 0x4000 || size > 0x100000) continue;

        /* 读整个区做双特征全区间搜索 (S-box + JNI 入口) */
        std::vector<uint8_t> buf(size);
        if (!safeMemRead(start, buf.data(), size)) continue;
        /* 搜索 AES S-box 特征 */
        size_t sb = 0;
        bool foundSb = false;
        for (size_t i = 0; i + sizeof(DU_SBOX_SIG) <= size; i += 4) {
            if (memcmp(buf.data() + i, DU_SBOX_SIG, sizeof(DU_SBOX_SIG)) == 0) {
                sb = i; foundSb = true; break;
            }
        }
        if (!foundSb) continue;
        /* 搜索 sg.ra JNI 入口 12B 特征 */
        size_t ent = 0;
        bool foundEnt = false;
        for (size_t i = 0; i + sizeof(DU_ENTRY_SIG) <= size; i += 4) {
            if (memcmp(buf.data() + i, DU_ENTRY_SIG, sizeof(DU_ENTRY_SIG)) == 0) {
                ent = i; foundEnt = true; break;
            }
        }
        if (!foundEnt) continue;
        /* 入口必须在 S-box 之前 (JNI 桥在代码区, S-box 在数据区) */
        if (ent >= sb) continue;
        if (entryOffsetOut) *entryOffsetOut = ent;
        result = start;
        LOGI("du region match: base=%p size=%#zx sbox=+%#zx entry=+%#zx",
             (void*)start, size, sb, ent);
        break;
    }
    free(line);
    fclose(fp);
    return result;
}

void config()
{
    /* 目标是匿名区, libname/libpath 不用于定位 */
    libname = "du_anon";
    trace_func = 0;  /* 动态: findDuAnonRegion 扫描后覆盖 */

    //trace buffer 累计多少字节往本地写一次。设置为0表示每trace一条指令就写入本地
    setBufferSize(0x1000000);//每16M写一次

    //是否开启逐指令日志，每条指令trace都会输出在logcat中，数据量巨大，用于调试时使用。
    enableDebugInsn(false);

    //是否开启jni trace 日志，可在logcat中查看jni调用
    enable_jni_trace_debug(true);

    //是否开启libc trace 日志，可在logcat中查看libc调用
    enable_libc_trace_debug(true);

}

void init_shadowhook()
{
    shadowhook_init(SHADOWHOOK_MODE_UNIQUE, true);
    shadowhook_set_debuggable(true);
}

static bool safeMemRead(size_t addr, void* buf, size_t len)
{
    /* 通过 /proc/self/mem 读, 避免直接解引用崩;/proc/self/maps 同权限 */
    FILE* fp = fopen("/proc/self/mem", "rb");
    if (!fp) return false;
    bool ok = false;
    if (fseeko(fp, (off_t)addr, SEEK_SET) == 0)
        ok = (fread(buf, 1, len, fp) == len);
    fclose(fp);
    return ok;
}

void trace()
{
    /*trace 配置*/
    config();

    /*JNI Trace*/
    initJni();
    //添加监控的jni函数
    addJNItrace();

    /*libc Trace*/
    initLibcTrace();
    //添加监控的libc函数
    addLibctrace();

    /*自定义hook监控*/
    initHookData();
    //添加目标so的hook点位
    addHooks();

    /* 得物: 扫描匿名区找 sg.ra JNI 实现 */
    size_t entryOff = 0;
    size_t regionBase = findDuAnonRegion(&entryOff);
    trace_func = entryOff;
    if (regionBase != 0) {
        /* 重扫 maps 拿区大小 */
        FILE* fp = fopen("/proc/self/maps", "r");
        size_t regionEnd = regionBase + 0xb000;
        if (fp) {
            char* line = nullptr; size_t len = 0;
            while (getline(&line, &len, fp) != -1) {
                size_t s = 0, e = 0;
                if (sscanf(line, "%lx-%lx", &s, &e) == 2 && s == regionBase) {
                    regionEnd = e; break;
                }
            }
            free(line); fclose(fp);
        }
        LOGI("du anon region: base=%p end=%p entry=+%#zx",
             (void*)regionBase, (void*)regionEnd, trace_func);
        _g_trace_data = new g_trace_data();
        _g_trace_data->base = regionBase;
        _g_trace_data->start = regionBase;
        _g_trace_data->end = regionEnd;
        _g_trace_data->target = trace_func;
        _g_trace_data->hooktask = shadowhook_hook_func_addr((void*)(regionBase + trace_func),
                                                            (void*)(hook_and_trace_arg8),
                                                            (void**)&ori_arg8);
        if (_g_trace_data->hooktask != nullptr) {
            LOGI("sg.ra entry hook installed @ %p", (void*)(regionBase + trace_func));
        } else {
            LOGE("failed to hook sg.ra entry");
        }
    } else {
        /* 匿名区还没解包 (VM 晚解包) — 周期重试 */
        LOGI("du anon region not found yet; install loader hook + retry timer");
        /* 简单处理: 轮询线程, 每 2s 扫一次, 最多 120 次 */
        pthread_t th;
        static auto retryFn = [](void*) -> void* {
            LOGI("retry thread started");
            for (int i = 0; i < 120; i++) {
                usleep(2 * 1000 * 1000);
                size_t entryOff2 = 0;
                size_t base = findDuAnonRegion(&entryOff2);
                if (i % 5 == 0) LOGI("retry scan #%d: base=%p", i, (void*)base);
                if (base != 0) {
                    LOGI("du anon region found on retry: %p", (void*)base);
                    /* 重新走 trace 安装流程 (递归一次) */
                    /* 直接在此安装, 避免递归 */
                    FILE* fp = fopen("/proc/self/maps", "r");
                    size_t end = base + 0xb000;
                    if (fp) {
                        char* line = nullptr; size_t len = 0;
                        while (getline(&line, &len, fp) != -1) {
                            size_t s = 0, e = 0;
                            if (sscanf(line, "%lx-%lx", &s, &e) == 2 && s == base) { end = e; break; }
                        }
                        free(line); fclose(fp);
                    }
                    _g_trace_data = new g_trace_data();
                    _g_trace_data->base = base;
                    _g_trace_data->start = base;
                    _g_trace_data->end = end;
                    _g_trace_data->target = entryOff2;
                    _g_trace_data->hooktask = shadowhook_hook_func_addr((void*)(base + entryOff2),
                                                                        (void*)(hook_and_trace_arg8),
                                                                        (void**)&ori_arg8);
                    LOGI("retry hook installed: %p", _g_trace_data->hooktask);
                    break;
                }
            }
            return nullptr;
        };
        int prc = pthread_create(&th, nullptr, +[](void* arg) -> void* { return retryFn(arg); }, nullptr);
        if (prc != 0) {
            LOGE("retry pthread_create failed: %d", prc);
        } else {
            pthread_detach(th);
            LOGI("retry thread launched");
        }
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
    init_shadowhook();
    trace();
}