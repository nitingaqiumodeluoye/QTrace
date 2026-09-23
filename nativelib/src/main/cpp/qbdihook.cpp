//
// Created by zgy on 2025/10/23.
//

#include "qbdihook.h"
#include "logger.h"
#include "HookUtils.h"
#include "jnitrace.h"
#include "TraceUtils.h"
#include <vector>

QBDIHookData*  _g_hook_data = nullptr;


void hook_0x71DD54(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    size_t input = QBDI_GPR_GET(gprState,3);
    size_t len = QBDI_GPR_GET(gprState,4);
    std::vector<uint8_t> data;
    if (!safeReadBytes(input, len, data)) {
        LOGW("base64 hook skipped unreadable input: %p, len: %zu", (void*)input, len);
        return;
    }
    char* hex = bytes_to_hex_string(reinterpret_cast<char*>(data.data()), data.size());
    const size_t base64Size = 4 * ((data.size() + 2) / 3) + 1;
    char* base64 = (char*) malloc(base64Size);
    if (hex == nullptr || base64 == nullptr) {
        free(hex);
        free(base64);
        return;
    }
    memset(base64,0,base64Size);
    base64_encode(base64,data.data(),data.size());
    LOGE("base64:src:%p,raw:%s,res:%s",(void*)input,hex,base64);
    appendlogendl();
    appendformat("base64:src:%p,raw:%s,res:%s",(void*)input,hex,base64);
    appendlogendl();
    free(hex);
    free(base64);
}

void initHookData()
{
    _g_hook_data = new QBDIHookData();
    _g_hook_data->hookMap.reserve(10);
}

void addHook(size_t addr,TraceCallBack callback)
{
    auto* func_hook = new QBDIHookFunc();
    func_hook->callback = callback;
    func_hook->ignore = nullptr;
    addQBDIHook(addr,func_hook);
}

void addHook(size_t addr,TraceCallBack callback,const size_t * ignorefrom,int ignorenum)
{
    auto* func_hook = new QBDIHookFunc();
    func_hook->callback = callback;
    auto * ignores = (size_t *)malloc(sizeof(size_t)*ignorenum);
    for(int i=0;i<ignorenum;i++)
    {
        ignores[i] = ignorefrom[i];
    }
    func_hook->ignore = ignores;
    func_hook->ignorenum = ignorenum;
    addQBDIHook(addr,func_hook);
}

void addQBDIHook(size_t addr,QBDIHookFunc* callback)
{
    if(_g_hook_data == nullptr)
    {
        LOGE("qbdi hook: not init!");
        return;
    }
    auto it = _g_hook_data->hookMap.find(addr);
    if(it != _g_hook_data->hookMap.end())
    {
        LOGE("qbdi hook: %p has installed!",(void*)addr);
        return;
    }
    _g_hook_data->hookMap[addr] = callback;
    LOGE("qbdi hook: %p install",(void*)addr);
}
