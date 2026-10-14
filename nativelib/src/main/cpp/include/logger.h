//
// Created by fang on 23-12-19.
//

#ifndef QBDIRECORDER_LOGGER_H
#define QBDIRECORDER_LOGGER_H
#include <android/log.h>
#include "sstream"
#include "fstream"
#include "sds.h"
using namespace std;
// 日志
#define LOG_TAG "QTrace"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

struct logger{
    sds buf;
    std::string logfile;
    int64_t lastwrite;
    int64_t totallen;
    int fd;
};

extern logger *_logger;

/* GumTrace 风格注解缓冲：
 * trace 侧的 libc/JNI/自定义 hook 特殊行不直接写进日志，而是先暂存到
 * 当前指令的注解区，由 vm.cpp 的 flushPending 在指令行之后写出。
 * 这样 trace-ui 才能把 call func:/argsN:/ret: 关联到对应的分支指令。 */
extern bool g_annot_mode;
void pending_annot_append(const char *str, size_t len);

void initLogger(size_t function_address);
void deleteLogger();
void writelog();
void appendlog(const char* str);
void appendlog_n(const char* str, size_t len);
void appendlogendl();
void appendformat(const char* format,...);

#endif //QBDIRECORDER_LOGGER_H
