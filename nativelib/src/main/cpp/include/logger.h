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

bool initLogger(size_t function_address);
void deleteLogger();
bool writelog();
void appendlog(const char* str);
void appendlog_n(const char* str, size_t len);
void appendlogendl();
void appendformat(const char* format,...);

#endif //QBDIRECORDER_LOGGER_H
