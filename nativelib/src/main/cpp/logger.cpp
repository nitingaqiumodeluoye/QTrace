//
// Created by zgy on 2025/12/3.
//
#include "logger.h"
#include "TraceLogger.h"
#include "sds.h"
#include <fcntl.h>
#include "unistd.h"
#include "vm.h"
logger *_logger = nullptr;

bool initLogger(size_t function_address)
{
    deleteLogger();
    _logger = new logger();
    _logger->buf = sdsempty();
    _logger->logfile = getLogPath(LogType::QBDI_TRACE,(void*)function_address);
    _logger->lastwrite = 0;
    _logger->totallen = 0;
    _logger->fd = -1;
    if (_logger->buf == nullptr) {
        LOGE("failed to create trace log buffer");
        deleteLogger();
        return false;
    }
    if (_logger->logfile.empty()) {
        LOGE("trace log path is empty");
        deleteLogger();
        return false;
    }
    _logger->fd = open(_logger->logfile.c_str(),O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (_logger->fd < 0) {
        LOGE("open trace log failed: %s, errno: %d (%s)",
             _logger->logfile.c_str(), errno, strerror(errno));
        deleteLogger();
        return false;
    }
    sds expanded = sdsMakeRoomFor(_logger->buf, static_cast<size_t>(bufsize));
    if (expanded == nullptr) {
        LOGE("failed to allocate trace log buffer");
        deleteLogger();
        return false;
    }
    _logger->buf = expanded;
    return true;
}

void deleteLogger()
{
    if(_logger != nullptr)
    {
        sdsfree(_logger->buf);
        if (_logger->fd >= 0) close(_logger->fd);
    }
    delete _logger;
    _logger = nullptr;
}

void appendlog(const char* str)
{
    if (_logger == nullptr || _logger->buf == nullptr || str == nullptr) return;
    sds appended = sdscat(_logger->buf, str);
    if (appended != nullptr) {
        _logger->buf = appended;
    } else {
        LOGE("failed to append trace log text");
    }
}

void appendlog_n(const char* str, size_t len) {
    if (_logger == nullptr || _logger->buf == nullptr || str == nullptr || len == 0) return;
    sds appended = sdscatlen(_logger->buf, str, len);
    if (appended != nullptr) {
        _logger->buf = appended;
    } else {
        LOGE("failed to append trace log bytes");
    }
}

void appendlogendl()
{
    appendlog("\n");
}

void appendformat(const char* format,...)
{
    if (_logger == nullptr || _logger->buf == nullptr || format == nullptr) return;
    va_list ap;
    va_start(ap, format);
    sds appended = sdscatvprintf(_logger->buf,format,ap);
    va_end(ap);
    if (appended != nullptr) {
        _logger->buf = appended;
    } else {
        LOGE("failed to append formatted trace log text");
    }
}

static bool write_all(int fd, const char* buf, size_t count) {
    size_t written = 0;
    while (written < count) {
        ssize_t n = write(fd, buf + written, count - written);
        if (n < 0) {
            if (errno == EINTR) continue;   // 被信号打断,重试
            LOGE("write failed: %s", strerror(errno));
            return false;
        }
        if (n == 0) {
            LOGE("write returned 0 before buffer was fully written");
            return false;
        }
        written += n;
    }
    return true;
}

bool writelog()
{
    if (_logger == nullptr || _logger->buf == nullptr || _logger->fd < 0) return false;
    const size_t length = sdslen(_logger->buf);
    if (length == 0) return true;
    _logger->totallen = _logger->lastwrite + sdslen(_logger->buf);
    LOGE("write log:%lx,%lx,%s", _logger->lastwrite,_logger->totallen,_logger->logfile.c_str());
    /*
    std::ofstream out(_logger->logfile.c_str(), std::ios::app);
    if (!out.is_open()) {
        LOGE("Failed to create trace log file: %s", _logger->logfile.c_str());
        return ;
    }
    out.write(_logger->buf, sdslen(_logger->buf));
    out.close();
    */
    if (!write_all(_logger->fd,_logger->buf, length)) {
        return false;
    }
    _logger->lastwrite = _logger->totallen;
    sdsfree(_logger->buf);
    _logger->buf = sdsempty();
    if (_logger->buf == nullptr) {
        LOGE("failed to recreate trace log buffer after flush");
        return false;
    }
    sds expanded = sdsMakeRoomFor(_logger->buf, static_cast<size_t>(bufsize));
    if (expanded == nullptr) {
        LOGE("failed to allocate trace log buffer after flush");
        return false;
    }
    _logger->buf = expanded;
    LOGE("write log done!");
    return true;
}
