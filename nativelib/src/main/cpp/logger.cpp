//
// Created by zgy on 2025/12/3.
//
#include "logger.h"
#include "TraceLogger.h"
#include "sds.h"
#include <fcntl.h>
#include <cstring>
#include <cstdio>
#include "unistd.h"
#include "vm.h"
logger *_logger = nullptr;

void initLogger(size_t function_address)
{
    _logger = new logger();
    _logger->buf = sdsempty();
    _logger->logfile = getLogPath(LogType::QBDI_TRACE,(void*)function_address);
    _logger->lastwrite = 0;
    _logger->totallen = 0;
    _logger->fd = open(_logger->logfile.c_str(),O_WRONLY | O_CREAT | O_TRUNC, 0644);
}

void deleteLogger()
{
    if(_logger != nullptr)
    {
        sdsfree(_logger->buf);
        close(_logger->fd);
    }
    delete _logger;
    _logger = nullptr;
}

void appendlog(const char* str)
{
      if(_logger == nullptr || str == nullptr)
      {
          return;
      }
      if (g_annot_mode)
      {
          pending_annot_append(str, strlen(str));
          return;
      }
      _logger->buf = sdscat(_logger->buf, str);
}

void appendlog_n(const char* str, size_t len) {
    if (_logger == nullptr || str == nullptr)
        return;
    if (g_annot_mode)
    {
        pending_annot_append(str, len);
        return;
    }
    _logger->buf = sdscatlen(_logger->buf, str, len);
}

void appendlogendl()
{
    appendlog("\n");
}

void appendformat(const char* format,...)
{
    if (_logger == nullptr || format == nullptr)
    {
        return;
    }
    va_list ap;
    va_start(ap, format);
    if (g_annot_mode)
    {
        char tmp[2048];
        int n = vsnprintf(tmp, sizeof(tmp), format, ap);
        va_end(ap);
        if (n > 0)
        {
            size_t len = ((size_t)n < sizeof(tmp)) ? (size_t)n : (sizeof(tmp) - 1);
            pending_annot_append(tmp, len);
        }
        return;
    }
    _logger->buf = sdscatvprintf(_logger->buf,format,ap);
    va_end(ap);
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
        written += n;
    }
    return true;
}

void writelog()
{
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
    write_all(_logger->fd,_logger->buf, sdslen(_logger->buf));
    _logger->lastwrite = _logger->totallen;
    sdsfree(_logger->buf);
    _logger->buf = sdsempty();
    _logger->buf = sdsMakeRoomFor(_logger->buf, 2*bufsize);
    LOGE("write log done!");
}