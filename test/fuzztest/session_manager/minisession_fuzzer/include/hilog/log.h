/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Local stub of hilog/log.h for the mini_session_fuzzer. The fuzzer links
   without libhilog (whose source recompilation trips the
   -fsanitize-minimal-runtime vs -fsanitize=fuzzer-no-link conflict in this
   build env); HiLogPrint is defined as a no-op in mini_session_fuzzer.cpp.
   This stub mirrors the minimal surface that hc_log.h/c pull in via
   #include "hilog/log.h" (LogType/LogLevel enums + HILOG_* macros), so
   the device_auth LOGE/LOGI/LOGD expand to the no-op HiLogPrint and the
   LightSession logic is still exercised. */

#ifndef MINI_SESSION_FUZZER_HILOG_LOG_H
#define MINI_SESSION_FUZZER_HILOG_LOG_H

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef LOG_DOMAIN
#define LOG_DOMAIN 0
#endif

#ifndef LOG_TAG
#define LOG_TAG NULL
#endif

typedef enum {
    LOG_TYPE_MIN = 0,
    LOG_APP = 0,
    LOG_INIT = 1,
    LOG_CORE = 3,
    LOG_KMSG = 4,
    LOG_TYPE_MAX
} LogType;

typedef enum {
    LOG_LEVEL_MIN = 0,
    LOG_DEBUG = 3,
    LOG_INFO = 4,
    LOG_WARN = 5,
    LOG_ERROR = 6,
    LOG_FATAL = 7,
    LOG_LEVEL_MAX
} LogLevel;

int HiLogPrint(LogType type, LogLevel level, unsigned int domain, const char *tag, const char *fmt, ...);

#define HILOG_IMPL(type, level, domain, tag, ...) HiLogPrint(type, level, domain, tag, ##__VA_ARGS__)
#define HILOG_DEBUG(type, ...) ((void)HILOG_IMPL((type), LOG_DEBUG, LOG_DOMAIN, LOG_TAG, __VA_ARGS__))
#define HILOG_INFO(type, ...) ((void)HILOG_IMPL((type), LOG_INFO, LOG_DOMAIN, LOG_TAG, __VA_ARGS__))
#define HILOG_WARN(type, ...) ((void)HILOG_IMPL((type), LOG_WARN, LOG_DOMAIN, LOG_TAG, __VA_ARGS__))
#define HILOG_ERROR(type, ...) ((void)HILOG_IMPL((type), LOG_ERROR, LOG_DOMAIN, LOG_TAG, __VA_ARGS__))
#define HILOG_FATAL(type, ...) ((void)HILOG_IMPL((type), LOG_FATAL, LOG_DOMAIN, LOG_TAG, __VA_ARGS__))

#ifdef __cplusplus
}
#endif

#endif
