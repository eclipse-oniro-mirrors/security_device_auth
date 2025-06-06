/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HIDUMP_ADAPTER_H
#define HIDUMP_ADAPTER_H

#include <stdio.h>
#include "hc_string_vector.h"

#define PERFORM_DUMP_ARG "performance"

typedef void (*DumpCallBack)(int);
typedef void (*CredDumpCallBack)(int);
typedef void (*PerformanceDumpCallBack)(int, StringVector *);

#ifndef DEV_AUTH_HIVIEW_ENABLE

#define DEV_AUTH_DUMP(fd, strArgVec)
#define DEV_AUTH_REG_DUMP_FUNC(func)
#define DEV_AUTH_REG_CRED_DUMP_FUNC(func)
#define DEV_AUTH_REG_PERFORM_DUMP_FUNC(func)

#else

#define DEV_AUTH_DUMP(fd, strArgVec) DevAuthDump(fd, strArgVec)
#define DEV_AUTH_REG_DUMP_FUNC(func) RegisterDumpFunc(func)
#define DEV_AUTH_REG_CRED_DUMP_FUNC(func) RegisterCredDumpFunc(func)
#define DEV_AUTH_REG_PERFORM_DUMP_FUNC(func) RegisterPerformDumpFunc(func)

#ifdef __cplusplus
extern "C" {
#endif

void DevAuthDump(int fd, StringVector *strArgVec);

void RegisterDumpFunc(DumpCallBack func);
void RegisterCredDumpFunc(CredDumpCallBack func);
void RegisterPerformDumpFunc(PerformanceDumpCallBack func);

#ifdef __cplusplus
}
#endif

#endif

#endif