/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef AUTH_CODE_IMPORT_H
#define AUTH_CODE_IMPORT_H

#include "base_cmd.h"

#define AUTH_CODE_IMPORT_CMD_TYPE 1

typedef struct {
    int32_t userType;
    const char *appId;
    const char *groupId;
    Uint8Buff authId;
    int32_t osAccountId;
} AuthCodeImportParams;

#ifdef ENABLE_AUTH_CODE_IMPORT

#ifdef __cplusplus
extern "C" {
#endif

BaseCmd *CreateAuthCodeImportCmd(const void *baseParams, bool isCaller, int32_t strategy);

#ifdef __cplusplus
}
#endif

#endif

#endif
