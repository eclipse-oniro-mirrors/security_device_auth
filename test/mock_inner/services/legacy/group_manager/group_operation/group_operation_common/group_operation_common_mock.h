/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef GROUP_OPERATION_COMMON_MOCK_H
#define GROUP_OPERATION_COMMON_MOCK_H
#include <stdint.h>
#include <stdbool.h>
#include "device_auth_defines.h"
#ifdef __cplusplus
extern "C" {
#endif
void SetCheckGroupExistResult(int32_t ret);
void SetCheckPermForGroupResult(int32_t ret);
void SetCheckDeviceNumLimitResult(int32_t ret);
void SetProcessKeyPairResult(int32_t ret);
void SetGetTrustedDevInfoByIdResult(int32_t ret);
void SetGetGroupTypeFromDbResult(int32_t ret);
void SetAssertGroupTypeMatchResult(int32_t ret);
void SetIsGroupExistByGroupId(bool exist);
void SetIsUserTypeValid(bool valid);
void ResetGroupOpMock(void);
#ifdef __cplusplus
}
#endif
#endif
