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

/* Controllable mock of BaseGroupAuth vtable so unit tests can drive the
 * account-related / account-unrelated group auth paths
 * (fillDeviceAuthInfo / getAuthParamsVecForServer / onFinish /
 * combineServerConfirmParams) without real group data or a real plugin. */

#ifndef GROUP_AUTH_MOCK_H
#define GROUP_AUTH_MOCK_H

#include <stdint.h>
#include "base_group_auth.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Register the mock GetGroupAuthFunc. After this call, GetGroupAuth() returns
 * the mock BaseGroupAuth instances instead of the real ones.
 * Call ResetGroupAuthMock() or DestroyDeviceAuthService() to restore. */
void RegisterMockGroupAuth(void);

/* Reset mock state to defaults (all return HC_SUCCESS, onFinish is no-op). */
void ResetGroupAuthMock(void);

/* Control the return value of fillDeviceAuthInfo for the next calls. */
void SetFillDeviceAuthInfoResult(int32_t ret);

/* Control the return value of getAuthParamsVecForServer for the next calls.
 * When ret == HC_SUCCESS, the mock pushes one CJson entry into the vector. */
void SetGetAuthParamsVecResult(int32_t ret);

/* Control the return value of combineServerConfirmParams. */
void SetCombineServerConfirmResult(int32_t ret);

/* Control whether onFinish calls the callback->onFinish. */
void SetOnFinishCallCallback(bool callCallback);

#ifdef __cplusplus
}
#endif

#endif
