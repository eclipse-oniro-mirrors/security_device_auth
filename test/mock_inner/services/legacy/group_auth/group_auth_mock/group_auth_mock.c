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

#include "group_auth_mock.h"
#include "compatible_auth_sub_session_util.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "json_utils.h"

static int32_t g_fillResult = HC_SUCCESS;
static int32_t g_getParamsResult = HC_SUCCESS;
static int32_t g_combineResult = HC_SUCCESS;
static bool g_callOnFinishCallback = false;

static void MockOnFinish(int64_t requestId, const CJson *authParam, const CJson *out,
    const DeviceAuthCallback *callback)
{
    (void)requestId;
    (void)authParam;
    (void)out;
    if (g_callOnFinishCallback && (callback != NULL) && (callback->onFinish != NULL)) {
        callback->onFinish(requestId, 0, NULL);
    }
}

static int32_t MockFillDeviceAuthInfo(int32_t osAccountId, const TrustedGroupEntry *entry,
    const TrustedDeviceEntry *localAuthInfo, CJson *paramsData)
{
    (void)osAccountId;
    (void)entry;
    (void)localAuthInfo;
    if (g_fillResult != HC_SUCCESS) {
        return g_fillResult;
    }
    /* Add minimal fields so subsequent code can proceed. */
    AddIntToJson(paramsData, FIELD_AUTH_FORM, AUTH_FORM_IDENTICAL_ACCOUNT);
    return HC_SUCCESS;
}

static int32_t MockGetAuthParamsVecForServer(const CJson *dataFromClient, ParamsVecForAuth *authParamsVec)
{
    (void)dataFromClient;
    if (g_getParamsResult != HC_SUCCESS) {
        return g_getParamsResult;
    }
    /* Push one entry so the caller has a candidate group to try. */
    CJson *params = CreateJson();
    if (params == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    AddIntToJson(params, FIELD_AUTH_FORM, AUTH_FORM_IDENTICAL_ACCOUNT);
    AddIntToJson(params, FIELD_GROUP_TYPE, IDENTICAL_ACCOUNT_GROUP);
    AddBoolToJson(params, FIELD_IS_CLIENT, false);
    const void *ptr = params;
    authParamsVec->pushBack(authParamsVec, &ptr);
    return HC_SUCCESS;
}

static int32_t MockCombineServerConfirmParams(const CJson *confirmationJson, CJson *dataFromClient)
{
    (void)confirmationJson;
    (void)dataFromClient;
    return g_combineResult;
}

static BaseGroupAuth g_mockUnrelatedAuth = {
    .onFinish = MockOnFinish,
    .fillDeviceAuthInfo = MockFillDeviceAuthInfo,
    .getAuthParamsVecForServer = MockGetAuthParamsVecForServer,
    .combineServerConfirmParams = MockCombineServerConfirmParams,
    .authType = ACCOUNT_UNRELATED_GROUP_AUTH_TYPE,
};

static BaseGroupAuth *MockGetGroupAuthFunc(int32_t groupAuthType)
{
    if (groupAuthType == ACCOUNT_UNRELATED_GROUP_AUTH_TYPE) {
        return &g_mockUnrelatedAuth;
    }
    /* Return NULL for ACCOUNT_RELATED_GROUP_AUTH_TYPE to avoid unsafe cast
     * to AccountRelatedGroupAuth* in GetCandidateGroups (which calls
     * getAccountCandidateGroup beyond the BaseGroupAuth vtable). */
    return NULL;
}

void RegisterMockGroupAuth(void)
{
    RegisterGroupAuth(MockGetGroupAuthFunc);
}

void ResetGroupAuthMock(void)
{
    g_fillResult = HC_SUCCESS;
    g_getParamsResult = HC_SUCCESS;
    g_combineResult = HC_SUCCESS;
    g_callOnFinishCallback = false;
}

void SetFillDeviceAuthInfoResult(int32_t ret)
{
    g_fillResult = ret;
}

void SetGetAuthParamsVecResult(int32_t ret)
{
    g_getParamsResult = ret;
}

void SetCombineServerConfirmResult(int32_t ret)
{
    g_combineResult = ret;
}

void SetOnFinishCallCallback(bool callCallback)
{
    g_callOnFinishCallback = callCallback;
}
