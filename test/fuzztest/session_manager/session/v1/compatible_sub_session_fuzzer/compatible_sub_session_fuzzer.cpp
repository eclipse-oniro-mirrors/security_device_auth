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

#include "compatible_sub_session_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "compatible_auth_sub_session.h"
#include "compatible_auth_sub_session_common.h"
#include "compatible_auth_sub_session_util.h"
#include "compatible_bind_sub_session.h"
#include "compatible_bind_sub_session_common.h"
#include "compatible_bind_sub_session_util.h"
#include "compatible_sub_session.h"
#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "dev_auth_module_manager_mock.h"
#include "group_auth_data_operation_mock.h"
#include "group_data_manager_mock.h"
#include "group_operation_common_mock.h"
#include "account_task_manager_mock_control.h"
#include "hc_log.h"
#include "hc_types.h"
#include "json_utils.h"
#include "securec.h"

namespace OHOS {
namespace {

/* ===== minimal no-op callback ===== */
static bool OnTransmit(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    (void)requestId;
    (void)data;
    (void)dataLen;
    return true;
}

static void OnSessionKeyReturned(int64_t requestId, const uint8_t *sessionKey, uint32_t sessionKeyLen)
{
    (void)requestId;
    (void)sessionKey;
    (void)sessionKeyLen;
}

static void OnFinish(int64_t requestId, int operationCode, const char *authReturn)
{
    (void)requestId;
    (void)operationCode;
    (void)authReturn;
}

static void OnError(int64_t requestId, int operationCode, int errorCode, const char *errorReturn)
{
    (void)requestId;
    (void)operationCode;
    (void)errorCode;
    (void)errorReturn;
}

static char *OnBindRequest(int64_t requestId, int operationCode, const char *reqParam)
{
    (void)requestId;
    (void)operationCode;
    (void)reqParam;
    CJson *json = CreateJson();
    if (json != nullptr) {
        AddIntToJson(json, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
        AddIntToJson(json, FIELD_OS_ACCOUNT_ID, 100);
        AddStringToJson(json, FIELD_PIN_CODE, "123456");
        AddStringToJson(json, FIELD_DEVICE_ID, "MockAuthId2");
        AddStringToJson(json, FIELD_SERVICE_PKG_NAME, "MockAppId");
        char *str = PackJsonToString(json);
        FreeJson(json);
        return str;
    }
    return nullptr;
}

static DeviceAuthCallback g_callback = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnBindRequest,
};

/* ===== FDP-driven mock control ===== */

static void FuzzResetMocks(FuzzedDataProvider &fdp)
{
    if (fdp.ConsumeBool()) {
        ResetGroupOpMock();
    }
    if (fdp.ConsumeBool()) {
        ResetModuleMock();
    }
    if (fdp.ConsumeBool()) {
        ResetGaMock();
    }
    if (fdp.ConsumeBool()) {
        ResetDbMock();
    }
}

static void FuzzSetupMocks(FuzzedDataProvider &fdp)
{
    if (fdp.ConsumeBool()) {
        SetCheckGroupExistResult(fdp.ConsumeIntegral<int32_t>());
    }
    if (fdp.ConsumeBool()) {
        SetCheckPermForGroupResult(fdp.ConsumeIntegral<int32_t>());
    }
    if (fdp.ConsumeBool()) {
        SetCheckDeviceNumLimitResult(fdp.ConsumeIntegral<int32_t>());
    }
    if (fdp.ConsumeBool()) {
        SetProcessKeyPairResult(fdp.ConsumeIntegral<int32_t>());
    }
    if (fdp.ConsumeBool()) {
        SetGetTrustedDevInfoByIdResult(fdp.ConsumeIntegral<int32_t>());
    }
    if (fdp.ConsumeBool()) {
        SetGetGroupTypeFromDbResult(fdp.ConsumeIntegral<int32_t>());
    }
    if (fdp.ConsumeBool()) {
        SetAssertGroupTypeMatchResult(fdp.ConsumeIntegral<int32_t>());
    }
    if (fdp.ConsumeBool()) {
        SetIsGroupExistByGroupId(fdp.ConsumeBool());
    }
    if (fdp.ConsumeBool()) {
        SetIsUserTypeValid(fdp.ConsumeBool());
    }
    if (fdp.ConsumeBool()) {
        SetIsGroupVisibilityValid(fdp.ConsumeBool());
    }
    if (fdp.ConsumeBool()) {
        SetIsExpireTimeValid(fdp.ConsumeBool());
    }
    if (fdp.ConsumeBool()) {
        SetCreateTaskResult(fdp.ConsumeIntegral<int32_t>());
    }
    if (fdp.ConsumeBool()) {
        int32_t ret = fdp.ConsumeIntegral<int32_t>();
        int32_t status = fdp.ConsumeIntegralInRange<int32_t>(0, 5);
        SetProcessTaskResult(ret, status);
    }
    if (fdp.ConsumeBool()) {
        SetGaGetLocalDeviceInfoResult(fdp.ConsumeIntegral<int32_t>());
    }
    if (fdp.ConsumeBool()) {
        SetGaIsGroupAccessible(fdp.ConsumeBool());
    }
    if (fdp.ConsumeBool()) {
        SetQueryGroupsResult(fdp.ConsumeIntegral<int32_t>());
    }
    if (fdp.ConsumeBool()) {
        SetHasAccountPlugin(fdp.ConsumeBool());
    }
}

/* ===== FDP-driven JSON construction ===== */

static const char *g_groupId = "E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C2874C230C7C21";
static const char *g_appId = "MockAppId";
static const char *g_groupName = "MockGroup";
static const char *g_authId = "MockAuthId";
static const char *g_pinCode = "123456";
static const char *g_udid = "52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C";

static CJson *BuildRandomBindParams(FuzzedDataProvider &fdp)
{
    CJson *params = CreateJson();
    if (params == nullptr) {
        return nullptr;
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(params, FIELD_REQUEST_ID, "123");
    }
    if (fdp.ConsumeBool()) {
        AddIntToJson(params, FIELD_OPERATION_CODE, fdp.ConsumeIntegralInRange<int32_t>(0, 10));
    }
    if (fdp.ConsumeBool()) {
        AddIntToJson(params, FIELD_GROUP_OP, fdp.ConsumeIntegralInRange<int32_t>(0, 10));
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(params, FIELD_APP_ID, g_appId);
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(params, FIELD_SERVICE_PKG_NAME, g_appId);
    }
    if (fdp.ConsumeBool()) {
        AddIntToJson(params, FIELD_OS_ACCOUNT_ID, 100);
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(params, FIELD_GROUP_ID, g_groupId);
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(params, FIELD_PIN_CODE, g_pinCode);
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(params, FIELD_GROUP_NAME, g_groupName);
    }
    if (fdp.ConsumeBool()) {
        AddIntToJson(params, FIELD_GROUP_TYPE, fdp.ConsumeIntegralInRange<int32_t>(0, 512));
    }
    if (fdp.ConsumeBool()) {
        AddIntToJson(params, FIELD_USER_TYPE, fdp.ConsumeIntegralInRange<int32_t>(0, 5));
    }
    if (fdp.ConsumeBool()) {
        AddIntToJson(params, FIELD_GROUP_VISIBILITY, fdp.ConsumeIntegralInRange<int32_t>(0, 5));
    }
    if (fdp.ConsumeBool()) {
        AddIntToJson(params, FIELD_EXPIRE_TIME, fdp.ConsumeIntegral<int32_t>());
    }
    if (fdp.ConsumeBool()) {
        int64_t chId = DEFAULT_CHANNEL_ID;
        AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    }
    if (fdp.ConsumeBool()) {
        AddIntToJson(params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    }
    if (fdp.ConsumeBool()) {
        AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(params, FIELD_DEVICE_ID, g_authId);
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(params, FIELD_CONN_DEVICE_ID, g_udid);
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(params, FIELD_PEER_CONN_DEVICE_ID, g_udid);
    }
    return params;
}

static CJson *BuildRandomAuthParams(FuzzedDataProvider &fdp)
{
    CJson *params = CreateJson();
    if (params == nullptr) {
        return nullptr;
    }
    if (fdp.ConsumeBool()) {
        AddIntToJson(params, FIELD_AUTH_FORM, fdp.ConsumeIntegralInRange<int32_t>(0, 20));
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(params, FIELD_SERVICE_PKG_NAME, g_appId);
    }
    if (fdp.ConsumeBool()) {
        AddBoolToJson(params, FIELD_IS_CLIENT, fdp.ConsumeBool());
    }
    if (fdp.ConsumeBool()) {
        AddBoolToJson(params, FIELD_IS_DEVICE_LEVEL, fdp.ConsumeBool());
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(params, FIELD_REQUEST_ID, "123");
    }
    if (fdp.ConsumeBool()) {
        AddIntToJson(params, FIELD_OS_ACCOUNT_ID, 100);
    }
    if (fdp.ConsumeBool()) {
        AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(params, FIELD_GROUP_ID, g_groupId);
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(params, FIELD_PEER_CONN_DEVICE_ID, g_udid);
    }
    if (fdp.ConsumeBool()) {
        AddIntToJson(params, FIELD_KEY_LENGTH, fdp.ConsumeIntegralInRange<int32_t>(0, 2048));
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(params, FIELD_PIN_CODE, g_pinCode);
    }
    return params;
}

/* ===== FDP-driven test functions (Create + Destroy only) ===== */

static void FuzzCreateClientBind(FuzzedDataProvider &fdp)
{
    CJson *params = BuildRandomBindParams(fdp);
    if (params == nullptr) {
        return;
    }
    CompatibleBaseSubSession *session = nullptr;
    (void)CreateClientBindSubSession(params, &g_callback, &session);
    if (session != nullptr) {
        DestroyCompatibleBindSubSession(session);
    }
    FreeJson(params);
}

static void FuzzCreateServerBind(FuzzedDataProvider &fdp)
{
    CJson *params = BuildRandomBindParams(fdp);
    if (params == nullptr) {
        return;
    }
    CompatibleBaseSubSession *session = nullptr;
    (void)CreateServerBindSubSession(params, &g_callback, &session);
    if (session != nullptr) {
        DestroyCompatibleBindSubSession(session);
    }
    FreeJson(params);
}

static void FuzzCreateClientAuth(FuzzedDataProvider &fdp)
{
    CJson *params = BuildRandomAuthParams(fdp);
    if (params == nullptr) {
        return;
    }
    CompatibleBaseSubSession *session = nullptr;
    (void)CreateClientAuthSubSession(params, &g_callback, &session);
    if (session != nullptr) {
        DestroyCompatibleAuthSubSession(session);
    }
    FreeJson(params);
}

static void FuzzCreateServerAuth(FuzzedDataProvider &fdp)
{
    CJson *params = BuildRandomAuthParams(fdp);
    if (params == nullptr) {
        return;
    }
    CompatibleBaseSubSession *session = nullptr;
    (void)CreateServerAuthSubSession(params, &g_callback, &session);
    if (session != nullptr) {
        DestroyCompatibleAuthSubSession(session);
    }
    FreeJson(params);
}

using FuzzFunc = void (*)(FuzzedDataProvider &fdp);
static FuzzFunc g_fuzzFuncs[] = {
    FuzzCreateClientBind,
    FuzzCreateServerBind,
    FuzzCreateClientAuth,
    FuzzCreateServerAuth,
};
constexpr size_t FUZZ_FUNC_COUNT = sizeof(g_fuzzFuncs) / sizeof(g_fuzzFuncs[0]);

} /* namespace */

bool FuzzDoCallback(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < 1) {
        return false;
    }
    FuzzedDataProvider fdp(data, size);

    /* Step 1: randomly reset some mocks (state control) */
    FuzzResetMocks(fdp);

    /* Step 2: randomly set mock return values (error path exploration) */
    FuzzSetupMocks(fdp);

    /* Step 3: sequential calls without intermediate reset (state leakage) */
    uint32_t callCount = fdp.ConsumeIntegralInRange<uint32_t>(1, 3);
    for (uint32_t i = 0; i < callCount; i++) {
        if (fdp.remaining_bytes() < 4) {
            break;
        }
        uint32_t funcId = fdp.ConsumeIntegral<uint32_t>();
        g_fuzzFuncs[funcId % FUZZ_FUNC_COUNT](fdp);
    }

    /* Step 4: final cleanup to prevent cross-iteration state pollution */
    ResetGroupOpMock();
    ResetModuleMock();
    ResetGaMock();
    ResetDbMock();
    return true;
}

} /* namespace OHOS */

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::FuzzDoCallback(data, size);
    return 0;
}
