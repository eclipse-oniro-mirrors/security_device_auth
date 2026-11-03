/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "securec.h"

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
#include "group_auth_mock.h"
#include "group_data_manager_mock.h"
#include "group_operation_common_mock.h"
#include "account_task_manager_mock_control.h"
#include "hc_log.h"
#include "hc_types.h"
#include "json_utils.h"

namespace OHOS {
namespace {

static const int32_t MOCK_OS_ACCOUNT_ID = 100;
static const int32_t FUZZ_MAX_OP_CODE = 10;
static const int32_t FUZZ_MAX_GROUP_TYPE = 512;
static const int32_t FUZZ_MAX_USER_TYPE = 5;
static const int32_t FUZZ_MAX_AUTH_FORM = 20;
static const int32_t FUZZ_MAX_KEY_LENGTH = 2048;
static const int32_t MOCK_REQ_ID = 123;
static const int32_t MIN_FDP_BYTES = 4;

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
        AddIntToJson(json, FIELD_OS_ACCOUNT_ID, MOCK_OS_ACCOUNT_ID);
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

static const char *G_GROUP_ID = "E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C2874C230C7C21";
static const char *G_APP_ID = "MockAppId";
static const char *G_GROUP_NAME = "MockGroup";
static const char *G_AUTH_ID = "MockAuthId";
static const char *G_PIN_CODE = "123456";
static const char *G_UDID = "52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C";

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
}

static void FuzzSetupMocksPart2(FuzzedDataProvider &fdp)
{
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
        int32_t status = fdp.ConsumeIntegralInRange<int32_t>(0, FUZZ_MAX_USER_TYPE);
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
    if (fdp.ConsumeBool()) {
        SetGetAuthParamsVecResult(fdp.ConsumeIntegral<int32_t>());
    }
    if (fdp.ConsumeBool()) {
        SetFillDeviceAuthInfoResult(fdp.ConsumeIntegral<int32_t>());
    }
}

/* ===== FDP-driven JSON construction ===== */

static void FillBindParamsGroup2(FuzzedDataProvider &fdp, CJson *params);

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
        AddIntToJson(params, FIELD_OPERATION_CODE, fdp.ConsumeIntegralInRange<int32_t>(0, FUZZ_MAX_OP_CODE));
    }
    if (fdp.ConsumeBool()) {
        AddIntToJson(params, FIELD_GROUP_OP, fdp.ConsumeIntegralInRange<int32_t>(0, FUZZ_MAX_OP_CODE));
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(params, FIELD_APP_ID, G_APP_ID);
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(params, FIELD_SERVICE_PKG_NAME, G_APP_ID);
    }
    if (fdp.ConsumeBool()) {
        AddIntToJson(params, FIELD_OS_ACCOUNT_ID, MOCK_OS_ACCOUNT_ID);
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(params, FIELD_GROUP_ID, G_GROUP_ID);
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(params, FIELD_PIN_CODE, G_PIN_CODE);
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(params, FIELD_GROUP_NAME, G_GROUP_NAME);
    }
    FillBindParamsGroup2(fdp, params);
    return params;
}

static void FillBindParamsGroup2(FuzzedDataProvider &fdp, CJson *params)
{
    if (fdp.ConsumeBool()) {
        AddIntToJson(params, FIELD_GROUP_TYPE, fdp.ConsumeIntegralInRange<int32_t>(0, FUZZ_MAX_GROUP_TYPE));
    }
    if (fdp.ConsumeBool()) {
        AddIntToJson(params, FIELD_USER_TYPE, fdp.ConsumeIntegralInRange<int32_t>(0, FUZZ_MAX_USER_TYPE));
    }
    if (fdp.ConsumeBool()) {
        AddIntToJson(params, FIELD_GROUP_VISIBILITY, fdp.ConsumeIntegralInRange<int32_t>(0, FUZZ_MAX_USER_TYPE));
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
        AddStringToJson(params, FIELD_DEVICE_ID, G_AUTH_ID);
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(params, FIELD_CONN_DEVICE_ID, G_UDID);
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(params, FIELD_PEER_CONN_DEVICE_ID, G_UDID);
    }
}

static CJson *BuildRandomAuthParams(FuzzedDataProvider &fdp)
{
    CJson *params = CreateJson();
    if (params == nullptr) {
        return nullptr;
    }
    if (fdp.ConsumeBool()) {
        AddIntToJson(params, FIELD_AUTH_FORM, fdp.ConsumeIntegralInRange<int32_t>(0, FUZZ_MAX_AUTH_FORM));
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(params, FIELD_SERVICE_PKG_NAME, G_APP_ID);
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
        AddIntToJson(params, FIELD_OS_ACCOUNT_ID, MOCK_OS_ACCOUNT_ID);
    }
    if (fdp.ConsumeBool()) {
        AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(params, FIELD_GROUP_ID, G_GROUP_ID);
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(params, FIELD_PEER_CONN_DEVICE_ID, G_UDID);
    }
    if (fdp.ConsumeBool()) {
        AddIntToJson(params, FIELD_KEY_LENGTH, fdp.ConsumeIntegralInRange<int32_t>(0, FUZZ_MAX_KEY_LENGTH));
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(params, FIELD_PIN_CODE, G_PIN_CODE);
    }
    return params;
}

static CJson *BuildRandomProcessInput(FuzzedDataProvider &fdp)
{
    CJson *in = CreateJson();
    if (in == nullptr) {
        return nullptr;
    }
    if (fdp.ConsumeBool()) {
        AddIntToJson(in, FIELD_RESULT_CODE, fdp.ConsumeIntegral<int32_t>());
    }
    if (fdp.ConsumeBool()) {
        AddIntToJson(in, FIELD_GROUP_ERROR_MSG, fdp.ConsumeIntegral<int32_t>());
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(in, FIELD_GROUP_ID, G_GROUP_ID);
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(in, FIELD_SERVICE_PKG_NAME, G_APP_ID);
    }
    if (fdp.ConsumeBool()) {
        AddStringToJson(in, FIELD_CONN_DEVICE_ID, G_UDID);
    }
    if (fdp.ConsumeBool()) {
        AddIntToJson(in, FIELD_AUTH_FORM, fdp.ConsumeIntegralInRange<int32_t>(0, FUZZ_MAX_AUTH_FORM));
    }
    return in;
}

/* ===== FDP-driven fuzz entry functions =====
 * Each function targets a specific V1 sub-session API entry point.
 * FDP drives all inputs: JSON field presence/values, mock return values,
 * and whether to additionally call Process after Create succeeds. */

/* FuzzCreateClientBind: test CreateClientBindSubSession + optional ProcessClientBindSubSession.
 * Target: compatible_bind_sub_session.c Create path (CheckInvitePeer/CheckJoinPeer/
 *         CreateBaseBindSubSession/GenerateKeyPairIfNeeded/InitChannel/GenerateBaseBindParams)
 *         + Process path (CreateAndProcessClientBindTask/HandleBindTaskStatus).
 * Flow: FDP → BuildRandomBindParams → Create → [FDP] Process? → Destroy. */
static void FuzzCreateClientBind(FuzzedDataProvider &fdp)
{
    CJson *params = BuildRandomBindParams(fdp);
    if (params == nullptr) {
        return;
    }
    CompatibleBaseSubSession *session = nullptr;
    (void)CreateClientBindSubSession(params, &g_callback, &session);
    if (session != nullptr) {
        uint8_t action = fdp.ConsumeIntegralInRange<uint8_t>(0, 2);
        if (action == 0) {
            CJson *in = BuildRandomProcessInput(fdp);
            CJson *out = nullptr;
            int32_t status = 0;
            (void)ProcessClientBindSubSession(session, in, &out, &status);
            if (out != nullptr) {
                FreeJson(out);
            }
            FreeJson(in);
        }
        DestroyCompatibleBindSubSession(session);
    }
    FreeJson(params);
}

/* FuzzCreateServerBind: test CreateServerBindSubSession + optional ProcessServerBindSubSession.
 * Target: CreateServerBindSubSession (CheckAcceptRequest/CheckServerStatusIfNotInvite/
 *         GenerateServerBindParams) + ProcessServerBindSubSession (CreateAndProcessServerBindTask).
 * Flow: FDP → BuildRandomBindParams → Create → [FDP] Process? → Destroy. */
static void FuzzCreateServerBind(FuzzedDataProvider &fdp)
{
    CJson *params = BuildRandomBindParams(fdp);
    if (params == nullptr) {
        return;
    }
    CompatibleBaseSubSession *session = nullptr;
    (void)CreateServerBindSubSession(params, &g_callback, &session);
    if (session != nullptr) {
        uint8_t action = fdp.ConsumeIntegralInRange<uint8_t>(0, 2);
        if (action == 0) {
            CJson *in = BuildRandomProcessInput(fdp);
            int32_t status = 0;
            (void)ProcessServerBindSubSession(session, in, &status);
            FreeJson(in);
        }
        DestroyCompatibleBindSubSession(session);
    }
    FreeJson(params);
}

/* FuzzCreateClientAuth: test CreateClientAuthSubSession + optional ProcessClientAuthSubSession.
 * Target: compatible_auth_sub_session.c (CheckInputAuthParams/CreateClientAuthSubSessionInner/
 *         GetAuthParamsVec/GetCandidateGroups) + ProcessClientAuthSubSession (HandleAuthTaskStatus).
 * Flow: FDP → BuildRandomAuthParams → Create → [FDP] Process? → Destroy. */
static void FuzzCreateClientAuth(FuzzedDataProvider &fdp)
{
    CJson *params = BuildRandomAuthParams(fdp);
    if (params == nullptr) {
        return;
    }
    CompatibleBaseSubSession *session = nullptr;
    (void)CreateClientAuthSubSession(params, &g_callback, &session);
    if (session != nullptr) {
        uint8_t action = fdp.ConsumeIntegralInRange<uint8_t>(0, 2);
        if (action == 0) {
            CJson *in = BuildRandomProcessInput(fdp);
            CJson *out = nullptr;
            int32_t status = 0;
            (void)ProcessClientAuthSubSession(session, in, &out, &status);
            if (out != nullptr) {
                FreeJson(out);
            }
            FreeJson(in);
        }
        DestroyCompatibleAuthSubSession(session);
    }
    FreeJson(params);
}

/* FuzzCreateServerAuth: test CreateServerAuthSubSession + optional ProcessServerAuthSubSession.
 * Target: CreateServerAuthSubSession (GetAuthInfoForServer/GetGroupAuth vtable) +
 *         ProcessServerAuthSubSession (CreateAndProcessServerAuthTask).
 * Flow: FDP → BuildRandomAuthParams → Create → [FDP] Process? → Destroy. */
static void FuzzCreateServerAuth(FuzzedDataProvider &fdp)
{
    CJson *params = BuildRandomAuthParams(fdp);
    if (params == nullptr) {
        return;
    }
    CompatibleBaseSubSession *session = nullptr;
    (void)CreateServerAuthSubSession(params, &g_callback, &session);
    if (session != nullptr) {
        uint8_t action = fdp.ConsumeIntegralInRange<uint8_t>(0, 2);
        if (action == 0) {
            CJson *in = BuildRandomProcessInput(fdp);
            int32_t status = 0;
            (void)ProcessServerAuthSubSession(session, in, &status);
            FreeJson(in);
        }
        DestroyCompatibleAuthSubSession(session);
    }
    FreeJson(params);
}

/* FuzzDispatcher: test CreateCompatibleSubSession + ProcessCompatibleSubSession + Destroy.
 * Target: compatible_sub_session.c dispatcher switch/NULL checks (was 0% before fuzz).
 * Flow: FDP → random sessionType (0-10) → Create → Process → Destroy. */
static void FuzzDispatcher(FuzzedDataProvider &fdp)
{
    CJson *params = BuildRandomBindParams(fdp);
    if (params == nullptr) {
        return;
    }
    CompatibleBaseSubSession *session = nullptr;
    SubSessionTypeValue type = (SubSessionTypeValue)fdp.ConsumeIntegralInRange<int32_t>(0, FUZZ_MAX_OP_CODE);
    (void)CreateCompatibleSubSession(type, params, &g_callback, &session);
    if (session != nullptr) {
        CJson *in = BuildRandomProcessInput(fdp);
        CJson *out = nullptr;
        int32_t status = 0;
        (void)ProcessCompatibleSubSession(session, in, &out, &status);
        if (out != nullptr) {
            FreeJson(out);
        }
        FreeJson(in);
        DestroyCompatibleSubSession(session);
    }
    FreeJson(params);
}

/* FuzzGenerateBaseBindParams: test GenerateBaseBindParams with manual session construction.
 * Target: compatible_bind_sub_session_common.c (AddPinCode/AddProtocolExpandVal/
 *         AddGroupAndDevInfo/GenerateParamsByInput/GenerateParamsByDatabase).
 * Flow: HcMalloc session → FDP → BuildRandomBindParams → GenerateBaseBindParams → cleanup. */
static void FuzzGenerateBaseBindParams(FuzzedDataProvider &fdp)
{
    CompatibleBindSubSession *session =
        (CompatibleBindSubSession *)HcMalloc(sizeof(CompatibleBindSubSession), 0);
    if (session == nullptr) {
        return;
    }
    session->base.type = TYPE_CLIENT_BIND_SUB_SESSION;
    session->base.appId = nullptr;
    session->base.curTaskId = 0;
    session->base.status = STATUS_INITIAL;
    session->base.callback = &g_callback;
    session->opCode = fdp.ConsumeIntegralInRange<int32_t>(0, FUZZ_MAX_OP_CODE);
    session->moduleType = DAS_MODULE;
    session->reqId = MOCK_REQ_ID;
    session->osAccountId = MOCK_OS_ACCOUNT_ID;
    session->channelType = SERVICE_CHANNEL;
    session->channelId = DEFAULT_CHANNEL_ID;
    session->params = CreateJson();
    CJson *jsonParams = BuildRandomBindParams(fdp);
    if (jsonParams != nullptr) {
        int32_t isClient = fdp.ConsumeBool() ? CLIENT : SERVER;
        (void)GenerateBaseBindParams(MOCK_OS_ACCOUNT_ID, isClient, jsonParams, session);
        FreeJson(jsonParams);
    }
    if (session->params != nullptr) {
        FreeJson(session->params);
    }
    if (session->base.appId != nullptr) {
        HcFree(session->base.appId);
    }
    HcFree(session);
}

using FuzzFunc = void (*)(FuzzedDataProvider &fdp);
static FuzzFunc g_fuzzFuncs[] = {
    FuzzCreateClientBind,
    FuzzCreateServerBind,
    FuzzCreateClientAuth,
    FuzzCreateServerAuth,
    FuzzDispatcher,
    FuzzGenerateBaseBindParams,
};
constexpr size_t FUZZ_FUNC_COUNT = sizeof(g_fuzzFuncs) / sizeof(g_fuzzFuncs[0]);

} /* namespace */

bool FuzzDoCallback(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < 1) {
        return false;
    }
    static bool gMockRegistered = false;
    if (!gMockRegistered) {
        RegisterMockGroupAuth();
        gMockRegistered = true;
    }
    FuzzedDataProvider fdp(data, size);
    FuzzResetMocks(fdp);
    FuzzSetupMocks(fdp);
    FuzzSetupMocksPart2(fdp);
    uint32_t callCount = fdp.ConsumeIntegralInRange<uint32_t>(1, 3);
    for (uint32_t i = 0; i < callCount; i++) {
        if (fdp.remaining_bytes() < MIN_FDP_BYTES) {
            break;
        }
        uint32_t funcId = fdp.ConsumeIntegral<uint32_t>();
        g_fuzzFuncs[funcId % FUZZ_FUNC_COUNT](fdp);
    }
    ResetGroupOpMock();
    ResetModuleMock();
    ResetGaMock();
    ResetDbMock();
    ResetGroupAuthMock();
    return true;
}

} /* namespace OHOS */

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::FuzzDoCallback(data, size);
    return 0;
}
