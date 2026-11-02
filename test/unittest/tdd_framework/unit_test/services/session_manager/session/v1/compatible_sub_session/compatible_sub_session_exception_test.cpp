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

#include <cinttypes>
#include <unistd.h>
#include <gtest/gtest.h>
#include "base_group_auth.h"
#include "common_defs.h"
#include "compatible_auth_sub_session.h"
#include "compatible_auth_sub_session_common.h"
#include "compatible_auth_sub_session_util.h"
#include "compatible_bind_sub_session.h"
#include "compatible_bind_sub_session_common.h"
#include "compatible_bind_sub_session_util.h"
#include "compatible_sub_session.h"
#include "das_module_defines.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "group_auth_data_operation.h"
#include "hc_dev_info_mock.h"
#include "hc_log.h"
#include "hc_types.h"
#include "json_utils.h"
#include "securec.h"
#include "exception_controller.h"
#include "memory_mock.h"

using namespace std;
using namespace testing::ext;

namespace {
#define TEST_REQ_ID 123
#define TEST_REQ_ID2 321
#define TEST_REQ_ID3 132
#define TEST_REQ_ID4 213
#define TEST_APP_ID "TestAppId"
#define TEST_GROUP_NAME "TestGroup"
#define TEST_AUTH_ID "TestAuthId"
#define TEST_AUTH_ID2 "TestAuthId2"
#define TEST_PIN_CODE "123456"
#define TEST_SERVICE_PKG_NAME "TestAppId"
#define TEST_GROUP_ID "E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C2874C230C7C21"
#define TEST_UDID_CLIENT "5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242B3930"
#define TEST_UDID_SERVER "52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C"
#define TEST_GROUP_DATA_PATH "/data/service/el1/public/deviceauthMock"
#define TEST_HKS_MAIN_DATA_PATH "/data/service/el1/public/huks_service/tmp/+0+0+0+0"
#define TEST_DEV_AUTH_SLEEP_TIME 50000
#define TEST_DEV_AUTH_BUFFER_SIZE 128
#define TEST_TRANS_BUFFER_SIZE 4096
#define TEST_CUR_TASK_ID 1001
#define TEST_SESSION_REQ_ID 123
#define TEST_MAX_WAIT_ROUNDS 200
static const int32_t TEST_OS_ACCOUNT_ID = 100;

enum AsyncStatus {
    ASYNC_STATUS_WAITING = 0,
    ASYNC_STATUS_TRANSMIT = 1,
    ASYNC_STATUS_FINISH = 2,
    ASYNC_STATUS_ERROR = 3
};

static AsyncStatus volatile g_asyncStatus;
static uint8_t g_transmitData[TEST_TRANS_BUFFER_SIZE] = { 0 };
static uint32_t g_transmitDataLen = 0;

static bool OnTransmit(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    (void)requestId;
    if ((data == nullptr) || (dataLen == 0) || (dataLen > TEST_TRANS_BUFFER_SIZE)) {
        return false;
    }
    if (memcpy_s(g_transmitData, TEST_TRANS_BUFFER_SIZE, data, dataLen) != EOK) {
        return false;
    }
    g_transmitDataLen = dataLen;
    g_asyncStatus = ASYNC_STATUS_TRANSMIT;
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
    g_asyncStatus = ASYNC_STATUS_FINISH;
}

static void OnError(int64_t requestId, int operationCode, int errorCode, const char *errorReturn)
{
    (void)requestId;
    (void)operationCode;
    (void)errorCode;
    (void)errorReturn;
    g_asyncStatus = ASYNC_STATUS_ERROR;
}

static char *OnBindRequest(int64_t requestId, int operationCode, const char *reqParam)
{
    (void)requestId;
    (void)operationCode;
    (void)reqParam;
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(json, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(json, FIELD_DEVICE_ID, TEST_AUTH_ID2);
    /* OpenServerAuthSession reads FIELD_SERVICE_PKG_NAME as appId and
     * GetPeerUdidFromJson reads FIELD_PEER_CONN_DEVICE_ID from the onRequest
     * return value; both must be present for the server auth session to open. */
    AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddStringToJson(json, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_CLIENT);
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
}

static DeviceAuthCallback g_gmCallback = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnBindRequest,
};

static void ResetTransmitBuffer(void)
{
    (void)memset_s(g_transmitData, TEST_TRANS_BUFFER_SIZE, 0, TEST_TRANS_BUFFER_SIZE);
    g_transmitDataLen = 0;
    g_asyncStatus = ASYNC_STATUS_WAITING;
}

static void DeleteDatabase(void)
{
    (void)system("rm -rf " TEST_GROUP_DATA_PATH);
    (void)system("rm -rf " TEST_HKS_MAIN_DATA_PATH);
}

static int32_t CreateDemoGroup(int32_t osAccountId, int64_t reqId, const char *appId, const char *createParams)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    const DeviceGroupManager *gm = GetGmInstance();
    if (gm == nullptr) {
        return HC_ERROR;
    }
    int32_t ret = gm->createGroup(osAccountId, reqId, appId, createParams);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    /* createGroup is async: wait for onFinish/onError to fire. */
    int32_t wait = 0;
    while ((g_asyncStatus == ASYNC_STATUS_WAITING) && (wait < TEST_MAX_WAIT_ROUNDS)) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
        ++wait;
    }
    usleep(TEST_DEV_AUTH_SLEEP_TIME);
    return (g_asyncStatus == ASYNC_STATUS_FINISH) ? HC_SUCCESS : HC_ERROR;
}

/* Build a CompatibleBindSubSession by hand for util/common unit tests. */
static CompatibleBindSubSession *CreateBindSessionForTest(void)
{
    auto *session = (CompatibleBindSubSession *)HcMalloc(sizeof(CompatibleBindSubSession), 0);
    if (session == nullptr) {
        return nullptr;
    }
    session->base.type = TYPE_CLIENT_BIND_SUB_SESSION;
    session->base.appId = nullptr;
    session->base.curTaskId = 0;
    session->base.status = STATUS_INITIAL;
    session->base.callback = &g_gmCallback;
    session->opCode = MEMBER_INVITE;
    session->moduleType = DAS_MODULE;
    session->reqId = TEST_REQ_ID;
    session->osAccountId = TEST_OS_ACCOUNT_ID;
    session->channelType = SERVICE_CHANNEL;
    session->channelId = DEFAULT_CHANNEL_ID;
    session->params = CreateJson();
    /* AddInfoToBindData/AddRequestInfoToSendData dereference appId; pre-fill it. */
    session->base.appId = (char *)HcMalloc(HcStrlen(TEST_APP_ID) + 1, 0);
    if (session->base.appId != nullptr) {
        (void)memcpy_s(session->base.appId, HcStrlen(TEST_APP_ID) + 1, TEST_APP_ID, HcStrlen(TEST_APP_ID) + 1);
    }
    return session;
}

static void DestroyBindSessionForTest(CompatibleBindSubSession *session)
{
    if (session == nullptr) {
        return;
    }
    HcFree(session->base.appId);
    session->base.appId = nullptr;
    FreeJson(session->params);
    session->params = nullptr;
    HcFree(session);
}

static CompatibleAuthSubSession *CreateAuthSessionForTest(CJson *authParam)
{
    auto *session = (CompatibleAuthSubSession *)HcMalloc(sizeof(CompatibleAuthSubSession), 0);
    if (session == nullptr) { return nullptr; }
    session->base.type = TYPE_CLIENT_AUTH_SUB_SESSION;
    session->base.appId = nullptr;
    session->base.curTaskId = TEST_CUR_TASK_ID;
    session->base.status = STATUS_INITIAL;
    session->base.callback = &g_gmCallback;
    CreateAuthParamsList(&session->paramsList);
    session->currentIndex = 0;
    if (authParam != nullptr) {
        session->paramsList.pushBack(&session->paramsList, (const void **)&authParam);
    }
    return session;
}

static void DestroyAuthSessionForTest(CompatibleAuthSubSession *session)
{
    if (session == nullptr) { return; }
    HcFree(session->base.appId);
    session->base.appId = nullptr;
    uint32_t index;
    void **p = nullptr;
    FOR_EACH_HC_VECTOR(session->paramsList, index, p) { FreeJson((CJson *)*p); }
    DestroyAuthParamsList(&session->paramsList);
    HcFree(session);
}

static CJson *BuildClientBindParams(int64_t reqId, int32_t opCode)
{
    CJson *params = CreateJson();
    if (params == nullptr) { return nullptr; }
    char reqIdStr[128] = { 0 };
    if (sprintf_s(reqIdStr, sizeof(reqIdStr), "%" PRId64, reqId) < 0) {
        FreeJson(params);
        return nullptr;
    }
    AddStringToJson(params, FIELD_REQUEST_ID, reqIdStr);
    AddIntToJson(params, FIELD_OPERATION_CODE, opCode);
    AddStringToJson(params, FIELD_APP_ID, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddIntToJson(params, FIELD_GROUP_VISIBILITY, GROUP_VISIBILITY_PUBLIC);
    AddStringToJson(params, FIELD_DEVICE_ID, TEST_AUTH_ID);
    AddIntToJson(params, FIELD_USER_TYPE, DEVICE_TYPE_ACCESSORY);
    int64_t channelId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&channelId, sizeof(int64_t));
    AddIntToJson(params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    return params;
}

class CompatibleSubSessionExceptionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CompatibleSubSessionExceptionTest::SetUpTestCase() {}

void CompatibleSubSessionExceptionTest::TearDownTestCase() {}

void CompatibleSubSessionExceptionTest::SetUp()
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
    SetDeviceStatus(true);
    ResetTransmitBuffer();
    /* Bind callback so GM async tasks (createGroup/addMember) can report back. */
    const DeviceGroupManager *gm = GetGmInstance();
    if (gm != nullptr) {
        (void)gm->regCallback(TEST_APP_ID, &g_gmCallback);
    }
    /* Enable exception-driven malloc/cJSON failure injection for branch coverage. */
    InitExceptionController();
    cJSON_Hooks hooks = {
        .malloc_fn = MockMallocForJson,
        .free_fn = MockFree,
    };
    cJSON_InitHooks(&hooks);
}

void CompatibleSubSessionExceptionTest::TearDown()
{
    cJSON_Hooks hooks = {
        .malloc_fn = malloc,
        .free_fn = free,
    };
    cJSON_InitHooks(&hooks);
    DestroyExceptionController();
    DestroyDeviceAuthService();
}

/* ===================== error-branch coverage for common helpers ===================== */

static int32_t RunBindParamsCase(const char *pin, const char *groupId,
    const char *groupName, int groupType, int userType, int vis, int exp)
{
    CompatibleBindSubSession *session = CreateBindSessionForTest();
    if (session == nullptr) { return HC_ERR_ALLOC_MEMORY; }
    session->opCode = MEMBER_JOIN;
    CJson *jsonParams = CreateJson();
    if (pin != nullptr) { AddStringToJson(jsonParams, FIELD_PIN_CODE, pin); }
    if (groupId != nullptr) { AddStringToJson(jsonParams, FIELD_GROUP_ID, groupId); }
    if (groupName != nullptr) { AddStringToJson(jsonParams, FIELD_GROUP_NAME, groupName); }
    AddIntToJson(jsonParams, FIELD_GROUP_TYPE, groupType);
    AddIntToJson(jsonParams, FIELD_USER_TYPE, userType);
    AddIntToJson(jsonParams, FIELD_GROUP_VISIBILITY, vis);
    AddIntToJson(jsonParams, FIELD_EXPIRE_TIME, exp);
    AddIntToJson(jsonParams, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    int32_t res = GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, CLIENT, jsonParams, session);
    FreeJson(jsonParams);
    DestroyBindSessionForTest(session);
    return res;
}

HWTEST_F(CompatibleSubSessionExceptionTest, CompatibleSubSessionTest045, TestSize.Level0)
{
    /* GenerateBaseBindParams error branches via CLIENT MEMBER_JOIN. */
    EXPECT_NE(RunBindParamsCase(nullptr, TEST_GROUP_ID, TEST_GROUP_NAME,
        PEER_TO_PEER_GROUP, DEVICE_TYPE_ACCESSORY, GROUP_VISIBILITY_PUBLIC, DEFAULT_EXPIRE_TIME),
        HC_SUCCESS);
    EXPECT_NE(RunBindParamsCase(TEST_PIN_CODE, TEST_GROUP_ID, nullptr,
        PEER_TO_PEER_GROUP, DEVICE_TYPE_ACCESSORY, GROUP_VISIBILITY_PUBLIC, DEFAULT_EXPIRE_TIME),
        HC_SUCCESS);
    EXPECT_NE(RunBindParamsCase(TEST_PIN_CODE, TEST_GROUP_ID, TEST_GROUP_NAME,
        IDENTICAL_ACCOUNT_GROUP, DEVICE_TYPE_ACCESSORY, GROUP_VISIBILITY_PUBLIC, DEFAULT_EXPIRE_TIME),
        HC_SUCCESS);
    EXPECT_NE(RunBindParamsCase(TEST_PIN_CODE, TEST_GROUP_ID, TEST_GROUP_NAME,
        PEER_TO_PEER_GROUP, -100, GROUP_VISIBILITY_PUBLIC, DEFAULT_EXPIRE_TIME),
        HC_SUCCESS);
    EXPECT_NE(RunBindParamsCase(TEST_PIN_CODE, TEST_GROUP_ID, TEST_GROUP_NAME,
        PEER_TO_PEER_GROUP, DEVICE_TYPE_ACCESSORY, 999, DEFAULT_EXPIRE_TIME),
        HC_SUCCESS);
    EXPECT_NE(RunBindParamsCase(TEST_PIN_CODE, TEST_GROUP_ID, TEST_GROUP_NAME,
        PEER_TO_PEER_GROUP, DEVICE_TYPE_ACCESSORY, GROUP_VISIBILITY_PUBLIC, -999),
        HC_SUCCESS);
    EXPECT_EQ(RunBindParamsCase(TEST_PIN_CODE, TEST_GROUP_ID, TEST_GROUP_NAME,
        PEER_TO_PEER_GROUP, DEVICE_TYPE_ACCESSORY, GROUP_VISIBILITY_PUBLIC, DEFAULT_EXPIRE_TIME),
        HC_SUCCESS);
}

HWTEST_F(CompatibleSubSessionExceptionTest, CompatibleSubSessionTest046, TestSize.Level0)
{
    /* AddGroupAuthTransmitData: isClientFirst=false branch + multi-param alternative group. */
    CJson *authParam = CreateJson();
    ASSERT_NE(authParam, nullptr);
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    AddStringToJson(authParam, FIELD_SERVICE_TYPE, "altGroup");
    CJson *authParam2 = CreateJson();
    ASSERT_NE(authParam2, nullptr);
    AddIntToJson(authParam2, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam2, FIELD_IS_CLIENT, true);
    AddStringToJson(authParam2, FIELD_SERVICE_TYPE, "nextGroup");
    CompatibleAuthSubSession *session = CreateAuthSessionForTest(authParam);
    ASSERT_NE(session, nullptr);
    /* push a second param so currentIndex < size-1 -> alternative group branch runs */
    session->paramsList.pushBack(&session->paramsList, (const void **)&authParam2);
    CJson *sendToPeer = CreateJson();
    ASSERT_NE(sendToPeer, nullptr);
    EXPECT_EQ(AddGroupAuthTransmitData(session, false, sendToPeer), HC_SUCCESS);
    FreeJson(sendToPeer);
    DestroyAuthSessionForTest(session);
}

HWTEST_F(CompatibleSubSessionExceptionTest, CompatibleSubSessionTest047, TestSize.Level0)
{
    /* NotifyPeerAuthError with IDENTICAL_ACCOUNT authForm -> AddInfoToErrorData adds FIELD_STEP. */
    CJson *authParam = CreateJson();
    ASSERT_NE(authParam, nullptr);
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_IDENTICAL_ACCOUNT);
    ResetTransmitBuffer();
    NotifyPeerAuthError(authParam, &g_gmCallback);
    FreeJson(authParam);
}

HWTEST_F(CompatibleSubSessionExceptionTest, CompatibleSubSessionTest048, TestSize.Level0)
{
    /* CreateClientAuthSubSession with FIELD_GROUP_ID -> GetAuthParamsVec ->
     * GetCandidateAuthInfo(groupId specified) -> GetGroupInfoByGroupId path. */
    const char *createParams =
        "{\"groupName\":\"TestGroup\",\"deviceId\":\"TestAuthId\",\"groupType\":256,\"group"
        "Visibility\":-1,\"userType\":0,\"expireTime\":-1}";
    int32_t ret = CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, createParams);
    EXPECT_EQ(ret, HC_SUCCESS);
    SetDeviceStatus(true);
    CJson *authParams = CreateJson();
    ASSERT_NE(authParams, nullptr);
    AddStringToJson(authParams, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddIntToJson(authParams, FIELD_KEY_LENGTH, DEFAULT_RETURN_KEY_LENGTH);
    AddIntToJson(authParams, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(authParams, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(authParams, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_SERVER);
    AddBoolToJson(authParams, FIELD_IS_CLIENT, true);
    CompatibleBaseSubSession *session = nullptr;
    ret = CreateClientAuthSubSession(authParams, &g_gmCallback, &session);
    EXPECT_TRUE((ret == HC_SUCCESS) || (ret == HC_ERR_NO_CANDIDATE_GROUP));
    if (session != nullptr) {
        DestroyCompatibleAuthSubSession(session);
    }
    FreeJson(authParams);
}

HWTEST_F(CompatibleSubSessionExceptionTest, CompatibleSubSessionTest049, TestSize.Level0)
{
    /* ProcessServerBindSubSession(PROCESSING) with a peer group-error msg present ->
     * ProcessBindTaskInner -> CheckPeerStatus error branch -> InformPeerGroupErrorIfNeeded. */
    CompatibleBindSubSession *session = CreateBindSessionForTest();
    ASSERT_NE(session, nullptr);
    session->base.type = TYPE_SERVER_BIND_SUB_SESSION;
    session->base.status = STATUS_PROCESSING;
    session->opCode = MEMBER_INVITE;
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    AddIntToJson(in, FIELD_GROUP_ERROR_MSG, HC_ERR_INVALID_PARAMS);
    AddIntToJson(in, FIELD_PEER_USER_TYPE, DEVICE_TYPE_ACCESSORY);
    int32_t status = 0;
    int32_t res = ProcessServerBindSubSession((CompatibleBaseSubSession *)session, in, &status);
    EXPECT_NE(res, HC_SUCCESS);
    FreeJson(in);
    DestroyBindSessionForTest(session);
}

HWTEST_F(CompatibleSubSessionExceptionTest, CompatibleSubSessionTest050, TestSize.Level0)
{
    /* GenerateBaseBindParams(CLIENT, MEMBER_INVITE) with an existing group ->
     * IsCreateGroupNeeded(CLIENT, INVITE)=false -> GenerateParamsByDatabase ->
     * AddGroupInfoByDatabase + AddDevInfoByDatabase (reads group/device from DB). */
    const char *createParams =
        "{\"groupName\":\"TestGroup\",\"deviceId\":\"TestAuthId\",\"groupType\":256,\"group"
        "Visibility\":-1,\"userType\":0,\"expireTime\":-1}";
    int32_t ret = CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, createParams);
    EXPECT_EQ(ret, HC_SUCCESS);
    SetDeviceStatus(true);
    CompatibleBindSubSession *session = CreateBindSessionForTest();
    ASSERT_NE(session, nullptr);
    session->opCode = MEMBER_INVITE;
    CJson *jsonParams = CreateJson();
    ASSERT_NE(jsonParams, nullptr);
    AddStringToJson(jsonParams, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(jsonParams, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(jsonParams, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(jsonParams, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddIntToJson(jsonParams, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(jsonParams, FIELD_DEVICE_ID, TEST_AUTH_ID);
    AddIntToJson(jsonParams, FIELD_USER_TYPE, DEVICE_TYPE_ACCESSORY);
    ret = GenerateBaseBindParams(DEFAULT_OS_ACCOUNT, CLIENT, jsonParams, session);
    EXPECT_EQ(ret, HC_SUCCESS);
    FreeJson(jsonParams);
    DestroyBindSessionForTest(session);
}

HWTEST_F(CompatibleSubSessionExceptionTest, CompatibleSubSessionTest051, TestSize.Level0)
{
    /* ProcessClientAuthError with FIELD_SEND_TO_PEER in out -> ReturnErrorToPeerByTask
     * (AddInfoToErrorData + PackJsonToString + callback->onTransmit). */
    CJson *authParam = CreateJson();
    ASSERT_NE(authParam, nullptr);
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    CompatibleAuthSubSession *session = CreateAuthSessionForTest(authParam);
    ASSERT_NE(session, nullptr);
    CJson *out = CreateJson();
    ASSERT_NE(out, nullptr);
    CJson *sendToPeer = CreateJson();
    AddIntToJson(sendToPeer, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    ASSERT_EQ(AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer), HC_SUCCESS);
    FreeJson(sendToPeer);
    ResetTransmitBuffer();
    int32_t res = ProcessClientAuthError(session, out);
    /* Returns AuthOnNextGroupIfExist result (no next group -> HC_ERR_NO_CANDIDATE_GROUP),
     * but ReturnErrorToPeerByTask ran and fired onTransmit. */
    EXPECT_NE(res, HC_SUCCESS);
    FreeJson(out);
    DestroyAuthSessionForTest(session);
}

HWTEST_F(CompatibleSubSessionExceptionTest, CompatibleSubSessionTest052, TestSize.Level0)
{
    /* AuthOnNextGroupIfExist with 2 candidate params -> increments currentIndex,
     * CreateAndProcessAuthTask on next param (fails -> ProcessClientAuthError). */
    CJson *authParam1 = CreateJson();
    ASSERT_NE(authParam1, nullptr);
    AddIntToJson(authParam1, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(authParam1, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddBoolToJson(authParam1, FIELD_IS_CLIENT, true);
    CJson *authParam2 = CreateJson();
    ASSERT_NE(authParam2, nullptr);
    AddIntToJson(authParam2, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(authParam2, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddBoolToJson(authParam2, FIELD_IS_CLIENT, true);
    CompatibleAuthSubSession *session = CreateAuthSessionForTest(authParam1);
    ASSERT_NE(session, nullptr);
    session->paramsList.pushBack(&session->paramsList, (const void **)&authParam2);
    int32_t res = AuthOnNextGroupIfExist(session);
    EXPECT_NE(res, HC_SUCCESS);
    DestroyAuthSessionForTest(session);
}

/* ===================== exception-driven branch coverage (malloc/cJSON injection) ===================== */

HWTEST_F(CompatibleSubSessionExceptionTest, CompatibleSubSessionTest053, TestSize.Level0)
{
    /* Inject the (i+1)-th malloc/cJSON failure across CreateClientBindSubSession to
     * cover every allocation-error / JSON-create-error branch in the bind create path. */
    const char *createParams =
        "{\"groupName\":\"TestGroup\",\"deviceId\":\"TestAuthId\",\"groupType\":256,\"group"
        "Visibility\":-1,\"userType\":0,\"expireTime\":-1}";
    (void)CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, createParams);
    CJson *params = BuildClientBindParams(TEST_REQ_ID, MEMBER_INVITE);
    ASSERT_NE(params, nullptr);
    for (uint32_t i = 0; i <= 35; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        CompatibleBaseSubSession *session = nullptr;
        (void)CreateClientBindSubSession(params, &g_gmCallback, &session);
        SetControllerMode(false);
        if (session != nullptr) {
            DestroyCompatibleBindSubSession(session);
        }
    }
    FreeJson(params);
}

HWTEST_F(CompatibleSubSessionExceptionTest, CompatibleSubSessionTest054, TestSize.Level0)
{
    /* Inject malloc/cJSON failures across CreateClientAuthSubSession. */
    CJson *authParams = CreateJson();
    ASSERT_NE(authParams, nullptr);
    AddStringToJson(authParams, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddIntToJson(authParams, FIELD_KEY_LENGTH, DEFAULT_RETURN_KEY_LENGTH);
    AddIntToJson(authParams, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(authParams, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_SERVER);
    AddBoolToJson(authParams, FIELD_IS_CLIENT, true);
    for (uint32_t i = 0; i <= 25; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        CompatibleBaseSubSession *session = nullptr;
        (void)CreateClientAuthSubSession(authParams, &g_gmCallback, &session);
        SetControllerMode(false);
        if (session != nullptr) {
            DestroyCompatibleAuthSubSession(session);
        }
    }
    FreeJson(authParams);
}

HWTEST_F(CompatibleSubSessionExceptionTest, CompatibleSubSessionTest055, TestSize.Level0)
{
    /* GetDuplicatePkgName: inject malloc failure for the returnPkgName allocation. */
    CJson *params = CreateJson();
    ASSERT_NE(params, nullptr);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    for (uint32_t i = 0; i <= 3; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        char *p = GetDuplicatePkgName(params);
        SetControllerMode(false);
        HcFree(p);
    }
    FreeJson(params);
}

HWTEST_F(CompatibleSubSessionExceptionTest, CompatibleSubSessionTest056, TestSize.Level0)
{
    /* Inject malloc/cJSON failures across ProcessClientBindSubSession (PROCESSING ->
     * ProcessBindTaskInner: CreateJson(out), ProcessModule, SendBindDataToPeer, ...). */
    CompatibleBindSubSession *session = CreateBindSessionForTest();
    ASSERT_NE(session, nullptr);
    session->base.type = TYPE_CLIENT_BIND_SUB_SESSION;
    session->base.status = STATUS_PROCESSING;
    AddStringToJson(session->params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(session->params, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddStringToJson(session->params, FIELD_AUTH_ID, TEST_AUTH_ID);
    AddStringToJson(session->params, FIELD_CONN_DEVICE_ID, TEST_UDID_CLIENT);
    AddIntToJson(session->params, FIELD_USER_TYPE, DEVICE_TYPE_ACCESSORY);
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    for (uint32_t i = 0; i <= 20; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        int32_t status = 0;
        (void)ProcessClientBindSubSession((CompatibleBaseSubSession *)session, in, nullptr, &status);
        SetControllerMode(false);
    }
    FreeJson(in);
    DestroyBindSessionForTest(session);
}

HWTEST_F(CompatibleSubSessionExceptionTest, CompatibleSubSessionTest057, TestSize.Level0)
{
    /* Inject malloc/cJSON failures across ProcessClientAuthSubSession (PROCESSING ->
     * ProcessClientAuthTask: CreateJson(out), ProcessClientAuthTaskInner, ...). */
    CJson *authParam = CreateJson();
    ASSERT_NE(authParam, nullptr);
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    AddStringToJson(authParam, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    CompatibleAuthSubSession *session = CreateAuthSessionForTest(authParam);
    ASSERT_NE(session, nullptr);
    session->base.type = TYPE_CLIENT_AUTH_SUB_SESSION;
    session->base.status = STATUS_PROCESSING;
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    for (uint32_t i = 0; i <= 18; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        int32_t status = 0;
        (void)ProcessClientAuthSubSession((CompatibleBaseSubSession *)session, in, nullptr, &status);
        SetControllerMode(false);
    }
    FreeJson(in);
    DestroyAuthSessionForTest(session);
}
}  // namespace
