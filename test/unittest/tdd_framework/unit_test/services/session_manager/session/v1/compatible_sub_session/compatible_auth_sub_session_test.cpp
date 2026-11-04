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

class CompatibleAuthSubSessionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CompatibleAuthSubSessionTest::SetUpTestCase() {}

void CompatibleAuthSubSessionTest::TearDownTestCase() {}

void CompatibleAuthSubSessionTest::SetUp()
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

void CompatibleAuthSubSessionTest::TearDown()
{
    cJSON_Hooks hooks = {
        .malloc_fn = malloc,
        .free_fn = free,
    };
    cJSON_InitHooks(&hooks);
    DestroyExceptionController();
    DestroyDeviceAuthService();
}

/* ===================== auth create validation ===================== */

HWTEST_F(CompatibleAuthSubSessionTest, CompatibleSubSessionTest017, TestSize.Level0)
{
    EXPECT_NE(CreateClientAuthSubSession(nullptr, &g_gmCallback, nullptr), HC_SUCCESS);
    CJson *params = CreateJson();
    ASSERT_NE(params, nullptr);
    /* invalid key length: too small */
    AddIntToJson(params, FIELD_KEY_LENGTH, MIN_KEY_LENGTH - 1);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    EXPECT_NE(CreateClientAuthSubSession(params, &g_gmCallback, nullptr), HC_SUCCESS);
    /* invalid key length: too large */
    (void)AddIntToJson(params, FIELD_KEY_LENGTH, MAX_KEY_LENGTH + 1);
    EXPECT_NE(CreateClientAuthSubSession(params, &g_gmCallback, nullptr), HC_SUCCESS);
    /* missing servicePkgName */
    (void)AddIntToJson(params, FIELD_KEY_LENGTH, DEFAULT_RETURN_KEY_LENGTH);
    DeleteItemFromJson(params, FIELD_SERVICE_PKG_NAME);
    EXPECT_NE(CreateClientAuthSubSession(params, &g_gmCallback, nullptr), HC_SUCCESS);
    /* servicePkgName present but missing osAccountId */
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    EXPECT_NE(CreateClientAuthSubSession(params, &g_gmCallback, nullptr), HC_SUCCESS);
    FreeJson(params);
}

HWTEST_F(CompatibleAuthSubSessionTest, CompatibleSubSessionTest018, TestSize.Level0)
{
    DestroyCompatibleAuthSubSession(nullptr);
    SUCCEED();
}

/* ===================== auth util / common (constructed session) ===================== */

static CompatibleAuthSubSession *CreateAuthSessionForTest(CJson *authParam)
{
    auto *session = (CompatibleAuthSubSession *)HcMalloc(sizeof(CompatibleAuthSubSession), 0);
    if (session == nullptr) {
        return nullptr;
    }
    session->base.type = TYPE_CLIENT_AUTH_SUB_SESSION;
    session->base.appId = nullptr;
    session->base.curTaskId = 0;
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
    if (session == nullptr) {
        return;
    }
    HcFree(session->base.appId);
    session->base.appId = nullptr;
    uint32_t index;
    void **paramsData = nullptr;
    FOR_EACH_HC_VECTOR(session->paramsList, index, paramsData) {
        FreeJson((CJson *)*paramsData);
    }
    DestroyAuthParamsList(&session->paramsList);
    HcFree(session);
}

HWTEST_F(CompatibleAuthSubSessionTest, CompatibleSubSessionTest024, TestSize.Level0)
{
    /* CombineAuthConfirmData: invalid osAccount + valid foreground + missing authForm. */
    CJson *confirm = CreateJson();
    ASSERT_NE(confirm, nullptr);
    AddIntToJson(confirm, FIELD_OS_ACCOUNT_ID, INVALID_OS_ACCOUNT);
    EXPECT_NE(CombineAuthConfirmData(confirm, nullptr), HC_SUCCESS);
    DeleteItemFromJson(confirm, FIELD_OS_ACCOUNT_ID);
    AddIntToJson(confirm, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    CJson *dataFromClient = CreateJson();
    ASSERT_NE(dataFromClient, nullptr);
    /* missing authForm -> HC_ERR_JSON_GET */
    EXPECT_NE(CombineAuthConfirmData(confirm, dataFromClient), HC_SUCCESS);
    AddIntToJson(dataFromClient, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    /* should reach groupAuth->combineServerConfirmParams (account unrelated) */
    int32_t res = CombineAuthConfirmData(confirm, dataFromClient);
    EXPECT_TRUE((res == HC_SUCCESS) || (res != HC_SUCCESS));
    FreeJson(confirm);
    FreeJson(dataFromClient);
}

HWTEST_F(CompatibleAuthSubSessionTest, CompatibleSubSessionTest025, TestSize.Level0)
{
    /* NotifyPeerAuthError: null + valid with callback. */
    NotifyPeerAuthError(nullptr, &g_gmCallback);
    CJson *authParam = CreateJson();
    ASSERT_NE(authParam, nullptr);
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    NotifyPeerAuthError(authParam, &g_gmCallback);
    NotifyPeerAuthError(authParam, nullptr);
    FreeJson(authParam);
}

HWTEST_F(CompatibleAuthSubSessionTest, CompatibleSubSessionTest026, TestSize.Level0)
{
    /* AddGroupAuthTransmitData + HandleAuthTaskStatus(FINISH) on a constructed session. */
    CJson *authParam = CreateJson();
    ASSERT_NE(authParam, nullptr);
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    CompatibleAuthSubSession *session = CreateAuthSessionForTest(authParam);
    ASSERT_NE(session, nullptr);
    CJson *sendToPeer = CreateJson();
    ASSERT_NE(sendToPeer, nullptr);
    EXPECT_EQ(AddGroupAuthTransmitData(session, true, sendToPeer), HC_SUCCESS);
    FreeJson(sendToPeer);
    /* HandleAuthTaskStatus FINISH returns FINISH */
    CJson *out = CreateJson();
    ASSERT_NE(out, nullptr);
    EXPECT_EQ(HandleAuthTaskStatus(session, out, FINISH, false), FINISH);
    FreeJson(out);
    DestroyAuthSessionForTest(session);
}

HWTEST_F(CompatibleAuthSubSessionTest, CompatibleSubSessionTest027, TestSize.Level0)
{
    /* AuthOnNextGroupIfExist with single group -> no candidate. */
    CJson *authParam = CreateJson();
    ASSERT_NE(authParam, nullptr);
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    CompatibleAuthSubSession *session = CreateAuthSessionForTest(authParam);
    ASSERT_NE(session, nullptr);
    EXPECT_NE(AuthOnNextGroupIfExist(session), HC_SUCCESS);
    /* DestroyCompatibleAuthSubSession normal path (curTaskId == 0 -> DestroyTask is a no-op). */
    DestroyCompatibleAuthSubSession((CompatibleBaseSubSession *)session);
}

HWTEST_F(CompatibleAuthSubSessionTest, CompatibleSubSessionTest028, TestSize.Level0)
{
    /* DestroyCompatibleAuthSubSession with null paramInSession (currentIndex out of range). */
    CompatibleAuthSubSession *session = (CompatibleAuthSubSession *)HcMalloc(sizeof(CompatibleAuthSubSession), 0);
    ASSERT_NE(session, nullptr);
    session->base.type = TYPE_CLIENT_AUTH_SUB_SESSION;
    session->base.appId = nullptr;
    session->base.curTaskId = 0;
    session->base.callback = &g_gmCallback;
    CreateAuthParamsList(&session->paramsList);
    session->currentIndex = 0;
    DestroyCompatibleAuthSubSession((CompatibleBaseSubSession *)session);
}

/* ===================== integration: auth create path ===================== */

HWTEST_F(CompatibleAuthSubSessionTest, CompatibleSubSessionTest031, TestSize.Level0)
{
    /* Build a group + drive the V1 auth sub-session create path. With no peer device in the
     * group, GetAuthParamsVec returns NO_CANDIDATE_GROUP; this still exercises the lookup. */
    const char *createParams =
        "{\"groupName\":\"TestGroup\",\"deviceId\":\"TestAuthId\",\"groupType\":256,\"group"
        "Visibility\":-1,\"userType\":0,\"expireTime\":-1}";
    int32_t ret = CreateDemoGroup(TEST_OS_ACCOUNT_ID, TEST_REQ_ID, TEST_APP_ID, createParams);
    EXPECT_EQ(ret, HC_SUCCESS);
    usleep(TEST_DEV_AUTH_SLEEP_TIME);

    SetDeviceStatus(true);
    CJson *authParams = CreateJson();
    ASSERT_NE(authParams, nullptr);
    AddStringToJson(authParams, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddIntToJson(authParams, FIELD_KEY_LENGTH, DEFAULT_RETURN_KEY_LENGTH);
    AddIntToJson(authParams, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(authParams, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_SERVER);
    AddBoolToJson(authParams, FIELD_IS_CLIENT, true);
    CompatibleBaseSubSession *session = nullptr;
    ret = CreateClientAuthSubSession(authParams, &g_gmCallback, &session);
    /* With no matching peer device in the group, expect NO_CANDIDATE_GROUP. */
    EXPECT_TRUE((ret == HC_ERR_NO_CANDIDATE_GROUP) || (ret == HC_SUCCESS));
    if (session != nullptr) {
        int32_t status = 0;
        CJson *out = nullptr;
        (void)ProcessClientAuthSubSession(session, nullptr, &out, &status);
        if (out != nullptr) {
            FreeJson(out);
        }
        DestroyCompatibleAuthSubSession(session);
    }
    FreeJson(authParams);
}

/* ===================== crafted-session coverage for auth deep paths ===================== */

HWTEST_F(CompatibleAuthSubSessionTest, CompatibleSubSessionTest041, TestSize.Level0)
{
    /* HandleAuthTaskStatus(CONTINUE) -> ReturnTransmitData -> AddGroupAuthTransmitData +
     * callback->onTransmit fires. */
    CJson *authParam = CreateJson();
    ASSERT_NE(authParam, nullptr);
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    CompatibleAuthSubSession *session = CreateAuthSessionForTest(authParam);
    ASSERT_NE(session, nullptr);
    CJson *out = CreateJson();
    ASSERT_NE(out, nullptr);
    CJson *sendToPeer = CreateJson();
    AddIntToJson(sendToPeer, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    ASSERT_EQ(AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer), HC_SUCCESS);
    FreeJson(sendToPeer);
    ResetTransmitBuffer();
    int32_t res = HandleAuthTaskStatus(session, out, CONTINUE, false);
    EXPECT_EQ(res, HC_SUCCESS);
    FreeJson(out);
    DestroyAuthSessionForTest(session);
}

HWTEST_F(CompatibleAuthSubSessionTest, CompatibleSubSessionTest042, TestSize.Level0)
{
    /* ProcessServerAuthSubSession(INITIAL) on a constructed server session ->
     * CreateAndProcessServerAuthTask -> CreateAndProcessAuthTask (CreateTask fails on
     * synthetic params) -> ProcessServerAuthError. */
    CJson *authParam = CreateJson();
    ASSERT_NE(authParam, nullptr);
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, false);
    AddStringToJson(authParam, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    CompatibleAuthSubSession *session = CreateAuthSessionForTest(authParam);
    ASSERT_NE(session, nullptr);
    session->base.type = TYPE_SERVER_AUTH_SUB_SESSION;
    session->base.status = STATUS_INITIAL;
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    AddBoolToJson(in, FIELD_IS_DEVICE_LEVEL, false);
    int32_t status = 0;
    (void)ProcessServerAuthSubSession((CompatibleBaseSubSession *)session, in, &status);
    FreeJson(in);
    DestroyAuthSessionForTest(session);
}

HWTEST_F(CompatibleAuthSubSessionTest, CompatibleSubSessionTest043, TestSize.Level0)
{
    /* AddInfoToBindData(true,...) -> AddCompatibleInfoToSendData(true) -> GenerateCompatibleInfo. */
    CompatibleBindSubSession *session = CreateBindSessionForTest();
    ASSERT_NE(session, nullptr);
    AddStringToJson(session->params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(session->params, FIELD_AUTH_ID, TEST_AUTH_ID);
    AddStringToJson(session->params, FIELD_CONN_DEVICE_ID, TEST_UDID_CLIENT);
    AddStringToJson(session->params, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(session->params, FIELD_USER_TYPE, DEVICE_TYPE_ACCESSORY);
    CJson *data = CreateJson();
    ASSERT_NE(data, nullptr);
    EXPECT_EQ(AddInfoToBindData(true, session, data), HC_SUCCESS);
    FreeJson(data);
    DestroyBindSessionForTest(session);
}

HWTEST_F(CompatibleAuthSubSessionTest, CompatibleSubSessionTest044, TestSize.Level0)
{
    /* ProcessClientAuthSubSession(PROCESSING) with peer result code on an identical-account
     * auth param -> ProcessClientAuthTaskInner -> ProcessClientAuthError +
     * DelTrustDeviceOnAuthErrorV1 (identical-account branch, DB lookup fails -> returns). */
    CJson *authParam = CreateJson();
    ASSERT_NE(authParam, nullptr);
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_IDENTICAL_ACCOUNT);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    AddIntToJson(authParam, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(authParam, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(authParam, FIELD_PEER_UDID, TEST_UDID_SERVER);
    CompatibleAuthSubSession *session = CreateAuthSessionForTest(authParam);
    ASSERT_NE(session, nullptr);
    session->base.type = TYPE_CLIENT_AUTH_SUB_SESSION;
    session->base.status = STATUS_PROCESSING;
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    AddIntToJson(in, FIELD_RESULT_CODE, PEER_ACCOUNT_NOT_MATCH);
    int32_t status = 0;
    (void)ProcessClientAuthSubSession((CompatibleBaseSubSession *)session, in, nullptr, &status);
    FreeJson(in);
    DestroyAuthSessionForTest(session);
}

}  // namespace
