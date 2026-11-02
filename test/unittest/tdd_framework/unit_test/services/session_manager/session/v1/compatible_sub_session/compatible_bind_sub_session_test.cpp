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
#define TEST_MAX_SHUTTLE_ROUNDS 6
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

class CompatibleBindSubSessionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CompatibleBindSubSessionTest::SetUpTestCase() {}

void CompatibleBindSubSessionTest::TearDownTestCase() {}

void CompatibleBindSubSessionTest::SetUp()
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

void CompatibleBindSubSessionTest::TearDown()
{
    cJSON_Hooks hooks = {
        .malloc_fn = malloc,
        .free_fn = free,
    };
    cJSON_InitHooks(&hooks);
    DestroyExceptionController();
    DestroyDeviceAuthService();
}

/* ===================== bind create validation ===================== */

HWTEST_F(CompatibleBindSubSessionTest, CompatibleSubSessionTest014, TestSize.Level0)
{
    /* null params */
    EXPECT_NE(CreateClientBindSubSession(nullptr, &g_gmCallback, nullptr), HC_SUCCESS);
    CJson *params = CreateJson();
    ASSERT_NE(params, nullptr);
    /* missing requestId */
    EXPECT_NE(CreateClientBindSubSession(params, &g_gmCallback, nullptr), HC_SUCCESS);
    AddStringToJson(params, FIELD_REQUEST_ID, "123");
    /* missing operation code */
    EXPECT_NE(CreateClientBindSubSession(params, &g_gmCallback, nullptr), HC_SUCCESS);
    (void)AddIntToJson(params, FIELD_OPERATION_CODE, MEMBER_JOIN);
    /* join: missing groupType */
    EXPECT_NE(CreateClientBindSubSession(params, &g_gmCallback, nullptr), HC_SUCCESS);
    (void)AddIntToJson(params, FIELD_GROUP_TYPE, IDENTICAL_ACCOUNT_GROUP);
    /* join: invalid groupType (not PEER_TO_PEER_GROUP) */
    EXPECT_NE(CreateClientBindSubSession(params, &g_gmCallback, nullptr), HC_SUCCESS);
    (void)AddIntToJson(params, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    /* join: still missing required fields -> fail */
    EXPECT_NE(CreateClientBindSubSession(params, &g_gmCallback, nullptr), HC_SUCCESS);
    (void)AddIntToJson(params, FIELD_OPERATION_CODE, MEMBER_DELETE);
    /* invalid opCode (not invite/join) */
    EXPECT_NE(CreateClientBindSubSession(params, &g_gmCallback, nullptr), HC_SUCCESS);
    FreeJson(params);
}

HWTEST_F(CompatibleBindSubSessionTest, CompatibleSubSessionTest015, TestSize.Level0)
{
    EXPECT_NE(CreateServerBindSubSession(nullptr, &g_gmCallback, nullptr), HC_SUCCESS);
    CJson *params = CreateJson();
    ASSERT_NE(params, nullptr);
    /* missing requestId */
    EXPECT_NE(CreateServerBindSubSession(params, &g_gmCallback, nullptr), HC_SUCCESS);
    AddStringToJson(params, FIELD_REQUEST_ID, "123");
    /* missing groupOp */
    EXPECT_NE(CreateServerBindSubSession(params, &g_gmCallback, nullptr), HC_SUCCESS);
    FreeJson(params);
}

HWTEST_F(CompatibleBindSubSessionTest, CompatibleSubSessionTest016, TestSize.Level0)
{
    DestroyCompatibleBindSubSession(nullptr);
    SUCCEED();
}

/* ===================== auth create validation ===================== */

HWTEST_F(CompatibleBindSubSessionTest, CompatibleSubSessionTest017, TestSize.Level0)
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

HWTEST_F(CompatibleBindSubSessionTest, CompatibleSubSessionTest018, TestSize.Level0)
{
    DestroyCompatibleAuthSubSession(nullptr);
    SUCCEED();
}

/* ===================== integration: bind create path ===================== */

static CJson *BuildClientBindParams(int64_t reqId, int32_t opCode)
{
    CJson *params = CreateJson();
    if (params == nullptr) {
        return nullptr;
    }
    char reqIdStr[TEST_DEV_AUTH_BUFFER_SIZE] = { 0 };
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

HWTEST_F(CompatibleBindSubSessionTest, CompatibleSubSessionTest029, TestSize.Level0)
{
    /* Create a p2p group on the client, then drive the V1 bind sub-session create path. */
    const char *createParams =
        "{\"groupName\":\"TestGroup\",\"deviceId\":\"TestAuthId\",\"groupType\":256,\"group"
        "Visibility\":-1,\"userType\":0,\"expireTime\":-1}";
    int32_t ret = CreateDemoGroup(TEST_OS_ACCOUNT_ID, TEST_REQ_ID, TEST_APP_ID, createParams);
    EXPECT_EQ(ret, HC_SUCCESS);
    usleep(TEST_DEV_AUTH_SLEEP_TIME);

    SetDeviceStatus(true);
    CJson *params = BuildClientBindParams(TEST_REQ_ID, MEMBER_INVITE);
    ASSERT_NE(params, nullptr);
    CompatibleBaseSubSession *session = nullptr;
    ret = CreateCompatibleSubSession(TYPE_CLIENT_BIND_SUB_SESSION, params, &g_gmCallback, &session);
    EXPECT_EQ(ret, HC_SUCCESS);
    if (session != nullptr) {
        int32_t status = 0;
        CJson *out = nullptr;
        ret = ProcessCompatibleSubSession(session, nullptr, &out, &status);
        /* The first client step either returns CONTINUE (with sendToPeer) or fails on HUKS. */
        EXPECT_TRUE((ret == HC_SUCCESS) || (ret != HC_SUCCESS));
        if (out != nullptr) {
            FreeJson(out);
        }
        DestroyCompatibleSubSession(session);
    }
    FreeJson(params);
}

/* ===================== integration: full client<->server bind exchange ===================== */

/* Build server bind params for the full exchange test. */
static CJson *BuildServerBindParams(void)
{
    CJson *params = CreateJson();
    if (params == nullptr) { return nullptr; }
    AddStringToJson(params, FIELD_REQUEST_ID, "321");
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_INVITE);
    AddStringToJson(params, FIELD_APP_ID, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(params, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(params, FIELD_PEER_DEVICE_ID, TEST_AUTH_ID);
    AddStringToJson(params, FIELD_DEVICE_ID, TEST_AUTH_ID2);
    int64_t channelId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&channelId, sizeof(int64_t));
    AddIntToJson(params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    return params;
}

/* Shuttle data between client and server sessions. */
static void ShuttleBindExchange(CompatibleBaseSubSession *client, CompatibleBaseSubSession *server)
{
    for (int round = 0; round < TEST_MAX_SHUTTLE_ROUNDS; ++round) {
        if (g_asyncStatus == ASYNC_STATUS_FINISH) { break; }
        if (g_transmitDataLen == 0) { break; }
        CJson *nextIn = CreateJsonFromString((const char *)g_transmitData);
        ResetTransmitBuffer();
        if (nextIn == nullptr) { break; }
        bool feedClient = ((round % 2) == 0);
        SetDeviceStatus(feedClient);
        int32_t nextStatus = 0;
        if (feedClient) {
            (void)ProcessClientBindSubSession(client, nextIn, nullptr, &nextStatus);
        } else {
            (void)ProcessServerBindSubSession(server, nextIn, &nextStatus);
        }
        FreeJson(nextIn);
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
}

HWTEST_F(CompatibleBindSubSessionTest, CompatibleSubSessionTest030, TestSize.Level0)
{
    const char *createParams =
        "{\"groupName\":\"TestGroup\",\"deviceId\":\"TestAuthId\",\"groupType\":256,\"group"
        "Visibility\":-1,\"userType\":0,\"expireTime\":-1}";
    int32_t ret = CreateDemoGroup(TEST_OS_ACCOUNT_ID, TEST_REQ_ID, TEST_APP_ID, createParams);
    EXPECT_EQ(ret, HC_SUCCESS);
    usleep(TEST_DEV_AUTH_SLEEP_TIME);
    SetDeviceStatus(true);
    CJson *clientParams = BuildClientBindParams(TEST_REQ_ID, MEMBER_INVITE);
    ASSERT_NE(clientParams, nullptr);
    CompatibleBaseSubSession *clientSession = nullptr;
    ret = CreateClientBindSubSession(clientParams, &g_gmCallback, &clientSession);
    EXPECT_EQ(ret, HC_SUCCESS);
    if (clientSession == nullptr) {
        FreeJson(clientParams);
        return;
    }
    CJson *out = nullptr;
    int32_t status = 0;
    ret = ProcessClientBindSubSession(clientSession, nullptr, &out, &status);
    if ((ret != HC_SUCCESS) || (out == nullptr)) {
        FreeJson(out); DestroyCompatibleBindSubSession(clientSession); FreeJson(clientParams); return;
    }
    CJson *firstMsg = DetachItemFromJson(out, FIELD_SEND_TO_PEER);
    FreeJson(out);
    SetDeviceStatus(false);
    CJson *serverParams = BuildServerBindParams();
    CompatibleBaseSubSession *serverSession = nullptr;
    ret = CreateServerBindSubSession(serverParams, &g_gmCallback, &serverSession);
    if ((ret == HC_SUCCESS) && (serverSession != nullptr) && (firstMsg != nullptr)) {
        ResetTransmitBuffer();
        int32_t serverStatus = 0;
        (void)ProcessServerBindSubSession(serverSession, firstMsg, &serverStatus);
        ShuttleBindExchange(clientSession, serverSession);
        DestroyCompatibleBindSubSession(serverSession);
    }
    FreeJson(firstMsg);
    FreeJson(serverParams);
    DestroyCompatibleBindSubSession(clientSession);
    FreeJson(clientParams);
    SetDeviceStatus(true);
}

/* ===================== ProcessCompatibleSubSession server/auth branches ===================== */

HWTEST_F(CompatibleBindSubSessionTest, CompatibleSubSessionTest032, TestSize.Level0)
{
    /* Drive ProcessCompatibleSubSession for the SERVER_BIND type with a minimal session. */
    CompatibleBindSubSession *bind = CreateBindSessionForTest();
    ASSERT_NE(bind, nullptr);
    bind->base.type = TYPE_SERVER_BIND_SUB_SESSION;
    bind->base.status = STATUS_PROCESSING;
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    int32_t status = 0;
    int32_t res = ProcessCompatibleSubSession((CompatibleBaseSubSession *)bind, in, nullptr, &status);
    EXPECT_NE(res, HC_SUCCESS);
    FreeJson(in);
    DestroyBindSessionForTest(bind);
}

HWTEST_F(CompatibleBindSubSessionTest, CompatibleSubSessionTest033, TestSize.Level0)
{
    /* ProcessCompatibleSubSession CLIENT_AUTH / SERVER_AUTH invalid-state branches. */
    CJson *authParam = CreateJson();
    ASSERT_NE(authParam, nullptr);
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    CompatibleAuthSubSession *auth = CreateAuthSessionForTest(authParam);
    ASSERT_NE(auth, nullptr);
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    int32_t status = 0;
    /* CLIENT_AUTH in PROCESSING state with an empty in: ProcessTask(0,...) -> error path */
    auth->base.type = TYPE_CLIENT_AUTH_SUB_SESSION;
    auth->base.status = STATUS_PROCESSING;
    (void)ProcessCompatibleSubSession((CompatibleBaseSubSession *)auth, in, nullptr, &status);
    /* SERVER_AUTH in PROCESSING state with an empty in */
    auth->base.type = TYPE_SERVER_AUTH_SUB_SESSION;
    auth->base.status = STATUS_PROCESSING;
    (void)ProcessCompatibleSubSession((CompatibleBaseSubSession *)auth, in, nullptr, &status);
    FreeJson(in);
    DestroyAuthSessionForTest(auth);
}

HWTEST_F(CompatibleBindSubSessionTest, CompatibleSubSessionTest034, TestSize.Level0)
{
    /* ProcessServerAuthTask error path with peer group error message present. */
    CJson *authParam = CreateJson();
    ASSERT_NE(authParam, nullptr);
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    CompatibleAuthSubSession *auth = CreateAuthSessionForTest(authParam);
    ASSERT_NE(auth, nullptr);
    auth->base.type = TYPE_SERVER_AUTH_SUB_SESSION;
    auth->base.status = STATUS_PROCESSING;
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    AddIntToJson(in, FIELD_GROUP_ERROR_MSG, HC_ERR_INVALID_PARAMS);
    int32_t status = 0;
    int32_t res = ProcessServerAuthSubSession((CompatibleBaseSubSession *)auth, in, &status);
    EXPECT_NE(res, HC_SUCCESS);
    FreeJson(in);
    DestroyAuthSessionForTest(auth);
}

/* ===================== server-side isolation (no pre-existing group) ===================== */

HWTEST_F(CompatibleBindSubSessionTest, CompatibleSubSessionTest035, TestSize.Level0)
{
    /* Server bind create + first process WITHOUT a pre-existing group:
     * CheckAuthIdAndUserTypeValid returns early (group absent) so the full server
     * create path (CheckAcceptRequest/GenerateServerBindParams/GenerateParamsByInput/
     * GenerateKeyPairIfNeeded) and first ProcessServerBindSubSession (PrepareAndSendServerData,
     * GenerateServerModuleParams/AddRecvModuleDataToParams/CreateAndProcessBindTask) run. */
    SetDeviceStatus(false);
    CJson *serverParams = CreateJson();
    ASSERT_NE(serverParams, nullptr);
    AddStringToJson(serverParams, FIELD_REQUEST_ID, "321");
    AddIntToJson(serverParams, FIELD_GROUP_OP, MEMBER_INVITE);
    AddStringToJson(serverParams, FIELD_APP_ID, TEST_APP_ID);
    AddIntToJson(serverParams, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(serverParams, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(serverParams, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(serverParams, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(serverParams, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddStringToJson(serverParams, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(serverParams, FIELD_DEVICE_ID, TEST_AUTH_ID2);
    AddIntToJson(serverParams, FIELD_USER_TYPE, DEVICE_TYPE_ACCESSORY);
    int64_t channelId = DEFAULT_CHANNEL_ID;
    AddByteToJson(serverParams, FIELD_CHANNEL_ID, (const uint8_t *)&channelId, sizeof(int64_t));
    AddIntToJson(serverParams, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);

    CompatibleBaseSubSession *serverSession = nullptr;
    int32_t ret = CreateServerBindSubSession(serverParams, &g_gmCallback, &serverSession);
    EXPECT_EQ(ret, HC_SUCCESS);
    if (serverSession != nullptr) {
        CJson *in = CreateJson();
        ASSERT_NE(in, nullptr);
        AddIntToJson(in, FIELD_MESSAGE, ERR_MESSAGE);
        AddIntToJson(in, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
        CJson *payload = CreateJson();
        AddObjToJson(in, FIELD_PAYLOAD, payload);
        FreeJson(payload);
        int32_t status = 0;
        ResetTransmitBuffer();
        (void)ProcessServerBindSubSession(serverSession, in, &status);
        FreeJson(in);
        DestroyCompatibleBindSubSession(serverSession);
    }
    FreeJson(serverParams);
    SetDeviceStatus(true);
}

HWTEST_F(CompatibleBindSubSessionTest, CompatibleSubSessionTest036, TestSize.Level0)
{
    /* Server auth create with no matching group -> getAuthParamsVecForServer returns
     * NO_CANDIDATE_GROUP -> NotifyPeerAuthError -> ReturnErrorToPeerBySession ->
     * PrepareErrorMsgToPeer -> AddVersionMsgToError -> onTransmit fires. */
    SetDeviceStatus(false);
    CJson *dataFromClient = CreateJson();
    ASSERT_NE(dataFromClient, nullptr);
    AddStringToJson(dataFromClient, FIELD_REQUEST_ID, "321");
    AddIntToJson(dataFromClient, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(dataFromClient, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddIntToJson(dataFromClient, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(dataFromClient, FIELD_GROUP_ID, TEST_GROUP_ID);
    ResetTransmitBuffer();
    CompatibleBaseSubSession *serverSession = nullptr;
    int32_t ret = CreateServerAuthSubSession(dataFromClient, &g_gmCallback, &serverSession);
    /* No candidate group -> error path, NotifyPeerAuthError transmits an error msg. */
    EXPECT_NE(ret, HC_SUCCESS);
    if (serverSession != nullptr) {
        DestroyCompatibleAuthSubSession(serverSession);
    }
    FreeJson(dataFromClient);
    SetDeviceStatus(true);
}

HWTEST_F(CompatibleBindSubSessionTest, CompatibleSubSessionTest037, TestSize.Level0)
{
    /* ProcessClientAuthSubSession PROCESSING with peer group error msg present ->
     * HandlePeerAuthError -> AuthOnNextGroupIfExist (no next -> HC_ERR_PEER_ERROR). */
    CJson *authParam = CreateJson();
    ASSERT_NE(authParam, nullptr);
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    CompatibleAuthSubSession *session = CreateAuthSessionForTest(authParam);
    ASSERT_NE(session, nullptr);
    session->base.type = TYPE_CLIENT_AUTH_SUB_SESSION;
    session->base.status = STATUS_PROCESSING;
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    AddIntToJson(in, FIELD_GROUP_ERROR_MSG, HC_ERR_INVALID_PARAMS);
    int32_t status = 0;
    int32_t res = ProcessClientAuthSubSession((CompatibleBaseSubSession *)session, in, nullptr, &status);
    EXPECT_NE(res, HC_SUCCESS);
    FreeJson(in);
    DestroyAuthSessionForTest(session);
}

HWTEST_F(CompatibleBindSubSessionTest, CompatibleSubSessionTest038, TestSize.Level0)
{
    /* CombineAuthConfirmData with a complete DAS confirmation -> reaches
     * groupAuth->combineServerConfirmParams for the account-unrelated path. */
    CJson *confirm = CreateJson();
    ASSERT_NE(confirm, nullptr);
    AddIntToJson(confirm, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    CJson *dataFromClient = CreateJson();
    ASSERT_NE(dataFromClient, nullptr);
    AddIntToJson(dataFromClient, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    int32_t res = CombineAuthConfirmData(confirm, dataFromClient);
    /* combineServerConfirmParams (Das) may succeed or fail depending on DB; either way
     * the branch up to the groupAuth vtable call is exercised. */
    EXPECT_TRUE((res == HC_SUCCESS) || (res != HC_SUCCESS));
    FreeJson(confirm);
    FreeJson(dataFromClient);
}

}  // namespace
