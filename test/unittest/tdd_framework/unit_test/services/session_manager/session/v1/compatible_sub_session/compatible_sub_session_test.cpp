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

class CompatibleSubSessionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CompatibleSubSessionTest::SetUpTestCase() {}

void CompatibleSubSessionTest::TearDownTestCase() {}

void CompatibleSubSessionTest::SetUp()
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

void CompatibleSubSessionTest::TearDown()
{
    cJSON_Hooks hooks = {
        .malloc_fn = malloc,
        .free_fn = free,
    };
    cJSON_InitHooks(&hooks);
    DestroyExceptionController();
    DestroyDeviceAuthService();
}

/* ===================== dispatcher: compatible_sub_session.c ===================== */

HWTEST_F(CompatibleSubSessionTest, CompatibleSubSessionTest001, TestSize.Level0)
{
    /* null params for CreateCompatibleSubSession */
    int32_t res = CreateCompatibleSubSession(TYPE_CLIENT_BIND_SUB_SESSION, nullptr, &g_gmCallback, nullptr);
    EXPECT_EQ(res, HC_ERR_INVALID_PARAMS);
    CJson *params = CreateJson();
    ASSERT_NE(params, nullptr);
    res = CreateCompatibleSubSession(TYPE_CLIENT_BIND_SUB_SESSION, params, nullptr, nullptr);
    EXPECT_EQ(res, HC_ERR_INVALID_PARAMS);
    FreeJson(params);
}

HWTEST_F(CompatibleSubSessionTest, CompatibleSubSessionTest002, TestSize.Level0)
{
    /* invalid session type */
    CJson *params = CreateJson();
    ASSERT_NE(params, nullptr);
    CompatibleBaseSubSession *session = nullptr;
    int32_t res = CreateCompatibleSubSession((SubSessionTypeValue)999, params, &g_gmCallback, &session);
    EXPECT_EQ(res, HC_ERR_INVALID_PARAMS);
    FreeJson(params);
}

HWTEST_F(CompatibleSubSessionTest, CompatibleSubSessionTest003, TestSize.Level0)
{
    /* null params for ProcessCompatibleSubSession */
    int32_t status = 0;
    CJson *out = nullptr;
    int32_t res = ProcessCompatibleSubSession(nullptr, nullptr, &out, &status);
    EXPECT_EQ(res, HC_ERR_INVALID_PARAMS);
}

HWTEST_F(CompatibleSubSessionTest, CompatibleSubSessionTest004, TestSize.Level0)
{
    /* invalid type while processing */
    CompatibleBaseSubSession session;
    (void)memset_s(&session, sizeof(session), 0, sizeof(session));
    session.type = 999;
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    CJson *out = nullptr;
    int32_t status = 0;
    int32_t res = ProcessCompatibleSubSession(&session, in, &out, &status);
    EXPECT_EQ(res, HC_ERR_INVALID_PARAMS);
    FreeJson(in);
}

HWTEST_F(CompatibleSubSessionTest, CompatibleSubSessionTest005, TestSize.Level0)
{
    /* DestroyCompatibleSubSession: null + invalid type */
    DestroyCompatibleSubSession(nullptr);
    CompatibleBaseSubSession session;
    (void)memset_s(&session, sizeof(session), 0, sizeof(session));
    session.type = 999;
    DestroyCompatibleSubSession(&session);
    SUCCEED();
}

/* ===================== pure helpers ===================== */

HWTEST_F(CompatibleSubSessionTest, CompatibleSubSessionTest006, TestSize.Level0)
{
    EXPECT_FALSE(IsCreateGroupNeeded(CLIENT, MEMBER_INVITE));
    EXPECT_TRUE(IsCreateGroupNeeded(CLIENT, MEMBER_JOIN));
    EXPECT_TRUE(IsCreateGroupNeeded(SERVER, MEMBER_INVITE));
    EXPECT_FALSE(IsCreateGroupNeeded(SERVER, MEMBER_JOIN));
}

HWTEST_F(CompatibleSubSessionTest, CompatibleSubSessionTest007, TestSize.Level0)
{
    EXPECT_EQ(GetAuthType(AUTH_FORM_ACCOUNT_UNRELATED), ACCOUNT_UNRELATED_GROUP_AUTH_TYPE);
    EXPECT_EQ(GetAuthType(AUTH_FORM_IDENTICAL_ACCOUNT), ACCOUNT_RELATED_GROUP_AUTH_TYPE);
    EXPECT_EQ(GetAuthType(AUTH_FORM_ACROSS_ACCOUNT), ACCOUNT_RELATED_GROUP_AUTH_TYPE);
    EXPECT_EQ(GetAuthType(AUTH_FORM_INVALID_TYPE), INVALID_GROUP_AUTH_TYPE);
}

HWTEST_F(CompatibleSubSessionTest, CompatibleSubSessionTest008, TestSize.Level0)
{
    EXPECT_EQ(GetAuthModuleType(nullptr), INVALID_MODULE_TYPE);
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    AddIntToJson(in, FIELD_AUTH_FORM, AUTH_FORM_INVALID_TYPE);
    EXPECT_EQ(GetAuthModuleType(in), INVALID_MODULE_TYPE);
    (void)AddIntToJson(in, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    EXPECT_EQ(GetAuthModuleType(in), DAS_MODULE);
    (void)AddIntToJson(in, FIELD_AUTH_FORM, AUTH_FORM_IDENTICAL_ACCOUNT);
    EXPECT_EQ(GetAuthModuleType(in), ACCOUNT_MODULE);
    (void)AddIntToJson(in, FIELD_AUTH_FORM, AUTH_FORM_ACROSS_ACCOUNT);
    EXPECT_EQ(GetAuthModuleType(in), ACCOUNT_MODULE);
    FreeJson(in);
}

HWTEST_F(CompatibleSubSessionTest, CompatibleSubSessionTest009, TestSize.Level0)
{
    char *pkgName = GetDuplicatePkgName(nullptr);
    EXPECT_EQ(pkgName, nullptr);
    CJson *params = CreateJson();
    ASSERT_NE(params, nullptr);
    pkgName = GetDuplicatePkgName(params);
    EXPECT_EQ(pkgName, nullptr);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    pkgName = GetDuplicatePkgName(params);
    ASSERT_NE(pkgName, nullptr);
    EXPECT_STREQ(pkgName, TEST_SERVICE_PKG_NAME);
    HcFree(pkgName);
    FreeJson(params);
}

HWTEST_F(CompatibleSubSessionTest, CompatibleSubSessionTest010, TestSize.Level0)
{
    ParamsVecForAuth vec;
    CreateAuthParamsList(&vec);
    EXPECT_EQ(vec.size(&vec), 0u);
    CJson *item = CreateJson();
    ASSERT_NE(item, nullptr);
    vec.pushBack(&vec, (const void **)&item);
    EXPECT_EQ(vec.size(&vec), 1u);
    DestroyAuthParamsList(&vec);
}

HWTEST_F(CompatibleSubSessionTest, CompatibleSubSessionTest011, TestSize.Level0)
{
    /* RegisterGroupAuth is already called during InitDeviceAuthService; verify GetGroupAuth. */
    BaseGroupAuth *unrelated = GetGroupAuth(ACCOUNT_UNRELATED_GROUP_AUTH_TYPE);
    ASSERT_NE(unrelated, nullptr);
    BaseGroupAuth *related = GetGroupAuth(ACCOUNT_RELATED_GROUP_AUTH_TYPE);
    ASSERT_NE(related, nullptr);
    EXPECT_EQ(GetGroupAuth(INVALID_GROUP_AUTH_TYPE), nullptr);
}

HWTEST_F(CompatibleSubSessionTest, CompatibleSubSessionTest012, TestSize.Level0)
{
    CJson *data = CreateJson();
    ASSERT_NE(data, nullptr);
    AddIntToJson(data, FIELD_PAYLOAD, 1);
    AddStringToJson(data, FIELD_SELF_AUTH_ID, TEST_AUTH_ID);
    AddIntToJson(data, FIELD_OPERATION_CODE, AUTHENTICATE);
    ClearCachedData(data);
    int32_t payloadVal = 1;
    EXPECT_NE(GetIntFromJson(data, FIELD_PAYLOAD, &payloadVal), HC_SUCCESS);
    int32_t opVal = 1;
    EXPECT_NE(GetIntFromJson(data, FIELD_OPERATION_CODE, &opVal), HC_SUCCESS);
    FreeJson(data);
}

HWTEST_F(CompatibleSubSessionTest, CompatibleSubSessionTest013, TestSize.Level0)
{
    /* IGNORE_MSG and invalid status do not dereference the session. */
    EXPECT_EQ(HandleAuthTaskStatus(nullptr, nullptr, IGNORE_MSG, true), HC_SUCCESS);
    EXPECT_NE(HandleAuthTaskStatus(nullptr, nullptr, 999, true), HC_SUCCESS);
}

}  // namespace
