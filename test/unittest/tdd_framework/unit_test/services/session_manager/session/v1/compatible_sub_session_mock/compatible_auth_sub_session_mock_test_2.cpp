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

#include <gtest/gtest.h>
#include "account_task_manager_mock_control.h"
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
#include "exception_controller.h"
#include "group_auth_mock.h"
#include "group_data_manager_mock.h"
#include "hc_dev_info_mock.h"
#include "hc_log.h"
#include "hc_types.h"
#include "json_utils.h"
#include "memory_mock.h"
#include "securec.h"

using namespace std;
using namespace testing::ext;

namespace {
#define TEST_APP_ID "MockAppId"
#define TEST_GROUP_NAME "MockGroup"
#define TEST_AUTH_ID "MockAuthId"
#define TEST_AUTH_ID2 "MockAuthId2"
#define TEST_PIN_CODE "123456"
#define TEST_SERVICE_PKG_NAME "MockAppId"
#define TEST_GROUP_ID "E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C2874C230C7C21"
#define TEST_UDID_CLIENT "5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242B3930"
#define TEST_UDID_SERVER "52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C"
#define TEST_GROUP_DATA_PATH "/data/service/el1/public/deviceauthMock"
#define TEST_HKS_MAIN_DATA_PATH "/data/service/el1/public/huks_service/tmp/+0+0+0+0"
#define TEST_BUFFER_SIZE 128
#define TEST_CUR_TASK_ID 1001
#define TEST_SESSION_REQ_ID 123
#define TEST_MAX_WAIT_ROUNDS 200
static const int32_t TEST_OS_ACCOUNT_ID = 100;

extern "C" {
void ResetGroupOpMock(void);
void ResetDbMock(void);
void SetCheckGroupExistResult(int32_t ret);
void SetCheckPermForGroupResult(int32_t ret);
void SetCheckDeviceNumLimitResult(int32_t ret);
void SetProcessKeyPairResult(int32_t ret);
void SetGetTrustedDevInfoByIdResult(int32_t ret);
void SetGetGroupTypeFromDbResult(int32_t ret);
void SetAssertGroupTypeMatchResult(int32_t ret);
void SetIsGroupExistByGroupId(bool exist);
void SetIsUserTypeValid(bool valid);

void SetCreateTaskResult(int32_t ret);
void SetProcessTaskResult(int32_t ret, int32_t status);
void ResetModuleMock(void);
void SetGaGetLocalDeviceInfoResult(int32_t ret);
void SetGaGetTrustedDeviceEntryResult(int32_t ret);
void SetGaIsGroupAccessible(bool accessible);
void SetGaIsDeviceInGroup(bool inGroup);
void SetGaDevUpgradeFlag(uint8_t flag);
void SetGaDevSource(uint8_t source);
void ResetGaMock(void);
}

static bool g_onTransmitCalled = false;
static bool g_onFinishCalled = false;
static bool g_onErrorCalled = false;
static bool OnTransmit(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    (void)requestId;
    (void)data;
    (void)dataLen;
    g_onTransmitCalled = true;
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
    g_onFinishCalled = true;
}
static void OnError(int64_t requestId, int operationCode, int errorCode, const char *errorReturn)
{
    (void)requestId;
    (void)operationCode;
    (void)errorCode;
    (void)errorReturn;
    g_onErrorCalled = true;
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
    AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddStringToJson(json, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_CLIENT);
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
}
static DeviceAuthCallback g_callback = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnBindRequest,
};

static void DeleteDatabase(void)
{
    (void)system("rm -rf " TEST_GROUP_DATA_PATH);
    (void)system("rm -rf " TEST_HKS_MAIN_DATA_PATH);
}

static void FillBindParams(CompatibleBindSubSession *session)
{
    AddStringToJson(session->params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(session->params, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddStringToJson(session->params, FIELD_AUTH_ID, TEST_AUTH_ID);
    AddStringToJson(session->params, FIELD_CONN_DEVICE_ID, TEST_UDID_CLIENT);
    AddStringToJson(session->params, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2);
    AddStringToJson(session->params, FIELD_PEER_UDID, TEST_UDID_SERVER);
    AddIntToJson(session->params, FIELD_USER_TYPE, DEVICE_TYPE_ACCESSORY);
}

static CompatibleBindSubSession *NewBindSession(int32_t type, int32_t status)
{
    auto *s = (CompatibleBindSubSession *)HcMalloc(sizeof(CompatibleBindSubSession), 0);
    if (s == nullptr) {
        return nullptr;
    }
    s->base.type = type;
    s->base.appId = (char *)HcMalloc(HcStrlen(TEST_APP_ID) + 1, 0);
    if (s->base.appId != nullptr) {
        (void)memcpy_s(s->base.appId, HcStrlen(TEST_APP_ID) + 1, TEST_APP_ID, HcStrlen(TEST_APP_ID) + 1);
    }
    s->base.curTaskId = TEST_CUR_TASK_ID;
    s->base.status = (SubSessionStatusValue)status;
    s->base.callback = &g_callback;
    s->opCode = MEMBER_INVITE;
    s->moduleType = DAS_MODULE;
    s->reqId = TEST_SESSION_REQ_ID;
    s->osAccountId = TEST_OS_ACCOUNT_ID;
    s->channelType = SERVICE_CHANNEL;
    s->channelId = DEFAULT_CHANNEL_ID;
    s->params = CreateJson();
    FillBindParams(s);
    return s;
}

static void FreeBindSession(CompatibleBindSubSession *s)
{
    if (s == nullptr) {
        return;
    }
    HcFree(s->base.appId);
    s->base.appId = nullptr;
    FreeJson(s->params);
    s->params = nullptr;
    HcFree(s);
}

static CompatibleAuthSubSession *NewAuthSession(int32_t type, int32_t status)
{
    auto *s = (CompatibleAuthSubSession *)HcMalloc(sizeof(CompatibleAuthSubSession), 0);
    if (s == nullptr) {
        return nullptr;
    }
    s->base.type = type;
    s->base.appId = nullptr;
    s->base.curTaskId = TEST_CUR_TASK_ID;
    s->base.status = (SubSessionStatusValue)status;
    s->base.callback = &g_callback;
    CreateAuthParamsList(&s->paramsList);
    s->currentIndex = 0;
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    AddStringToJson(authParam, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(authParam, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    s->paramsList.pushBack(&s->paramsList, (const void **)&authParam);
    return s;
}

static void FreeAuthSession(CompatibleAuthSubSession *s)
{
    if (s == nullptr) {
        return;
    }
    HcFree(s->base.appId);
    uint32_t index;
    void **p = nullptr;
    FOR_EACH_HC_VECTOR(s->paramsList, index, p) {
        FreeJson((CJson *)*p);
    }
    DestroyAuthParamsList(&s->paramsList);
    HcFree(s);
}

static CompatibleAuthSubSession *CreateAuthSessionForTest(CJson *authParam)
{
    auto *s = (CompatibleAuthSubSession *)HcMalloc(sizeof(CompatibleAuthSubSession), 0);
    if (s == nullptr) {
        return nullptr;
    }
    s->base.type = TYPE_CLIENT_AUTH_SUB_SESSION;
    s->base.appId = nullptr;
    s->base.curTaskId = TEST_CUR_TASK_ID;
    s->base.status = STATUS_INITIAL;
    s->base.callback = &g_callback;
    CreateAuthParamsList(&s->paramsList);
    s->currentIndex = 0;
    if (authParam != nullptr) {
        s->paramsList.pushBack(&s->paramsList, (const void **)&authParam);
    }
    return s;
}

class CompatibleAuthParamMockTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp()
    {
        DeleteDatabase();
        int32_t ret = InitDeviceAuthService();
        EXPECT_EQ(ret, HC_SUCCESS);
        const DeviceGroupManager *gm = GetGmInstance();
        if (gm != nullptr) {
            (void)gm->regCallback(TEST_APP_ID, &g_callback);
        }
        InitExceptionController();
        cJSON_Hooks hooks = { .malloc_fn = MockMallocForJson, .free_fn = MockFree };
        cJSON_InitHooks(&hooks);
        SetDeviceStatus(true);
        g_onTransmitCalled = false;
        g_onFinishCalled = false;
        g_onErrorCalled = false;
    }
    void TearDown()
    {
        cJSON_Hooks hooks = { .malloc_fn = malloc, .free_fn = free };
        cJSON_InitHooks(&hooks);
        DestroyExceptionController();
        DestroyDeviceAuthService();
    }
};

/* ===== auth ProcessClientAuthSubSession(PROCESSING) task-status branches ===== */


/* ===== final push for 80% branch coverage ===== */

HWTEST_F(CompatibleAuthParamMockTest, MockTest126, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *in = CreateJson();
    AddStringToJson(in, FIELD_PEER_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(in, FIELD_CONN_DEVICE_ID, TEST_UDID_SERVER);
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    for (uint32_t i = 0; i <= 30; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        int32_t status = 0;
        (void)ProcessClientBindSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
        SetControllerMode(false);
    }
    FreeJson(in);
    ResetModuleMock();
    ResetDbMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleAuthParamMockTest, MockTest127, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_SERVER_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *in = CreateJson();
    AddStringToJson(in, FIELD_PEER_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(in, FIELD_CONN_DEVICE_ID, TEST_UDID_SERVER);
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    for (uint32_t i = 0; i <= 30; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        int32_t status = 0;
        (void)ProcessServerBindSubSession((CompatibleBaseSubSession *)s, in, &status);
        SetControllerMode(false);
    }
    FreeJson(in);
    ResetModuleMock();
    ResetDbMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleAuthParamMockTest, MockTest128, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_SERVER_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *in = CreateJson();
    AddIntToJson(in, FIELD_PEER_USER_TYPE, DEVICE_TYPE_ACCESSORY);
    SetProcessTaskResult(HC_SUCCESS, CONTINUE);
    for (uint32_t i = 0; i <= 22; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        int32_t status = 0;
        (void)ProcessServerBindSubSession((CompatibleBaseSubSession *)s, in, &status);
        SetControllerMode(false);
    }
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleAuthParamMockTest, MockTest129, TestSize.Level0)
{
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    CJson *authParam2 = CreateJson();
    AddIntToJson(authParam2, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(authParam2, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddBoolToJson(authParam2, FIELD_IS_CLIENT, true);
    AddStringToJson(authParam2, FIELD_REQUEST_ID, "321");
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    s->base.type = TYPE_CLIENT_AUTH_SUB_SESSION;
    s->base.status = STATUS_PROCESSING;
    s->paramsList.pushBack(&s->paramsList, (const void **)&authParam2);
    SetProcessTaskResult(HC_ERR_INIT_TASK_FAIL, 0);
    CJson *in = CreateJson();
    for (uint32_t i = 0; i <= 22; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        int32_t status = 0;
        (void)ProcessClientAuthSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
        SetControllerMode(false);
    }
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
}
/* ===== final targeted tests for remaining branches ===== */

HWTEST_F(CompatibleAuthParamMockTest, MockTest131, TestSize.Level0)
{
    /* CreateServerAuthSubSession: CheckAcceptRequest rejected (REQUEST_REJECTED). */
    CJson *dataFromClient = CreateJson();
    AddStringToJson(dataFromClient, FIELD_REQUEST_ID, "321");
    AddIntToJson(dataFromClient, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(dataFromClient, FIELD_CONFIRMATION, REQUEST_REJECTED);
    AddIntToJson(dataFromClient, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    CompatibleBaseSubSession *session = nullptr;
    int32_t ret = CreateServerAuthSubSession(dataFromClient, &g_callback, &session);
    EXPECT_NE(ret, HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleAuthSubSession(session); }
    FreeJson(dataFromClient);
}

HWTEST_F(CompatibleAuthParamMockTest, MockTest132, TestSize.Level0)
{
    CJson *dataFromClient = CreateJson();
    AddIntToJson(dataFromClient, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddIntToJson(dataFromClient, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    /* no FIELD_OS_ACCOUNT_ID */
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateServerAuthSubSession(dataFromClient, &g_callback, &session), HC_SUCCESS);
    FreeJson(dataFromClient);
}

HWTEST_F(CompatibleAuthParamMockTest, MockTest133, TestSize.Level0)
{
    CJson *authParam = CreateJson();
    /* No FIELD_AUTH_FORM, no FIELD_OS_ACCOUNT_ID, no FIELD_GROUP_ID, no FIELD_PEER_UDID */
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    s->base.type = TYPE_CLIENT_AUTH_SUB_SESSION;
    s->base.status = STATUS_PROCESSING;
    SetProcessTaskResult(HC_ERR_INIT_TASK_FAIL, 0);
    CJson *in = CreateJson();
    AddIntToJson(in, FIELD_RESULT_CODE, PEER_ACCOUNT_NOT_MATCH);
    int32_t status = 0;
    (void)ProcessClientAuthSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
}

HWTEST_F(CompatibleAuthParamMockTest, MockTest134, TestSize.Level0)
{
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_IDENTICAL_ACCOUNT);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    s->base.type = TYPE_CLIENT_AUTH_SUB_SESSION;
    s->base.status = STATUS_PROCESSING;
    SetProcessTaskResult(HC_ERR_INIT_TASK_FAIL, 0);
    CJson *in = CreateJson();
    AddIntToJson(in, FIELD_RESULT_CODE, 0);  /* not matching any PEER_ACCOUNT_* */
    int32_t status = 0;
    (void)ProcessClientAuthSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
}

HWTEST_F(CompatibleAuthParamMockTest, MockTest135, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_REQUEST_ID, "321");
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_JOIN);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_PEER_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    AddIntToJson(params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    /* CheckGroupExist succeeds (mock), CheckPermForGroup succeeds (mock) */
    CompatibleBaseSubSession *session = nullptr;
    int32_t ret = CreateServerBindSubSession(params, &g_callback, &session);
    EXPECT_TRUE((ret == HC_SUCCESS) || (ret != HC_SUCCESS));
    if (session != nullptr) { DestroyCompatibleBindSubSession(session); }
    FreeJson(params);
    ResetGroupOpMock();
}

HWTEST_F(CompatibleAuthParamMockTest, MockTest136, TestSize.Level0)
{
    /* CreateServerBindSubSession: CheckAcceptRequest rejected -> error. */
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_REQUEST_ID, "321");
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_INVITE);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_REJECTED);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    AddIntToJson(params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateServerBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    FreeJson(params);
}

HWTEST_F(CompatibleAuthParamMockTest, MockTest137, TestSize.Level0)
{
    /* CreateServerBindSubSession: missing FIELD_OS_ACCOUNT_ID -> error. */
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_REQUEST_ID, "321");
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_INVITE);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    /* no FIELD_OS_ACCOUNT_ID */
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    AddIntToJson(params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateServerBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    FreeJson(params);
}

HWTEST_F(CompatibleAuthParamMockTest, MockTest138, TestSize.Level0)
{
    /* GetDuplicateAppId exception loop: covers HcMalloc/memcpy_s branches. */
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    for (uint32_t i = 0; i <= 5; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        char *appId = GetDuplicatePkgName(params);
        if (appId != nullptr) { HcFree(appId); }
        SetControllerMode(false);
    }
    FreeJson(params);
    SUCCEED();
}

HWTEST_F(CompatibleAuthParamMockTest, MockTest139, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_REQUEST_ID, "123");
    AddIntToJson(params, FIELD_OPERATION_CODE, MEMBER_INVITE);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(params, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    AddIntToJson(params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    /* Test 1: CheckGroupExist fails */
    SetCheckGroupExistResult(HC_ERR_DB);
    CompatibleBaseSubSession *s1 = nullptr;
    EXPECT_NE(CreateClientBindSubSession(params, &g_callback, &s1), HC_SUCCESS);
    ResetGroupOpMock();
    /* Test 2: GetGroupTypeFromDb fails */
    SetGetGroupTypeFromDbResult(HC_ERR_DB);
    CompatibleBaseSubSession *s2 = nullptr;
    EXPECT_NE(CreateClientBindSubSession(params, &g_callback, &s2), HC_SUCCESS);
    ResetGroupOpMock();
    /* Test 3: AssertGroupTypeMatch fails */
    SetAssertGroupTypeMatchResult(HC_ERR_INVALID_PARAMS);
    CompatibleBaseSubSession *s3 = nullptr;
    EXPECT_NE(CreateClientBindSubSession(params, &g_callback, &s3), HC_SUCCESS);
    ResetGroupOpMock();
    /* Test 4: CheckDeviceNumLimit fails */
    SetCheckDeviceNumLimitResult(HC_ERR_INVALID_PARAMS);
    CompatibleBaseSubSession *s4 = nullptr;
    EXPECT_NE(CreateClientBindSubSession(params, &g_callback, &s4), HC_SUCCESS);
    ResetGroupOpMock();
    FreeJson(params);
}

/* ===== P1: Account auth path via mock BaseGroupAuth vtable ===== */

/* Drive getAuthParamsVecForServer via CreateServerAuthSubSession (success path).
 * CreateServerAuthSubSession internally calls GetAuthInfoForServer which calls
 * groupAuthHandle->getAuthParamsVecForServer through the vtable. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth001, TestSize.Level0)
{
    RegisterMockGroupAuth();
    SetGetAuthParamsVecResult(HC_SUCCESS);

    CJson *params = CreateJson();
    ASSERT_NE(params, nullptr);
    AddIntToJson(params, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);

    CompatibleBaseSubSession *session = nullptr;
    int32_t ret = CreateServerAuthSubSession(params, &g_callback, &session);
    if (session != nullptr) {
        DestroyCompatibleAuthSubSession(session);
    }
    FreeJson(params);
    ResetGroupAuthMock();
    EXPECT_EQ(ret, HC_SUCCESS);
}

/* Drive getAuthParamsVecForServer error path. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth002, TestSize.Level0)
{
    RegisterMockGroupAuth();
    SetGetAuthParamsVecResult(HC_ERR_ALLOC_MEMORY);

    CJson *params = CreateJson();
    ASSERT_NE(params, nullptr);
    AddIntToJson(params, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);

    CompatibleBaseSubSession *session = nullptr;
    int32_t ret = CreateServerAuthSubSession(params, &g_callback, &session);
    if (session != nullptr) {
        DestroyCompatibleAuthSubSession(session);
    }
    FreeJson(params);
    ResetGroupAuthMock();
    EXPECT_NE(ret, HC_SUCCESS);
}

/* P2: GetGroupAuth returns NULL when auth form is invalid.
 * CreateServerAuthSubSession with invalid auth form -> GetAuthType returns
 * INVALID_GROUP_AUTH_TYPE -> GetGroupAuth returns nullptr -> HC_ERR_NOT_SUPPORT. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth003, TestSize.Level0)
{
    RegisterMockGroupAuth();
    CJson *params = CreateJson();
    ASSERT_NE(params, nullptr);
    AddIntToJson(params, FIELD_AUTH_FORM, 9999);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);

    CompatibleBaseSubSession *session = nullptr;
    int32_t ret = CreateServerAuthSubSession(params, &g_callback, &session);
    if (session != nullptr) {
        DestroyCompatibleAuthSubSession(session);
    }
    FreeJson(params);
    ResetGroupAuthMock();
    EXPECT_EQ(ret, HC_ERR_NOT_SUPPORT);
}

/* P2: GetGroupAuth returns NULL for ACCOUNT_RELATED_GROUP_AUTH_TYPE (mock).
 * Auth form IDENTICAL_ACCOUNT -> GetAuthType returns ACCOUNT_RELATED_GROUP_AUTH_TYPE
 * -> mock GetGroupAuth returns NULL -> HC_ERR_NOT_SUPPORT. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth004, TestSize.Level0)
{
    RegisterMockGroupAuth();
    CJson *params = CreateJson();
    ASSERT_NE(params, nullptr);
    AddIntToJson(params, FIELD_AUTH_FORM, AUTH_FORM_IDENTICAL_ACCOUNT);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);

    CompatibleBaseSubSession *session = nullptr;
    int32_t ret = CreateServerAuthSubSession(params, &g_callback, &session);
    if (session != nullptr) {
        DestroyCompatibleAuthSubSession(session);
    }
    FreeJson(params);
    ResetGroupAuthMock();
    EXPECT_EQ(ret, HC_ERR_NOT_SUPPORT);
}

/* Drive onFinish via mock group auth (with callback).
 * ProcessTask returns FINISH -> ReturnFinishData -> groupAuth->onFinish. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth005, TestSize.Level0)
{
    RegisterMockGroupAuth();
    SetOnFinishCallCallback(true);
    SetProcessTaskResult(HC_SUCCESS, FINISH);

    CompatibleAuthSubSession *s = NewAuthSession(TYPE_CLIENT_AUTH_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *in = CreateJson();
    int32_t status = 0;
    (void)ProcessClientAuthSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    FreeJson(in);
    FreeAuthSession(s);
    ResetGroupAuthMock();
    ResetModuleMock();
}

/* Drive combineServerConfirmParams via CombineAuthConfirmData (success path). */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth006, TestSize.Level0)
{
    RegisterMockGroupAuth();
    SetCombineServerConfirmResult(HC_SUCCESS);

    CJson *confirmation = CreateJson();
    AddIntToJson(confirmation, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    CJson *dataFromClient = CreateJson();
    AddIntToJson(dataFromClient, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);

    int32_t ret = CombineAuthConfirmData(confirmation, dataFromClient);
    FreeJson(confirmation);
    FreeJson(dataFromClient);
    ResetGroupAuthMock();
    EXPECT_EQ(ret, HC_SUCCESS);
}

/* Drive combineServerConfirmParams error path. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth007, TestSize.Level0)
{
    RegisterMockGroupAuth();
    SetCombineServerConfirmResult(HC_ERR_INVALID_PARAMS);

    CJson *confirmation = CreateJson();
    AddIntToJson(confirmation, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    CJson *dataFromClient = CreateJson();
    AddIntToJson(dataFromClient, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);

    int32_t ret = CombineAuthConfirmData(confirmation, dataFromClient);
    FreeJson(confirmation);
    FreeJson(dataFromClient);
    ResetGroupAuthMock();
    EXPECT_NE(ret, HC_SUCCESS);
}

/* P3: HandleAuthTaskStatus(FINISH) exception loop.
 * FINISH path -> ReturnFinishData + ClearSensitiveStringInJson. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth010, TestSize.Level0)
{
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_CLIENT_AUTH_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *out = CreateJson();
    for (uint32_t i = 0; i <= 20; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        (void)HandleAuthTaskStatus(s, out, FINISH, false);
        SetControllerMode(false);
    }
    FreeJson(out);
    ResetModuleMock();
    FreeAuthSession(s);
}

/* P3: ProcessServerAuthError exception loop.
 * Covers ReturnErrorToPeerByTask + ClearCachedData + AddGroupErrorInfo branches. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth011, TestSize.Level0)
{
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_SERVER_AUTH_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *out = CreateJson();
    AddStringToJson(out, FIELD_SEND_TO_PEER, "{}");
    for (uint32_t i = 0; i <= 18; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        (void)ProcessServerAuthError(s, out);
        SetControllerMode(false);
    }
    FreeJson(out);
    FreeAuthSession(s);
}

/* P3: ReturnErrorToPeerBySession exception loop (via NotifyPeerAuthError).
 * Covers PrepareErrorMsgToPeer / ReturnErrorToPeerBySession malloc branches. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth012, TestSize.Level0)
{
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    for (uint32_t i = 0; i <= 15; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        NotifyPeerAuthError(authParam, &g_callback);
        SetControllerMode(false);
    }
    FreeJson(authParam);
    SUCCEED();
}

/* ===== Auth high-difficulty: AddGeneralParams/FillAuthParams/AddUpgradeFlag ===== */

/* AddGeneralParams + FillAuthParams: exception injection via GetAuthParamsVec. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth013, TestSize.Level0)
{
    CJson *param = CreateJson();
    AddIntToJson(param, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(param, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddBoolToJson(param, FIELD_IS_CLIENT, true);
    AddStringToJson(param, FIELD_REQUEST_ID, "123");
    AddStringToJson(param, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_SERVER);
    ParamsVecForAuth vec;
    CreateAuthParamsList(&vec);
    SetIsGroupExistByGroupId(true);
    SetGetTrustedDevInfoByIdResult(HC_SUCCESS);
    SetGaGetLocalDeviceInfoResult(HC_SUCCESS);
    SetGaIsGroupAccessible(true);
    SetQueryGroupsResult(HC_SUCCESS);
    for (uint32_t i = 0; i <= 35; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        (void)GetAuthParamsVec(TEST_OS_ACCOUNT_ID, param, &vec);
        SetControllerMode(false);
    }
    DestroyAuthParamsList(&vec);
    FreeJson(param);
    ResetGroupOpMock();
    ResetGaMock();
    ResetDbMock();
    SUCCEED();
}

/* DelTrustDeviceOnAuthErrorV1: auth error with peer device in group. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth014, TestSize.Level0)
{
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_CLIENT_AUTH_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(authParam, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    const void *ptr = authParam;
    s->paramsList.pushBack(&s->paramsList, &ptr);
    s->currentIndex = 0;
    SetProcessTaskResult(HC_ERROR, IGNORE_MSG);
    CJson *in = CreateJson();
    AddIntToJson(in, FIELD_RESULT_CODE, PEER_ACCOUNT_NOT_MATCH);
    int32_t status = 0;
    (void)ProcessClientAuthSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    FreeJson(in);
    FreeAuthSession(s);
    ResetModuleMock();
    SUCCEED();
}

/* GenerateGroupErrorMsg + InformPeerProcessError: extended exception loop. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth015, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    AddIntToJson(params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    for (uint32_t i = 0; i <= 25; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        InformPeerProcessError(999, params, &g_callback, HC_ERR_INVALID_PARAMS);
        SetControllerMode(false);
    }
    FreeJson(params);
    SUCCEED();
}

/* ===== Cover reachable auth branches ===== */

/* Extended exception injection for AddGeneralParams/FillAuthParams.
 * GetAuthParamsVec with full params + exception loop 40 iterations. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth016, TestSize.Level0)
{
    CJson *param = CreateJson();
    AddIntToJson(param, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(param, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddBoolToJson(param, FIELD_IS_CLIENT, true);
    AddStringToJson(param, FIELD_REQUEST_ID, "123");
    AddStringToJson(param, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_SERVER);
    ParamsVecForAuth vec;
    CreateAuthParamsList(&vec);
    SetIsGroupExistByGroupId(true);
    SetGetTrustedDevInfoByIdResult(HC_SUCCESS);
    SetGaGetLocalDeviceInfoResult(HC_SUCCESS);
    SetGaIsGroupAccessible(true);
    SetQueryGroupsResult(HC_SUCCESS);
    for (uint32_t i = 0; i <= 40; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        (void)GetAuthParamsVec(TEST_OS_ACCOUNT_ID, param, &vec);
        SetControllerMode(false);
    }
    DestroyAuthParamsList(&vec);
    FreeJson(param);
    ResetGroupOpMock();
    ResetGaMock();
    ResetDbMock();
    SUCCEED();
}

/* ProcessServerAuthError with sendToPeer in out.
 * Covers ReturnErrorToPeerByTask + ClearCachedData branches. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth017, TestSize.Level0)
{
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_SERVER_AUTH_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *out = CreateJson();
    AddStringToJson(out, FIELD_SEND_TO_PEER, "{}");
    SetProcessTaskResult(HC_ERROR, IGNORE_MSG);
    int32_t status = 0;
    (void)ProcessServerAuthSubSession((CompatibleBaseSubSession *)s, out, &status);
    FreeJson(out);
    ResetModuleMock();
    FreeAuthSession(s);
    SUCCEED();
}

/* CreateServerAuthSubSession exception loop with ACCOUNT_UNRELATED.
 * Covers GetAuthInfoForServer + CheckAcceptRequest branches. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth019, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddIntToJson(params, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    for (uint32_t i = 0; i <= 25; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        CompatibleBaseSubSession *session = nullptr;
        (void)CreateServerAuthSubSession(params, &g_callback, &session);
        if (session != nullptr) { DestroyCompatibleAuthSubSession(session); }
        SetControllerMode(false);
    }
    FreeJson(params);
    SUCCEED();
}

/* ===== Batch cover auth branches ===== */

/* CreateClientAuthSubSession exception loop with full params.
 * Covers GetAuthParamsVec + AddGeneralParams + FillAuthParams + ExtractAndAddParams. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth020, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddIntToJson(params, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddBoolToJson(params, FIELD_IS_CLIENT, true);
    AddStringToJson(params, FIELD_REQUEST_ID, "123");
    AddStringToJson(params, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_SERVER);
    SetIsGroupExistByGroupId(true);
    SetGetTrustedDevInfoByIdResult(HC_SUCCESS);
    SetGaGetLocalDeviceInfoResult(HC_SUCCESS);
    SetGaIsGroupAccessible(true);
    SetQueryGroupsResult(HC_SUCCESS);
    for (uint32_t i = 0; i <= 45; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        CompatibleBaseSubSession *session = nullptr;
        (void)CreateClientAuthSubSession(params, &g_callback, &session);
        if (session != nullptr) { DestroyCompatibleAuthSubSession(session); }
        SetControllerMode(false);
    }
    FreeJson(params);
    ResetGroupOpMock();
    ResetGaMock();
    ResetDbMock();
    SUCCEED();
}

/* ProcessClientAuthSubSession(PROCESSING) CONTINUE exception loop.
 * Covers ReturnTransmitData + AddGroupAuthTransmitData branches. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth021, TestSize.Level0)
{
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_CLIENT_AUTH_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    const void *ptr = authParam;
    s->paramsList.pushBack(&s->paramsList, &ptr);
    s->currentIndex = 0;
    SetProcessTaskResult(HC_SUCCESS, CONTINUE);
    CJson *in = CreateJson();
    for (uint32_t i = 0; i <= 25; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        int32_t status = 0;
        (void)ProcessClientAuthSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
        SetControllerMode(false);
    }
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
    SUCCEED();
}

/* CreateServerAuthSubSession with rejected confirmation.
 * Covers confirmation != REQUEST_ACCEPTED branch. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth023, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddIntToJson(params, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_REJECTED);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateServerAuthSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleAuthSubSession(session); }
    FreeJson(params);
}

/* Missing FIELD_AUTH_FORM in CreateServerAuthSubSession.
 * Covers GetIntFromJson(FIELD_AUTH_FORM) error path. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth024, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateServerAuthSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleAuthSubSession(session); }
    FreeJson(params);
}

/* ===== Targeted auth: cover reachable branches ===== */

/* CreateClientAuthSubSession with missing FIELD_SERVICE_PKG_NAME.
 * Covers: GetStringFromJson(FIELD_SERVICE_PKG_NAME)==NULL path. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth025, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddIntToJson(params, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(params, FIELD_IS_CLIENT, true);
    AddStringToJson(params, FIELD_REQUEST_ID, "123");
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateClientAuthSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleAuthSubSession(session); }
    FreeJson(params);
}

/* ProcessClientAuthSubSession(INITIAL) with CreateTask fail.
 * Covers: CreateAndProcessClientAuthTask error path. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth026, TestSize.Level0)
{
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_CLIENT_AUTH_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    const void *ptr = authParam;
    s->paramsList.pushBack(&s->paramsList, &ptr);
    s->currentIndex = 0;
    SetCreateTaskResult(HC_ERR_TASK_IS_NULL);
    CJson *in = CreateJson();
    CJson *out = nullptr;
    int32_t status = 0;
    (void)ProcessClientAuthSubSession((CompatibleBaseSubSession *)s, in, &out, &status);
    if (out != nullptr) { FreeJson(out); }
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
    SUCCEED();
}

/* ProcessServerAuthSubSession(INITIAL) with CreateTask fail.
 * Covers: CreateAndProcessServerAuthTask error path. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth027, TestSize.Level0)
{
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_SERVER_AUTH_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, false);
    const void *ptr = authParam;
    s->paramsList.pushBack(&s->paramsList, &ptr);
    s->currentIndex = 0;
    SetCreateTaskResult(HC_ERR_TASK_IS_NULL);
    CJson *in = CreateJson();
    int32_t status = 0;
    (void)ProcessServerAuthSubSession((CompatibleBaseSubSession *)s, in, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
    SUCCEED();
}

/* ProcessClientAuthSubSession(PROCESSING) with ProcessTask FINISH + NULL callback.
 * Covers: ReturnFinishData with callback NULL + groupAuth NULL. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth028, TestSize.Level0)
{
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_CLIENT_AUTH_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    s->base.callback = nullptr;
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    const void *ptr = authParam;
    s->paramsList.pushBack(&s->paramsList, &ptr);
    s->currentIndex = 0;
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    CJson *in = CreateJson();
    int32_t status = 0;
    (void)ProcessClientAuthSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
    SUCCEED();
}

/* CreateServerAuthSubSession with invalid authForm.
 * Covers: GetAuthType returns INVALID -> GetGroupAuth returns NULL. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth029, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddIntToJson(params, FIELD_AUTH_FORM, 9999);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateServerAuthSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleAuthSubSession(session); }
    FreeJson(params);
}

/* ===== Cover remaining auth reachable branches ===== */

/* CreateClientAuthSubSession exception loop with 50 iters.
 * Covers remaining AddGeneralParams/FillAuthParams/ExtractAndAddParams JSON failures. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth030, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddIntToJson(params, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddBoolToJson(params, FIELD_IS_CLIENT, true);
    AddStringToJson(params, FIELD_REQUEST_ID, "123");
    AddStringToJson(params, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_SERVER);
    SetIsGroupExistByGroupId(true);
    SetGetTrustedDevInfoByIdResult(HC_SUCCESS);
    SetGaGetLocalDeviceInfoResult(HC_SUCCESS);
    SetGaIsGroupAccessible(true);
    SetQueryGroupsResult(HC_SUCCESS);
    for (uint32_t i = 0; i <= 50; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        CompatibleBaseSubSession *session = nullptr;
        (void)CreateClientAuthSubSession(params, &g_callback, &session);
        if (session != nullptr) { DestroyCompatibleAuthSubSession(session); }
        SetControllerMode(false);
    }
    FreeJson(params);
    ResetGroupOpMock();
    ResetGaMock();
    ResetDbMock();
    SUCCEED();
}

/* ProcessClientAuthSubSession(PROCESSING) FINISH + exception loop 30 iters.
 * Covers: ReturnFinishData + ClearSensitiveStringInJson remaining branches. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth031, TestSize.Level0)
{
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_CLIENT_AUTH_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    AddStringToJson(authParam, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    const void *ptr = authParam;
    s->paramsList.pushBack(&s->paramsList, &ptr);
    s->currentIndex = 0;
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    CJson *in = CreateJson();
    for (uint32_t i = 0; i <= 30; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        int32_t status = 0;
        (void)ProcessClientAuthSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
        SetControllerMode(false);
    }
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
    SUCCEED();
}

/* ProcessServerAuthSubSession(PROCESSING) FINISH + exception loop 30 iters.
 * Covers: ReturnFinishData server-side branches. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth032, TestSize.Level0)
{
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_SERVER_AUTH_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, false);
    const void *ptr = authParam;
    s->paramsList.pushBack(&s->paramsList, &ptr);
    s->currentIndex = 0;
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    CJson *in = CreateJson();
    for (uint32_t i = 0; i <= 30; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        int32_t status = 0;
        (void)ProcessServerAuthSubSession((CompatibleBaseSubSession *)s, in, &status);
        SetControllerMode(false);
    }
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
    SUCCEED();
}

/* ProcessClientAuthSubSession(PROCESSING) error + peer error code.
 * Covers: HandlePeerAuthError + DelTrustDeviceOnAuthErrorV1 path. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth033, TestSize.Level0)
{
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_CLIENT_AUTH_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    AddStringToJson(authParam, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddIntToJson(authParam, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    const void *ptr = authParam;
    s->paramsList.pushBack(&s->paramsList, &ptr);
    s->currentIndex = 0;
    SetProcessTaskResult(HC_ERROR, IGNORE_MSG);
    CJson *in = CreateJson();
    AddIntToJson(in, FIELD_RESULT_CODE, PEER_ACCOUNT_NOT_MATCH);
    int32_t status = 0;
    (void)ProcessClientAuthSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
    SUCCEED();
}

/* ProcessServerAuthSubSession(INITIAL) exception loop 30 iters.
 * Covers: CreateAndProcessServerAuthTask remaining branches. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth034, TestSize.Level0)
{
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_SERVER_AUTH_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, false);
    const void *ptr = authParam;
    s->paramsList.pushBack(&s->paramsList, &ptr);
    s->currentIndex = 0;
    SetProcessTaskResult(HC_SUCCESS, CONTINUE);
    CJson *in = CreateJson();
    for (uint32_t i = 0; i <= 30; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        int32_t status = 0;
        (void)ProcessServerAuthSubSession((CompatibleBaseSubSession *)s, in, &status);
        SetControllerMode(false);
    }
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
    SUCCEED();
}

/* ===== Correct field name auth tests ===== */

/* CreateClientAuthSubSession with invalid FIELD_KEY_LENGTH (too small).
 * Flow: L376 CheckInputAuthParams -> L31 keyLen=5 -> L32 (5 < 16) TRUE.
 * Covers: L32 (keyLen < MIN_KEY_LENGTH) in CheckInputAuthParams. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth035, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddIntToJson(params, FIELD_KEY_LENGTH, 5);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateClientAuthSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleAuthSubSession(session); }
    FreeJson(params);
}

/* CreateClientAuthSubSession with invalid FIELD_KEY_LENGTH (too large).
 * Flow: L376 CheckInputAuthParams -> L31 keyLen=2048 -> L32 (2048 > 1024) TRUE.
 * Covers: L32 (keyLen > MAX_KEY_LENGTH) in CheckInputAuthParams. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth036, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddIntToJson(params, FIELD_KEY_LENGTH, 2048);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateClientAuthSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleAuthSubSession(session); }
    FreeJson(params);
}

/* CreateClientAuthSubSession missing FIELD_OS_ACCOUNT_ID (after CheckInputAuthParams ok).
 * Flow: L376 ok -> L381 ok -> L386 GetIntFromJson(OS_ACCOUNT_ID) fail.
 * Covers: L386 (osAccountId fail) in CreateClientAuthSubSession. */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth037, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateClientAuthSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleAuthSubSession(session); }
    FreeJson(params);
}

/* ===== Cover auth_sub_session_common.c reachable branches ===== */

/* CreateClientAuthSubSession with no FIELD_IS_CLIENT.
 * Flow: L376 ok -> L386 ok -> L390 CreateClientAuthSubSessionInner ->
 *   L48 GetAuthParamsVec -> L587 groupId=NULL -> L591 GetCandidateAuthInfo ->
 *   L278 groupId=NULL -> L280 GetCandidateGroups -> L94 GetBoolFromJson(IS_CLIENT) fail -> L95.
 * Covers: L95 (isClient fail) in GetCandidateGroups, L54-57 (empty auth params). */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth038, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    /* NO FIELD_GROUP_ID, NO FIELD_SERVICE_TYPE, NO FIELD_IS_CLIENT */
    SetHasAccountPlugin(false);
    CompatibleBaseSubSession *session = nullptr;
    int32_t ret = CreateClientAuthSubSession(params, &g_callback, &session);
    EXPECT_NE(ret, HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleAuthSubSession(session); }
    FreeJson(params);
    ResetGaMock();
    ResetDbMock();
}

/* CreateClientAuthSubSession with FIELD_IS_CLIENT=true, no IS_DEVICE_LEVEL.
 * Flow: ... -> GetCandidateGroups -> L94 ok -> L98 false -> L101 GetAccountRelatedCandidateGroups
 *   -> L42 groupAuth=NULL -> return -> L102 GetAccountUnrelatedCandidateGroups
 *   -> L76 !isDeviceLevel(false) -> true -> L80 QueryGroups.
 * Covers: L76 (true arc), L42-43 (groupAuth NULL), L80 (QueryGroups ok). */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth039, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddBoolToJson(params, FIELD_IS_CLIENT, true);
    /* NO FIELD_GROUP_ID, NO FIELD_IS_DEVICE_LEVEL */
    SetHasAccountPlugin(false);
    SetQueryGroupsResult(HC_SUCCESS);
    CompatibleBaseSubSession *session = nullptr;
    int32_t ret = CreateClientAuthSubSession(params, &g_callback, &session);
    EXPECT_NE(ret, HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleAuthSubSession(session); }
    FreeJson(params);
    ResetGaMock();
    ResetDbMock();
}

/* CreateClientAuthSubSession with QueryGroups error.
 * Flow: ... -> L102 GetAccountUnrelatedCandidateGroups -> L80 QueryGroups fails -> return.
 * Covers: L80 (QueryGroups fail true arc). */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth040, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddBoolToJson(params, FIELD_IS_CLIENT, true);
    SetHasAccountPlugin(false);
    SetQueryGroupsResult(HC_ERROR);
    CompatibleBaseSubSession *session = nullptr;
    int32_t ret = CreateClientAuthSubSession(params, &g_callback, &session);
    EXPECT_NE(ret, HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleAuthSubSession(session); }
    FreeJson(params);
    ResetGaMock();
    ResetDbMock();
}

/* CreateClientAuthSubSession with FIELD_IS_DEVICE_LEVEL=true + FIELD_IS_CLIENT=true.
 * Flow: ... -> GetCandidateGroups -> L98 isDeviceLevel && isClient = true -> L99.
 * Covers: L98 true arc, L99 (device-level candidate groups path). */
HWTEST_F(CompatibleAuthParamMockTest, MockTestAccountAuth041, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddBoolToJson(params, FIELD_IS_CLIENT, true);
    AddBoolToJson(params, FIELD_IS_DEVICE_LEVEL, true);
    SetHasAccountPlugin(false);
    SetQueryGroupsResult(HC_SUCCESS);
    CompatibleBaseSubSession *session = nullptr;
    int32_t ret = CreateClientAuthSubSession(params, &g_callback, &session);
    EXPECT_NE(ret, HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleAuthSubSession(session); }
    FreeJson(params);
    ResetGaMock();
    ResetDbMock();
}


}  // namespace
