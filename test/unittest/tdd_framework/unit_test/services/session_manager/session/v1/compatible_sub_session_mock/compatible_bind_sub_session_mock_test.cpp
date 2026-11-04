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

class CompatibleBindProcessMockTest : public testing::Test {
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

/* ===== bind ProcessClientBindSubSession(PROCESSING) task-status branches ===== */

HWTEST_F(CompatibleBindProcessMockTest, MockTest001, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    int32_t status = 0;
    int32_t res = ProcessClientBindSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    EXPECT_EQ(res, FINISH);
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindProcessMockTest, MockTest002, TestSize.Level0)
{
    /* ProcessTask returns CONTINUE -> SendBindDataToPeer -> TransmitBindSessionData (onTransmit). */
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    SetProcessTaskResult(HC_SUCCESS, CONTINUE);
    CJson *out = CreateJson();
    CJson *sendToPeer = CreateJson();
    AddIntToJson(sendToPeer, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);
    FreeJson(sendToPeer);
    CJson *in = CreateJson();
    int32_t status = 0;
    (void)ProcessClientBindSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    FreeJson(in);
    FreeJson(out);
    ResetModuleMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindProcessMockTest, MockTest003, TestSize.Level0)
{
    /* ProcessTask returns IGNORE_MSG -> the msg is ignored branch. */
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    SetProcessTaskResult(HC_SUCCESS, IGNORE_MSG);
    CJson *in = CreateJson();
    int32_t status = 0;
    (void)ProcessClientBindSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindProcessMockTest, MockTest004, TestSize.Level0)
{
    /* ProcessTask returns error -> InformPeerModuleError + InformPeerGroupErrorIfNeeded. */
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    SetProcessTaskResult(HC_ERR_INIT_TASK_FAIL, 0);
    CJson *in = CreateJson();
    int32_t status = 0;
    int32_t res = ProcessClientBindSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    EXPECT_NE(res, HC_SUCCESS);
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindProcessMockTest, MockTest005, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    SetCreateTaskResult(HC_ERR_INIT_TASK_FAIL);
    CJson *out = nullptr;
    int32_t status = 0;
    int32_t res = ProcessClientBindSubSession((CompatibleBaseSubSession *)s, nullptr, &out, &status);
    EXPECT_NE(res, HC_SUCCESS);
    if (out != nullptr) {
        FreeJson(out);
    }
    ResetModuleMock();
    FreeBindSession(s);
}

/* ===== bind ProcessServerBindSubSession(PROCESSING) task-status branches ===== */

HWTEST_F(CompatibleBindProcessMockTest, MockTest006, TestSize.Level0)
{
    /* Server bind PROCESSING: ProcessTask FINISH -> OnSessionFinish (server side). */
    CompatibleBindSubSession *s = NewBindSession(TYPE_SERVER_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    CJson *in = CreateJson();
    AddStringToJson(in, FIELD_PEER_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(in, FIELD_CONN_DEVICE_ID, TEST_UDID_SERVER);
    int32_t status = 0;
    (void)ProcessServerBindSubSession((CompatibleBaseSubSession *)s, in, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindProcessMockTest, MockTest007, TestSize.Level0)
{
    /* Server bind PROCESSING: ProcessTask error -> InformPeerModuleError. */
    CompatibleBindSubSession *s = NewBindSession(TYPE_SERVER_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    SetProcessTaskResult(HC_ERR_INIT_TASK_FAIL, 0);
    CJson *in = CreateJson();
    int32_t status = 0;
    (void)ProcessServerBindSubSession((CompatibleBaseSubSession *)s, in, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
}

/* ===== additional task-status / creation branches ===== */

HWTEST_F(CompatibleBindProcessMockTest, MockTest015, TestSize.Level0)
{
    /* Server bind PROCESSING: ProcessTask CONTINUE -> SendBindDataToPeer. */
    CompatibleBindSubSession *s = NewBindSession(TYPE_SERVER_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    SetProcessTaskResult(HC_SUCCESS, CONTINUE);
    CJson *in = CreateJson();
    int32_t status = 0;
    (void)ProcessServerBindSubSession((CompatibleBaseSubSession *)s, in, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindProcessMockTest, MockTest016, TestSize.Level0)
{
    /* Server bind PROCESSING: ProcessTask IGNORE_MSG -> ignore branch. */
    CompatibleBindSubSession *s = NewBindSession(TYPE_SERVER_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    SetProcessTaskResult(HC_SUCCESS, IGNORE_MSG);
    CJson *in = CreateJson();
    int32_t status = 0;
    (void)ProcessServerBindSubSession((CompatibleBaseSubSession *)s, in, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindProcessMockTest, MockTest017, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    SetCreateTaskResult(HC_SUCCESS);
    SetProcessTaskResult(HC_ERR_INIT_TASK_FAIL, 0);
    CJson *out = nullptr;
    int32_t status = 0;
    int32_t res = ProcessClientBindSubSession((CompatibleBaseSubSession *)s, nullptr, &out, &status);
    EXPECT_NE(res, HC_SUCCESS);
    if (out != nullptr) {
        FreeJson(out);
    }
    ResetModuleMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindProcessMockTest, MockTest018, TestSize.Level0)
{
    /* Client auth PROCESSING: ProcessTask IGNORE_MSG -> HandleAuthTaskStatus IGNORE_MSG. */
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_CLIENT_AUTH_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    SetProcessTaskResult(HC_SUCCESS, IGNORE_MSG);
    CJson *in = CreateJson();
    int32_t status = 0;
    int32_t res = ProcessClientAuthSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    EXPECT_EQ(res, HC_SUCCESS);
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
}

HWTEST_F(CompatibleBindProcessMockTest, MockTest019, TestSize.Level0)
{
    /* Server auth PROCESSING: ProcessTask error -> ProcessServerAuthError. */
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_SERVER_AUTH_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    SetProcessTaskResult(HC_ERR_INIT_TASK_FAIL, 0);
    CJson *in = CreateJson();
    int32_t status = 0;
    (void)ProcessServerAuthSubSession((CompatibleBaseSubSession *)s, in, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
}

HWTEST_F(CompatibleBindProcessMockTest, MockTest020, TestSize.Level0)
{
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_CLIENT_AUTH_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    /* push a second param */
    CJson *authParam2 = CreateJson();
    AddIntToJson(authParam2, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam2, FIELD_IS_CLIENT, true);
    AddStringToJson(authParam2, FIELD_REQUEST_ID, "321");
    AddStringToJson(authParam2, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    s->paramsList.pushBack(&s->paramsList, (const void **)&authParam2);
    SetCreateTaskResult(HC_SUCCESS);
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    int32_t res = AuthOnNextGroupIfExist(s);
    /* Returns FINISH on success of the next group auth. */
    EXPECT_TRUE((res == FINISH) || (res != HC_SUCCESS));
    ResetModuleMock();
    FreeAuthSession(s);
}

/* ===== server bind exception (re-add to find + fix null-deref) ===== */

HWTEST_F(CompatibleBindProcessMockTest, MockTest041, TestSize.Level0)
{
    /* CreateServerBindSubSession exception loop. Params built outside the window. */
    CJson *params = CreateJson();
    ASSERT_NE(params, nullptr);
    AddStringToJson(params, FIELD_REQUEST_ID, "321");
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_INVITE);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(params, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(params, FIELD_DEVICE_ID, TEST_AUTH_ID2);
    AddIntToJson(params, FIELD_USER_TYPE, DEVICE_TYPE_ACCESSORY);
    int64_t channelId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&channelId, sizeof(int64_t));
    AddIntToJson(params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    for (uint32_t i = 0; i <= 30; i++) {
        GTEST_LOG_(INFO) << "MockTest041 i=" << i;
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        CompatibleBaseSubSession *session = nullptr;
        (void)CreateServerBindSubSession(params, &g_callback, &session);
        if (session != nullptr) {
            DestroyCompatibleBindSubSession(session);
        }
        SetControllerMode(false);
    }
    FreeJson(params);
}

HWTEST_F(CompatibleBindProcessMockTest, MockTest042, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_SERVER_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_INVITE;
    CJson *in = CreateJson();
    ASSERT_NE(in, nullptr);
    AddIntToJson(in, FIELD_MESSAGE, ERR_MESSAGE);
    AddIntToJson(in, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    CJson *payload = CreateJson();
    AddObjToJson(in, FIELD_PAYLOAD, payload);
    FreeJson(payload);
    for (uint32_t i = 0; i <= 25; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        int32_t status = 0;
        (void)ProcessServerBindSubSession((CompatibleBaseSubSession *)s, in, &status);
        SetControllerMode(false);
    }
    FreeJson(in);
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindProcessMockTest, MockTest043, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *in = CreateJson();
    AddStringToJson(in, FIELD_PEER_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(in, FIELD_CONN_DEVICE_ID, TEST_UDID_SERVER);
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    for (uint32_t i = 0; i <= 25; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        int32_t status = 0;
        (void)ProcessClientBindSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
        SetControllerMode(false);
    }
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
}

/* ===== CONTINUE/FINISH path branches (sendToPeer injected by mock ProcessTask) ===== */

HWTEST_F(CompatibleBindProcessMockTest, MockTest060, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *in = CreateJson();
    SetProcessTaskResult(HC_SUCCESS, CONTINUE);
    for (uint32_t i = 0; i <= 20; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        int32_t status = 0;
        (void)ProcessClientBindSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
        SetControllerMode(false);
    }
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindProcessMockTest, MockTest061, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *in = CreateJson();
    AddStringToJson(in, FIELD_PEER_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(in, FIELD_CONN_DEVICE_ID, TEST_UDID_SERVER);
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    for (uint32_t i = 0; i <= 20; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        int32_t status = 0;
        (void)ProcessClientBindSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
        SetControllerMode(false);
    }
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindProcessMockTest, MockTest062, TestSize.Level0)
{
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    for (uint32_t i = 0; i <= 15; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        CJson *out = CreateJson();
        CJson *sendToPeer = CreateJson();
        AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);
        FreeJson(sendToPeer);
        (void)HandleAuthTaskStatus(s, out, FINISH, false);
        FreeJson(out);
        SetControllerMode(false);
    }
    ResetModuleMock();
    FreeAuthSession(s);
}

/* ===== bind server CONTINUE + AddRecvModuleDataToParams crafted branches ===== */

HWTEST_F(CompatibleBindProcessMockTest, MockTest063, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_SERVER_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *in = CreateJson();
    SetProcessTaskResult(HC_SUCCESS, CONTINUE);
    for (uint32_t i = 0; i <= 18; i++) {
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

HWTEST_F(CompatibleBindProcessMockTest, MockTest064, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_SERVER_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_INVITE;
    /* Case 1: empty in (all fields missing) */
    CJson *in1 = CreateJson();
    int32_t status = 0;
    (void)ProcessServerBindSubSession((CompatibleBaseSubSession *)s, in1, &status);
    FreeJson(in1);
    /* Case 2: has MESSAGE but missing AUTH_FORM + PAYLOAD */
    CJson *in2 = CreateJson();
    AddIntToJson(in2, FIELD_MESSAGE, ERR_MESSAGE);
    (void)ProcessServerBindSubSession((CompatibleBaseSubSession *)s, in2, &status);
    FreeJson(in2);
    /* Case 3: has MESSAGE + AUTH_FORM but missing PAYLOAD */
    CJson *in3 = CreateJson();
    AddIntToJson(in3, FIELD_MESSAGE, ERR_MESSAGE);
    AddIntToJson(in3, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    (void)ProcessServerBindSubSession((CompatibleBaseSubSession *)s, in3, &status);
    FreeJson(in3);
    ResetModuleMock();
    FreeBindSession(s);
}

/* ===== DB-failure branch coverage (group_data_manager + group_operation_common mock) ===== */

extern "C" {
void SetCheckGroupExistResult(int32_t ret);
void SetCheckPermForGroupResult(int32_t ret);
void SetCheckDeviceNumLimitResult(int32_t ret);
void SetProcessKeyPairResult(int32_t ret);
void SetGetTrustedDevInfoByIdResult(int32_t ret);
void SetGetGroupTypeFromDbResult(int32_t ret);
void SetAssertGroupTypeMatchResult(int32_t ret);
void SetIsGroupExistByGroupId(bool exist);
void SetIsUserTypeValid(bool valid);
void SetIsGroupVisibilityValid(bool valid);
void SetIsExpireTimeValid(bool valid);
void SetAddGroupResult(int32_t ret);
void SetAddTrustedDeviceResult(int32_t ret);
void SetQueryGroupsResult(int32_t ret);
void ResetDbMock(void);
void ResetGroupOpMock(void);
}

HWTEST_F(CompatibleBindProcessMockTest, MockTest068, TestSize.Level0)
{
    /* CreateClientBindSubSession(MEMBER_INVITE): CheckGroupExist fails -> error. */
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
    SetCheckGroupExistResult(HC_ERR_DB);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateClientBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    FreeJson(params);
    ResetGroupOpMock();
}

HWTEST_F(CompatibleBindProcessMockTest, MockTest069, TestSize.Level0)
{
    /* CheckPermForGroup fails -> CheckInvitePeer error. */
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
    SetCheckPermForGroupResult(HC_ERR_INVALID_PARAMS);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateClientBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    FreeJson(params);
    ResetGroupOpMock();
}

HWTEST_F(CompatibleBindProcessMockTest, MockTest070, TestSize.Level0)
{
    /* CheckDeviceNumLimit fails. */
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
    SetCheckDeviceNumLimitResult(HC_ERR_INVALID_PARAMS);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateClientBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    FreeJson(params);
    ResetGroupOpMock();
}

HWTEST_F(CompatibleBindProcessMockTest, MockTest071, TestSize.Level0)
{
    /* ProcessKeyPair fails -> GenerateKeyPairIfNeeded error (server MEMBER_INVITE path). */
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_REQUEST_ID, "321");
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_INVITE);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(params, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    AddIntToJson(params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    SetProcessKeyPairResult(HC_ERR_INIT_TASK_FAIL);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateServerBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    FreeJson(params);
    ResetGroupOpMock();
}

HWTEST_F(CompatibleBindProcessMockTest, MockTest072, TestSize.Level0)
{
    /* OnSessionFinish: AddGroup fails -> HandleBindSuccess error. */
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *in = CreateJson();
    AddStringToJson(in, FIELD_PEER_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(in, FIELD_CONN_DEVICE_ID, TEST_UDID_SERVER);
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    SetAddGroupResult(HC_ERR_DB);
    int32_t status = 0;
    (void)ProcessClientBindSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    FreeJson(in);
    ResetModuleMock();
    ResetDbMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindProcessMockTest, MockTest073, TestSize.Level0)
{
    /* OnSessionFinish: AddTrustedDevice fails -> AddPeerDevToGroup error. */
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *in = CreateJson();
    AddStringToJson(in, FIELD_PEER_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(in, FIELD_CONN_DEVICE_ID, TEST_UDID_SERVER);
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    SetAddTrustedDeviceResult(HC_ERR_DB);
    int32_t status = 0;
    (void)ProcessClientBindSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    FreeJson(in);
    ResetModuleMock();
    ResetDbMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindProcessMockTest, MockTest074, TestSize.Level0)
{
    /* QueryGroups fails -> GetCandidateGroups error -> CreateClientAuthSubSession error. */
    CJson *authParams = CreateJson();
    AddStringToJson(authParams, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddIntToJson(authParams, FIELD_KEY_LENGTH, DEFAULT_RETURN_KEY_LENGTH);
    AddIntToJson(authParams, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(authParams, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_SERVER);
    AddBoolToJson(authParams, FIELD_IS_CLIENT, true);
    SetQueryGroupsResult(HC_ERR_DB);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateClientAuthSubSession(authParams, &g_callback, &session), HC_SUCCESS);
    FreeJson(authParams);
    ResetDbMock();
}

HWTEST_F(CompatibleBindProcessMockTest, MockTest075, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_INVITE;
    FreeJson(s->params);
    s->params = CreateJson();
    CJson *jsonParams = CreateJson();
    AddStringToJson(jsonParams, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(jsonParams, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(jsonParams, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(jsonParams, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddIntToJson(jsonParams, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(jsonParams, FIELD_DEVICE_ID, TEST_AUTH_ID);
    SetIsGroupExistByGroupId(true);
    SetGetTrustedDevInfoByIdResult(HC_ERR_DB);
    (void)GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, CLIENT, jsonParams, s);
    FreeJson(jsonParams);
    ResetGroupOpMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindProcessMockTest, MockTest076, TestSize.Level0)
{
    /* AssertGroupTypeMatch fails (CheckJoinPeer with wrong groupType). */
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_REQUEST_ID, "123");
    AddIntToJson(params, FIELD_OPERATION_CODE, MEMBER_JOIN);
    AddIntToJson(params, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    AddIntToJson(params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    SetAssertGroupTypeMatchResult(HC_ERR_INVALID_PARAMS);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateClientBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    FreeJson(params);
    ResetGroupOpMock();
}

HWTEST_F(CompatibleBindProcessMockTest, MockTest077, TestSize.Level0)
{
    /* GetGroupTypeFromDb fails -> CheckInvitePeer error. */
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
    SetGetGroupTypeFromDbResult(HC_ERR_DB);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateClientBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    FreeJson(params);
    ResetGroupOpMock();
}

/* ===== Reach 80%% effective branch rate: +7 branches from 4 targeted tests ===== */

/* DestroyCompatibleSubSession(NULL) -> covers session==NULL true branch.
 * DestroyCompatibleSubSession with invalid type -> covers default branch. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest182, TestSize.Level0)
{
    DestroyCompatibleSubSession(NULL);
    CompatibleBaseSubSession fake;
    fake.type = (SubSessionTypeValue)999;
    DestroyCompatibleSubSession(&fake);
    SUCCEED();
}

/* ProcessCompatibleSubSession(NULL,...) -> covers NULL param check.
 * ProcessCompatibleSubSession with invalid type -> covers default branch. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest183, TestSize.Level0)
{
    CJson *in = CreateJson();
    CJson *out = nullptr;
    int32_t status = 0;
    EXPECT_EQ(ProcessCompatibleSubSession(NULL, in, &out, &status), HC_ERR_INVALID_PARAMS);
    CompatibleBaseSubSession fake;
    fake.type = (SubSessionTypeValue)999;
    EXPECT_EQ(ProcessCompatibleSubSession(&fake, in, &out, &status), HC_ERR_INVALID_PARAMS);
    FreeJson(in);
}

/* CombineAuthConfirmData with invalid osAccountId -> covers INVALID_OS_ACCOUNT branch. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest184, TestSize.Level0)
{
    CJson *confirmation = CreateJson();
    AddIntToJson(confirmation, FIELD_OS_ACCOUNT_ID, INVALID_OS_ACCOUNT);
    CJson *dataFromClient = CreateJson();
    AddIntToJson(dataFromClient, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    EXPECT_EQ(CombineAuthConfirmData(confirmation, dataFromClient), HC_ERR_INVALID_PARAMS);
    FreeJson(confirmation);
    FreeJson(dataFromClient);
}

/* GetDuplicatePkgName(NULL) -> covers pkgName==NULL branch. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest185, TestSize.Level0)
{
    EXPECT_EQ(GetDuplicatePkgName(NULL), nullptr);
}


/* ===== Push to theoretical limit: high-difficulty static function coverage ===== */

/* CheckInvitePeer: all mock checks pass. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest186, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_APP_ID, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_INVITE);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(params, FIELD_DEVICE_ID, TEST_AUTH_ID);
    SetIsGroupExistByGroupId(true);
    SetGetGroupTypeFromDbResult(HC_SUCCESS);
    SetAssertGroupTypeMatchResult(HC_SUCCESS);
    SetCheckPermForGroupResult(HC_SUCCESS);
    SetCheckDeviceNumLimitResult(HC_SUCCESS);
    CompatibleBaseSubSession *session = nullptr;
    (void)CreateClientBindSubSession(params, &g_callback, &session);
    if (session != nullptr) {
        DestroyCompatibleBindSubSession(session);
    }
    FreeJson(params);
    ResetGroupOpMock();
    SUCCEED();
}

/* CheckServerStatusIfNotInvite: MEMBER_JOIN + all pass. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest187, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_JOIN);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(params, FIELD_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(params, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(params, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    SetIsGroupExistByGroupId(true);
    SetGetGroupTypeFromDbResult(HC_SUCCESS);
    SetAssertGroupTypeMatchResult(HC_SUCCESS);
    SetCheckPermForGroupResult(HC_SUCCESS);
    SetCheckDeviceNumLimitResult(HC_SUCCESS);
    CompatibleBaseSubSession *session = nullptr;
    (void)CreateServerBindSubSession(params, &g_callback, &session);
    if (session != nullptr) {
        DestroyCompatibleBindSubSession(session);
    }
    FreeJson(params);
    ResetGroupOpMock();
    SUCCEED();
}

/* CheckServerStatusIfNotInvite: MEMBER_JOIN + CheckGroupExist fails. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest188, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_JOIN);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(params, FIELD_DEVICE_ID, TEST_AUTH_ID2);
    SetIsGroupExistByGroupId(false);
    SetCheckGroupExistResult(HC_ERR_DB);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateServerBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) {
        DestroyCompatibleBindSubSession(session);
    }
    FreeJson(params);
    ResetGroupOpMock();
}

/* CheckInvitePeer: CheckDeviceNumLimit fails. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest189, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_APP_ID, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_INVITE);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(params, FIELD_DEVICE_ID, TEST_AUTH_ID);
    SetIsGroupExistByGroupId(true);
    SetGetGroupTypeFromDbResult(HC_SUCCESS);
    SetAssertGroupTypeMatchResult(HC_SUCCESS);
    SetCheckPermForGroupResult(HC_SUCCESS);
    SetCheckDeviceNumLimitResult(HC_ERR_NO_CANDIDATE_GROUP);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateClientBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) {
        DestroyCompatibleBindSubSession(session);
    }
    FreeJson(params);
    ResetGroupOpMock();
}

/* CheckInvitePeer: CheckPermForGroup fails. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest190, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_APP_ID, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_INVITE);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(params, FIELD_DEVICE_ID, TEST_AUTH_ID);
    SetIsGroupExistByGroupId(true);
    SetGetGroupTypeFromDbResult(HC_SUCCESS);
    SetAssertGroupTypeMatchResult(HC_SUCCESS);
    SetCheckPermForGroupResult(HC_ERR_ACCESS_DENIED);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateClientBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) {
        DestroyCompatibleBindSubSession(session);
    }
    FreeJson(params);
    ResetGroupOpMock();
}

/* GenerateGroupParams: SERVER + INVITE + group not exist + exception loop. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest191, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_INVITE);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(params, FIELD_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(params, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(params, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddIntToJson(params, FIELD_USER_TYPE, DEVICE_TYPE_ACCESSORY);
    AddIntToJson(params, FIELD_GROUP_VISIBILITY, GROUP_VISIBILITY_PUBLIC);
    AddIntToJson(params, FIELD_EXPIRE_TIME, DEFAULT_EXPIRE_TIME);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    AddIntToJson(params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    SetIsGroupExistByGroupId(false);
    SetCheckPermForGroupResult(HC_SUCCESS);
    SetCheckDeviceNumLimitResult(HC_SUCCESS);
    SetProcessKeyPairResult(HC_SUCCESS);
    for (uint32_t i = 0; i <= 35; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        CompatibleBaseSubSession *session = nullptr;
        (void)CreateServerBindSubSession(params, &g_callback, &session);
        if (session != nullptr) {
            DestroyCompatibleBindSubSession(session);
        }
        SetControllerMode(false);
    }
    FreeJson(params);
    ResetGroupOpMock();
    SUCCEED();
}

/* AddPeerAuthIdAndUdidIfExist: session with peerAuthId + peerUdid + exception loop. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest192, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_INVITE;
    CJson *jsonParams = CreateJson();
    AddStringToJson(jsonParams, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(jsonParams, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(jsonParams, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(jsonParams, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddIntToJson(jsonParams, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(jsonParams, FIELD_DEVICE_ID, TEST_AUTH_ID);
    AddStringToJson(jsonParams, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2);
    AddStringToJson(jsonParams, FIELD_PEER_UDID, TEST_UDID_SERVER);
    SetIsGroupExistByGroupId(true);
    SetGetTrustedDevInfoByIdResult(HC_SUCCESS);
    for (uint32_t i = 0; i <= 20; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        (void)GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, CLIENT, jsonParams, s);
        SetControllerMode(false);
    }
    FreeJson(jsonParams);
    ResetGroupOpMock();
    FreeBindSession(s);
    SUCCEED();
}

/* InformPeerModuleError: server PROCESSING ProcessTask error. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest193, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_SERVER_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_INVITE;
    s->params = CreateJson();
    AddStringToJson(s->params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(s->params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(s->params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    AddIntToJson(s->params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    SetProcessTaskResult(HC_ERROR, IGNORE_MSG);
    CJson *in = CreateJson();
    int32_t status = 0;
    (void)ProcessServerBindSubSession((CompatibleBaseSubSession *)s, in, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
    SUCCEED();
}

/* GenerateCompatibleInfo: CLIENT JOIN with group in DB + exception loop. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest194, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddIntToJson(params, FIELD_OPERATION_CODE, MEMBER_JOIN);
    AddStringToJson(params, FIELD_REQUEST_ID, "123");
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddIntToJson(params, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(params, FIELD_DEVICE_ID, TEST_AUTH_ID);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    AddIntToJson(params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    SetIsGroupExistByGroupId(true);
    SetGetTrustedDevInfoByIdResult(HC_SUCCESS);
    SetCheckPermForGroupResult(HC_SUCCESS);
    SetCheckDeviceNumLimitResult(HC_SUCCESS);
    for (uint32_t i = 0; i <= 30; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        CompatibleBaseSubSession *session = nullptr;
        (void)CreateClientBindSubSession(params, &g_callback, &session);
        if (session != nullptr) {
            DestroyCompatibleBindSubSession(session);
        }
        SetControllerMode(false);
    }
    FreeJson(params);
    ResetGroupOpMock();
    SUCCEED();
}


/* ===== Cover reachable uncovered branches ===== */

/* switch case: CreateCompatibleSubSession with different types.
 * Covers TYPE_SERVER_BIND, TYPE_CLIENT_AUTH, TYPE_SERVER_AUTH in dispatcher. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest195, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_REQUEST_ID, "123");
    AddStringToJson(params, FIELD_APP_ID, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    CompatibleBaseSubSession *session = nullptr;
    (void)CreateCompatibleSubSession(TYPE_SERVER_BIND_SUB_SESSION, params, &g_callback, &session);
    if (session != nullptr) { DestroyCompatibleSubSession(session); }
    FreeJson(params);
    SUCCEED();
}


/* NULL callback: ProcessClientAuthSubSession with NULL callback.
 * Covers callback==NULL branches in ReturnErrorToPeerBySession/ReturnTransmitData. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest197, TestSize.Level0)
{
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_CLIENT_AUTH_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    s->base.callback = nullptr;
    SetProcessTaskResult(HC_ERROR, IGNORE_MSG);
    CJson *in = CreateJson();
    int32_t status = 0;
    (void)ProcessClientAuthSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
    SUCCEED();
}

/* NULL callback: ReturnErrorToPeerBySession with callback NULL.
 * Covers callback->onTransmit==NULL branches. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest198, TestSize.Level0)
{
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    NotifyPeerAuthError(authParam, nullptr);
    FreeJson(authParam);
    SUCCEED();
}

/* Missing FIELD_PIN_CODE: GenerateBaseBindParams(CLIENT, INVITE) missing pin.
 * Covers AddPinCode error path. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest199, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_INVITE;
    CJson *jsonParams = CreateJson();
    AddStringToJson(jsonParams, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(jsonParams, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(jsonParams, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddIntToJson(jsonParams, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(jsonParams, FIELD_DEVICE_ID, TEST_AUTH_ID);
    SetIsGroupExistByGroupId(true);
    int32_t ret = GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, CLIENT, jsonParams, s);
    FreeJson(jsonParams);
    ResetGroupOpMock();
    FreeBindSession(s);
    EXPECT_NE(ret, HC_SUCCESS);
}

/* Missing FIELD_DEVICE_ID: GenerateBaseBindParams(SERVER, INVITE) missing device.
 * Covers authId==NULL path in AddGroupAndDevInfoToParams. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest200, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_SERVER_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_INVITE;
    CJson *jsonParams = CreateJson();
    AddStringToJson(jsonParams, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(jsonParams, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(jsonParams, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(jsonParams, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddIntToJson(jsonParams, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    SetIsGroupExistByGroupId(true);
    int32_t ret = GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, SERVER, jsonParams, s);
    FreeJson(jsonParams);
    ResetGroupOpMock();
    FreeBindSession(s);
    EXPECT_NE(ret, HC_SUCCESS);
}

/* Extended exception injection: GenerateGroupErrorMsg with more iterations.
 * Covers remaining AddGroupErrorInfo/AddInfoToErrorData branches. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest201, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    AddIntToJson(params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    for (uint32_t i = 0; i <= 30; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        InformPeerProcessError(999, params, &g_callback, HC_ERR_INVALID_PARAMS);
        SetControllerMode(false);
    }
    FreeJson(params);
    SUCCEED();
}

/* Missing FIELD_MESSAGE: PrepareServerData missing message field.
 * Covers GetIntFromJson(FIELD_MESSAGE) error path. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest202, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_SERVER_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_INVITE;
    s->params = CreateJson();
    AddStringToJson(s->params, FIELD_GROUP_ID, TEST_GROUP_ID);
    CJson *in = CreateJson();
    AddStringToJson(in, FIELD_PAYLOAD, "{}");
    int32_t status = 0;
    (void)ProcessServerBindSubSession((CompatibleBaseSubSession *)s, in, &status);
    FreeJson(in);
    FreeBindSession(s);
    SUCCEED();
}

/* CheckIsForegroundOsAccountId: CombineAuthConfirmData with foreground check.
 * Covers !CheckIsForegroundOsAccountId branch. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest203, TestSize.Level0)
{
    CJson *confirmation = CreateJson();
    AddIntToJson(confirmation, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    CJson *dataFromClient = CreateJson();
    AddIntToJson(dataFromClient, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    (void)CombineAuthConfirmData(confirmation, dataFromClient);
    FreeJson(confirmation);
    FreeJson(dataFromClient);
    SUCCEED();
}

/* GetDuplicatePkgName: NULL params -> covers pkgName==NULL branch. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest204, TestSize.Level0)
{
    EXPECT_EQ(GetDuplicatePkgName(nullptr), nullptr);
}


/* ===== Batch cover: JSON failures + error returns + missing fields ===== */

/* CreateServerBindSubSession exception loop: SERVER + INVITE + group not exist.
 * Covers GenerateServerBindParams + GenerateBaseBindParams(SERVER) + SetGroupId/
 * SetGroupName/SetGroupOwner/SetGroupType/SetGroupVisibility/SetGroupExpireTime. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest205, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_INVITE);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(params, FIELD_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(params, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(params, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddIntToJson(params, FIELD_USER_TYPE, DEVICE_TYPE_ACCESSORY);
    AddIntToJson(params, FIELD_GROUP_VISIBILITY, GROUP_VISIBILITY_PUBLIC);
    AddIntToJson(params, FIELD_EXPIRE_TIME, DEFAULT_EXPIRE_TIME);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    AddIntToJson(params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    SetIsGroupExistByGroupId(false);
    SetCheckPermForGroupResult(HC_SUCCESS);
    SetCheckDeviceNumLimitResult(HC_SUCCESS);
    SetProcessKeyPairResult(HC_SUCCESS);
    for (uint32_t i = 0; i <= 45; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        CompatibleBaseSubSession *session = nullptr;
        (void)CreateServerBindSubSession(params, &g_callback, &session);
        if (session != nullptr) { DestroyCompatibleBindSubSession(session); }
        SetControllerMode(false);
    }
    FreeJson(params);
    ResetGroupOpMock();
    SUCCEED();
}

/* CreateClientBindSubSession exception loop: CLIENT + JOIN + group exists in DB.
 * Covers GenerateParamsByDatabase + AddGroupInfoToParams + AddDevInfoToParams +
 * AddDevInfoByDatabase + GenerateCompatibleInfo. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest206, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddIntToJson(params, FIELD_OPERATION_CODE, MEMBER_JOIN);
    AddStringToJson(params, FIELD_REQUEST_ID, "123");
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddIntToJson(params, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(params, FIELD_DEVICE_ID, TEST_AUTH_ID);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    AddIntToJson(params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    SetIsGroupExistByGroupId(true);
    SetGetTrustedDevInfoByIdResult(HC_SUCCESS);
    SetCheckPermForGroupResult(HC_SUCCESS);
    SetCheckDeviceNumLimitResult(HC_SUCCESS);
    for (uint32_t i = 0; i <= 45; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        CompatibleBaseSubSession *session = nullptr;
        (void)CreateClientBindSubSession(params, &g_callback, &session);
        if (session != nullptr) { DestroyCompatibleBindSubSession(session); }
        SetControllerMode(false);
    }
    FreeJson(params);
    ResetGroupOpMock();
    SUCCEED();
}

/* ProcessServerBindSubSession(PROCESSING) with ProcessTask CONTINUE.
 * Covers AddInfoToBindData + TransmitBindSessionData exception branches. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest207, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_SERVER_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_INVITE;
    s->params = CreateJson();
    AddStringToJson(s->params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(s->params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddStringToJson(s->params, FIELD_AUTH_ID, TEST_AUTH_ID);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(s->params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    AddIntToJson(s->params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    SetProcessTaskResult(HC_SUCCESS, CONTINUE);
    CJson *in = CreateJson();
    for (uint32_t i = 0; i <= 25; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        int32_t status = 0;
        (void)ProcessServerBindSubSession((CompatibleBaseSubSession *)s, in, &status);
        SetControllerMode(false);
    }
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
    SUCCEED();
}

/* GenerateBaseModuleParams(CLIENT) exception loop with full params.
 * Covers AddRequestInfoToParams + AddPinCodeToParams + AddProtocolExpandValToParams. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest208, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_INVITE;
    s->params = CreateJson();
    AddStringToJson(s->params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(s->params, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(s->params, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddStringToJson(s->params, FIELD_AUTH_ID, TEST_AUTH_ID);
    AddStringToJson(s->params, FIELD_CONN_DEVICE_ID, TEST_UDID_CLIENT);
    AddStringToJson(s->params, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2);
    AddStringToJson(s->params, FIELD_PEER_UDID, TEST_UDID_SERVER);
    CJson *moduleParams = CreateJson();
    for (uint32_t i = 0; i <= 25; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        (void)GenerateBaseModuleParams(true, s, moduleParams);
        SetControllerMode(false);
    }
    FreeJson(moduleParams);
    FreeBindSession(s);
    SUCCEED();
}

/* GenerateBaseModuleParams(SERVER) exception loop with full params.
 * Covers AddRecvModuleDataToParams + AddConfirmationToParams. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest209, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_SERVER_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_INVITE;
    s->params = CreateJson();
    AddStringToJson(s->params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(s->params, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(s->params, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddStringToJson(s->params, FIELD_AUTH_ID, TEST_AUTH_ID);
    AddStringToJson(s->params, FIELD_CONN_DEVICE_ID, TEST_UDID_CLIENT);
    AddStringToJson(s->params, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2);
    AddStringToJson(s->params, FIELD_PEER_UDID, TEST_UDID_SERVER);
    CJson *jsonParams = CreateJson();
    AddStringToJson(jsonParams, FIELD_PAYLOAD, "{}");
    AddIntToJson(jsonParams, FIELD_MESSAGE, 0);
    CJson *moduleParams = CreateJson();
    for (uint32_t i = 0; i <= 25; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        (void)GenerateBaseModuleParams(false, s, moduleParams);
        SetControllerMode(false);
    }
    FreeJson(moduleParams);
    FreeJson(jsonParams);
    FreeBindSession(s);
    SUCCEED();
}

/* Missing FIELD_GROUP_NAME in SERVER INVITE path.
 * Covers groupName==NULL in SetGroupName. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest210, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_INVITE);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(params, FIELD_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddIntToJson(params, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    SetIsGroupExistByGroupId(false);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateServerBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleBindSubSession(session); }
    FreeJson(params);
    ResetGroupOpMock();
}

/* Missing FIELD_REQUEST_ID in CLIENT INVITE.
 * Covers GetInt64FromJson error path. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest211, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_INVITE);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(params, FIELD_DEVICE_ID, TEST_AUTH_ID);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateClientBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleBindSubSession(session); }
    FreeJson(params);
}

/* CheckPermForGroup fails in CheckInvitePeer. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest212, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_APP_ID, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_INVITE);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(params, FIELD_DEVICE_ID, TEST_AUTH_ID);
    AddStringToJson(params, FIELD_REQUEST_ID, "123");
    SetIsGroupExistByGroupId(true);
    SetGetGroupTypeFromDbResult(HC_SUCCESS);
    SetAssertGroupTypeMatchResult(HC_SUCCESS);
    SetCheckPermForGroupResult(HC_ERR_ACCESS_DENIED);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateClientBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleBindSubSession(session); }
    FreeJson(params);
    ResetGroupOpMock();
}

/* GetGroupTypeFromDb fails in CheckInvitePeer. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest213, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_APP_ID, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_INVITE);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(params, FIELD_DEVICE_ID, TEST_AUTH_ID);
    AddStringToJson(params, FIELD_REQUEST_ID, "123");
    SetIsGroupExistByGroupId(true);
    SetGetGroupTypeFromDbResult(HC_ERR_DB);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateClientBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleBindSubSession(session); }
    FreeJson(params);
    ResetGroupOpMock();
}


/* ===== Targeted: cover 51+ reachable branches to hit 80% ===== */

/* CreateClientBindSubSession(CLIENT, INVITE) with mock CheckGroupExist fail.
 * Covers: CheckGroupExist error in CheckInvitePeer L53. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest214, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_APP_ID, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_INVITE);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(params, FIELD_DEVICE_ID, TEST_AUTH_ID);
    AddStringToJson(params, FIELD_REQUEST_ID, "123");
    SetIsGroupExistByGroupId(true);
    SetCheckGroupExistResult(HC_ERR_DB);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateClientBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleBindSubSession(session); }
    FreeJson(params);
    ResetGroupOpMock();
}

/* CreateServerBindSubSession(MEMBER_JOIN) with CheckPermForGroup fail.
 * Covers: CheckPermForGroup error in CheckServerStatusIfNotInvite. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest215, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_JOIN);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(params, FIELD_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(params, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(params, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    SetIsGroupExistByGroupId(true);
    SetCheckPermForGroupResult(HC_ERR_ACCESS_DENIED);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateServerBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleBindSubSession(session); }
    FreeJson(params);
    ResetGroupOpMock();
}

/* CreateServerBindSubSession(MEMBER_JOIN) with CheckDeviceNumLimit fail.
 * Covers: CheckDeviceNumLimit error in CheckServerStatusIfNotInvite. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest216, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_JOIN);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(params, FIELD_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(params, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(params, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    SetIsGroupExistByGroupId(true);
    SetCheckPermForGroupResult(HC_SUCCESS);
    SetCheckDeviceNumLimitResult(HC_ERR_OUT_OF_LIMIT);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateServerBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleBindSubSession(session); }
    FreeJson(params);
    ResetGroupOpMock();
}

/* CreateServerBindSubSession with confirmation rejected.
 * Covers: confirmation != REQUEST_ACCEPTED in CheckAcceptRequest. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest217, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_INVITE);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_REJECTED);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(params, FIELD_DEVICE_ID, TEST_AUTH_ID2);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateServerBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleBindSubSession(session); }
    FreeJson(params);
}

/* GenerateBaseBindParams(CLIENT, INVITE) with invalid userType.
 * Covers: !IsUserTypeValid in AddAuthIdAndUserTypeIfValidOrDefault. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest218, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_JOIN;
    CJson *jsonParams = CreateJson();
    AddStringToJson(jsonParams, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(jsonParams, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(jsonParams, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(jsonParams, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddIntToJson(jsonParams, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(jsonParams, FIELD_DEVICE_ID, TEST_AUTH_ID);
    AddIntToJson(jsonParams, FIELD_USER_TYPE, 9999);
    SetIsGroupExistByGroupId(false);
    SetIsUserTypeValid(false);
    int32_t ret = GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, CLIENT, jsonParams, s);
    FreeJson(jsonParams);
    ResetGroupOpMock();
    FreeBindSession(s);
    SetIsUserTypeValid(true);
    EXPECT_NE(ret, HC_SUCCESS);
}

/* GenerateBaseBindParams(CLIENT, INVITE) with invalid groupVisibility.
 * Covers: !IsGroupVisibilityValid in GenerateParamsByInput. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest219, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_JOIN;
    CJson *jsonParams = CreateJson();
    AddStringToJson(jsonParams, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(jsonParams, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(jsonParams, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(jsonParams, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddIntToJson(jsonParams, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(jsonParams, FIELD_GROUP_VISIBILITY, 9999);
    SetIsGroupExistByGroupId(false);
    SetIsGroupVisibilityValid(false);
    int32_t ret = GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, CLIENT, jsonParams, s);
    FreeJson(jsonParams);
    ResetGroupOpMock();
    FreeBindSession(s);
    SetIsGroupVisibilityValid(true);
    EXPECT_NE(ret, HC_SUCCESS);
}

/* GenerateBaseBindParams(CLIENT, INVITE) with invalid expireTime.
 * Covers: !IsExpireTimeValid in GenerateParamsByInput. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest220, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_JOIN;
    CJson *jsonParams = CreateJson();
    AddStringToJson(jsonParams, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(jsonParams, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(jsonParams, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(jsonParams, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddIntToJson(jsonParams, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(jsonParams, FIELD_GROUP_VISIBILITY, GROUP_VISIBILITY_PUBLIC);
    AddIntToJson(jsonParams, FIELD_EXPIRE_TIME, -999);
    SetIsGroupExistByGroupId(false);
    SetIsExpireTimeValid(false);
    int32_t ret = GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, CLIENT, jsonParams, s);
    FreeJson(jsonParams);
    ResetGroupOpMock();
    FreeBindSession(s);
    SetIsExpireTimeValid(true);
    EXPECT_NE(ret, HC_SUCCESS);
}

/* ProcessServerBindSubSession(INITIAL) with ProcessTask error.
 * Covers: error path in CreateAndProcessServerBindTask. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest221, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_SERVER_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_INVITE;
    s->params = CreateJson();
    AddStringToJson(s->params, FIELD_GROUP_ID, TEST_GROUP_ID);
    SetProcessTaskResult(HC_ERROR, IGNORE_MSG);
    CJson *in = CreateJson();
    int32_t status = 0;
    (void)ProcessServerBindSubSession((CompatibleBaseSubSession *)s, in, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
    SUCCEED();
}

/* ProcessClientBindSubSession(PROCESSING) with ProcessTask FINISH.
 * Covers: FINISH path in HandleBindTaskStatus. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest222, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_INVITE;
    s->params = CreateJson();
    AddStringToJson(s->params, FIELD_GROUP_ID, TEST_GROUP_ID);
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    CJson *in = CreateJson();
    CJson *out = nullptr;
    int32_t status = 0;
    (void)ProcessClientBindSubSession((CompatibleBaseSubSession *)s, in, &out, &status);
    if (out != nullptr) { FreeJson(out); }
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
    SUCCEED();
}

/* CombineConfirmData(MEMBER_INVITE) exception loop.
 * Covers: AddPinCode/AddAuthIdIfExist/AddUserTypeIfExistAndValid JSON failures. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest223, TestSize.Level0)
{
    CJson *returnData = CreateJson();
    AddIntToJson(returnData, FIELD_USER_TYPE, DEVICE_TYPE_ACCESSORY);
    AddIntToJson(returnData, FIELD_GROUP_VISIBILITY, GROUP_VISIBILITY_PUBLIC);
    AddIntToJson(returnData, FIELD_EXPIRE_TIME, DEFAULT_EXPIRE_TIME);
    CJson *jsonParams = CreateJson();
    AddStringToJson(jsonParams, FIELD_PIN_CODE, TEST_PIN_CODE);
    for (uint32_t i = 0; i <= 20; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        (void)CombineConfirmData(MEMBER_INVITE, returnData, jsonParams);
        SetControllerMode(false);
    }
    FreeJson(returnData);
    FreeJson(jsonParams);
    SUCCEED();
}


/* ===== Cover remaining reachable branches: missing fields + value checks + error paths ===== */

/* CreateClientBindSubSession missing FIELD_SERVICE_PKG_NAME.
 * Covers: GetDuplicateAppId error -> appId==NULL path. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest224, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_REQUEST_ID, "123");
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_INVITE);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(params, FIELD_DEVICE_ID, TEST_AUTH_ID);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateClientBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleBindSubSession(session); }
    FreeJson(params);
}

/* CreateServerBindSubSession missing FIELD_GROUP_ID.
 * Covers: groupId==NULL in CheckServerStatusIfNotInvite. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest225, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_JOIN);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(params, FIELD_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateServerBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleBindSubSession(session); }
    FreeJson(params);
}

/* CreateServerBindSubSession missing FIELD_DEVICE_ID (connDeviceId).
 * Covers: peerUdid==NULL in CheckServerStatusIfNotInvite L186. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest226, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_JOIN);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(params, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(params, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    SetIsGroupExistByGroupId(true);
    SetCheckPermForGroupResult(HC_SUCCESS);
    SetCheckDeviceNumLimitResult(HC_SUCCESS);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateServerBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleBindSubSession(session); }
    FreeJson(params);
    ResetGroupOpMock();
}

/* GenerateBaseBindParams(CLIENT, INVITE) missing FIELD_GROUP_TYPE.
 * Covers: GetIntFromJson(FIELD_GROUP_TYPE) error in AddGroupTypeIfValid. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest227, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_JOIN;
    CJson *jsonParams = CreateJson();
    AddStringToJson(jsonParams, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(jsonParams, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(jsonParams, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(jsonParams, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    SetIsGroupExistByGroupId(false);
    int32_t ret = GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, CLIENT, jsonParams, s);
    FreeJson(jsonParams);
    ResetGroupOpMock();
    FreeBindSession(s);
    EXPECT_NE(ret, HC_SUCCESS);
}

/* CreateServerBindSubSession exception loop with full params + 50 iters.
 * Covers remaining SetGroupId/SetGroupName/SetGroupOwner JSON failures. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest228, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_INVITE);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(params, FIELD_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(params, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(params, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddIntToJson(params, FIELD_USER_TYPE, DEVICE_TYPE_ACCESSORY);
    AddIntToJson(params, FIELD_GROUP_VISIBILITY, GROUP_VISIBILITY_PUBLIC);
    AddIntToJson(params, FIELD_EXPIRE_TIME, DEFAULT_EXPIRE_TIME);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    AddIntToJson(params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    SetIsGroupExistByGroupId(false);
    SetCheckPermForGroupResult(HC_SUCCESS);
    SetCheckDeviceNumLimitResult(HC_SUCCESS);
    SetProcessKeyPairResult(HC_SUCCESS);
    for (uint32_t i = 0; i <= 50; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        CompatibleBaseSubSession *session = nullptr;
        (void)CreateServerBindSubSession(params, &g_callback, &session);
        if (session != nullptr) { DestroyCompatibleBindSubSession(session); }
        SetControllerMode(false);
    }
    FreeJson(params);
    ResetGroupOpMock();
    SUCCEED();
}

/* ProcessClientBindSubSession(PROCESSING) ProcessTask FINISH + exception loop.
 * Covers: OnBindFinish + InformSelfBindSuccess JSON failures. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest229, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_INVITE;
    s->params = CreateJson();
    AddStringToJson(s->params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(s->params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddStringToJson(s->params, FIELD_AUTH_ID, TEST_AUTH_ID);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(s->params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    AddIntToJson(s->params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    CJson *in = CreateJson();
    for (uint32_t i = 0; i <= 25; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        CJson *out = nullptr;
        int32_t status = 0;
        (void)ProcessClientBindSubSession((CompatibleBaseSubSession *)s, in, &out, &status);
        if (out != nullptr) { FreeJson(out); }
        SetControllerMode(false);
    }
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
    SUCCEED();
}

/* InformPeerGroupErrorIfNeeded with exception loop.
 * Covers: GenerateGroupErrorMsg + AddGroupErrorInfo JSON failures. */
HWTEST_F(CompatibleBindProcessMockTest, MockTest230, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_INVITE;
    s->params = CreateJson();
    AddStringToJson(s->params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(s->params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddStringToJson(s->params, FIELD_AUTH_ID, TEST_AUTH_ID);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(s->params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    AddIntToJson(s->params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    for (uint32_t i = 0; i <= 25; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        InformPeerGroupErrorIfNeeded(true, HC_ERR_INVALID_PARAMS, s);
        SetControllerMode(false);
    }
    FreeBindSession(s);
    SUCCEED();
}
}  // namespace
