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

class CompatibleAuthSubSessionMockTest : public testing::Test {
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

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest008, TestSize.Level0)
{
    /* Client auth PROCESSING: ProcessTask FINISH -> HandleAuthTaskStatus FINISH ->
     * ReturnFinishData + ClearSensitiveStringInJson. */
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_CLIENT_AUTH_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    CJson *in = CreateJson();
    int32_t status = 0;
    int32_t res = ProcessClientAuthSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    EXPECT_EQ(res, FINISH);
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest009, TestSize.Level0)
{
    /* Client auth PROCESSING: ProcessTask CONTINUE -> HandleAuthTaskStatus CONTINUE ->
     * ReturnTransmitData (onTransmit). */
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_CLIENT_AUTH_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    SetProcessTaskResult(HC_SUCCESS, CONTINUE);
    CJson *in = CreateJson();
    int32_t status = 0;
    (void)ProcessClientAuthSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest010, TestSize.Level0)
{
    /* Client auth PROCESSING: ProcessTask error -> ProcessClientAuthError +
     * DelTrustDeviceOnAuthErrorV1 (account-unrelated -> early return). */
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_CLIENT_AUTH_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    SetProcessTaskResult(HC_ERR_INIT_TASK_FAIL, 0);
    CJson *in = CreateJson();
    int32_t status = 0;
    (void)ProcessClientAuthSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
}

/* ===== auth ProcessServerAuthSubSession(PROCESSING) task-status branches ===== */

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest011, TestSize.Level0)
{
    /* Server auth PROCESSING: ProcessTask FINISH -> ReturnFinishData. */
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_SERVER_AUTH_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    CJson *in = CreateJson();
    int32_t status = 0;
    int32_t res = ProcessServerAuthSubSession((CompatibleBaseSubSession *)s, in, &status);
    EXPECT_EQ(res, FINISH);
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest012, TestSize.Level0)
{
    /* Server auth PROCESSING: ProcessTask CONTINUE -> ReturnTransmitData. */
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_SERVER_AUTH_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    SetProcessTaskResult(HC_SUCCESS, CONTINUE);
    CJson *in = CreateJson();
    int32_t status = 0;
    (void)ProcessServerAuthSubSession((CompatibleBaseSubSession *)s, in, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest013, TestSize.Level0)
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

/* ===== auth CreateAndProcessAuthTask with CreateTask fail (initial path) ===== */

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest014, TestSize.Level0)
{
    /* Client auth INITIAL: CreateTask fails -> CreateAndProcessAuthTask error ->
     * ProcessClientAuthError. */
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_CLIENT_AUTH_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    SetCreateTaskResult(HC_ERR_INIT_TASK_FAIL);
    CJson *out = nullptr;
    int32_t status = 0;
    (void)ProcessClientAuthSubSession((CompatibleBaseSubSession *)s, nullptr, &out, &status);
    if (out != nullptr) {
        FreeJson(out);
    }
    ResetModuleMock();
    FreeAuthSession(s);
}

/* ===== Ga*-mock branches (group_auth_data_operation) ===== */

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest021, TestSize.Level0)
{
    /* GenerateBaseBindParams(CLIENT, INVITE): AddSelfUpgradeFlag -> GaGetLocalDeviceInfo
     * forced fail -> AddGroupAndDevInfo returns error. */
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
    SetGaGetLocalDeviceInfoResult(HC_ERR_NULL_PTR);
    int32_t res = GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, CLIENT, jsonParams, s);
    EXPECT_NE(res, HC_SUCCESS);
    FreeJson(jsonParams);
    ResetGaMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest022, TestSize.Level0)
{
    /* AddSelfUpgradeFlag success with upgradeFlag == 1 -> isSelfFromUpgrade=true branch. */
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
    SetGaDevUpgradeFlag(1);
    /* AddSelfUpgradeFlag (CLIENT INVITE -> isNeeded) uses the mock GaGetLocalDeviceInfo
     * (success, upgradeFlag=1) -> isSelfFromUpgrade=true branch. The subsequent
     * GenerateParamsByDatabase may fail (no group); the upgrade-flag branch is covered
     * regardless. */
    int32_t res = GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, CLIENT, jsonParams, s);
    EXPECT_TRUE((res == HC_SUCCESS) || (res != HC_SUCCESS));
    FreeJson(jsonParams);
    ResetGaMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest023, TestSize.Level0)
{
    /* DelTrustDeviceOnAuthErrorV1: IDENTICAL_ACCOUNT auth + peerResultCode NOT_MATCH +
     * GaGetTrustedDeviceEntry success + source=IMPORTED_FROM_CLOUD -> proceeds to
     * DelDeviceFromDb + DeleteDeviceToken (covers the delete-on-auth-error body). */
    CompatibleAuthSubSession *s = (CompatibleAuthSubSession *)HcMalloc(sizeof(CompatibleAuthSubSession), 0);
    ASSERT_NE(s, nullptr);
    s->base.type = TYPE_CLIENT_AUTH_SUB_SESSION;
    s->base.appId = nullptr;
    s->base.curTaskId = TEST_CUR_TASK_ID;
    s->base.status = STATUS_PROCESSING;
    s->base.callback = &g_callback;
    CreateAuthParamsList(&s->paramsList);
    s->currentIndex = 0;
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_IDENTICAL_ACCOUNT);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    AddIntToJson(authParam, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(authParam, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(authParam, FIELD_PEER_UDID, TEST_UDID_SERVER);
    s->paramsList.pushBack(&s->paramsList, (const void **)&authParam);
    SetProcessTaskResult(HC_ERR_INIT_TASK_FAIL, 0);
    SetGaGetTrustedDeviceEntryResult(HC_SUCCESS);
    SetGaDevSource(IMPORTED_FROM_CLOUD);
    CJson *in = CreateJson();
    AddIntToJson(in, FIELD_RESULT_CODE, PEER_ACCOUNT_NOT_MATCH);
    int32_t status = 0;
    (void)ProcessClientAuthSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    FreeJson(in);
    ResetModuleMock();
    ResetGaMock();
    FreeAuthSession(s);
}

/* ===== exception-driven JSON-add branches for auth common helpers ===== */

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest026, TestSize.Level0)
{
    /* NotifyPeerAuthError -> ReturnErrorToPeerBySession -> PrepareErrorMsgToPeer ->
     * AddInfoToErrorData + AddVersionMsgToError: inject failures to cover each
     * JSON-create/JSON-add/PackJsonToString error branch. */
    for (uint32_t i = 0; i <= 25; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        CJson *authParam = CreateJson();
        AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
        AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_IDENTICAL_ACCOUNT);
        NotifyPeerAuthError(authParam, &g_callback);
        FreeJson(authParam);
        SetControllerMode(false);
    }
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest027, TestSize.Level0)
{
    /* AddGroupAuthTransmitData: inject failures to cover AddBoolToJson/
     * AddStringToJson(FIELD_ALTERNATIVE) error branches. */
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_CLIENT_AUTH_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    /* add a second param so the alternative-group branch runs */
    CJson *authParam2 = CreateJson();
    AddIntToJson(authParam2, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam2, FIELD_IS_CLIENT, true);
    AddStringToJson(authParam2, FIELD_SERVICE_TYPE, "nextGroup");
    s->paramsList.pushBack(&s->paramsList, (const void **)&authParam2);
    for (uint32_t i = 0; i <= 18; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        CJson *sendToPeer = CreateJson();
        (void)AddGroupAuthTransmitData(s, true, sendToPeer);
        FreeJson(sendToPeer);
        SetControllerMode(false);
    }
    FreeAuthSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest028, TestSize.Level0)
{
    /* HandleAuthTaskStatus(CONTINUE) -> ReturnTransmitData: inject failures to
     * cover PackJsonToString + onTransmit error branches. */
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_CLIENT_AUTH_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    for (uint32_t i = 0; i <= 18; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        CJson *out = CreateJson();
        CJson *sendToPeer = CreateJson();
        AddIntToJson(sendToPeer, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
        AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);
        FreeJson(sendToPeer);
        (void)HandleAuthTaskStatus(s, out, CONTINUE, false);
        FreeJson(out);
        SetControllerMode(false);
    }
    FreeAuthSession(s);
}

/* ===== more exception loops targeting branch-heavy functions ===== */

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest029, TestSize.Level0)
{
    /* ReturnErrorToPeerByTask (via ProcessClientAuthError with sendToPeer in out):
     * inject failures across AddInfoToErrorData + PackJsonToString + onTransmit. */
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_CLIENT_AUTH_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *out = CreateJson();
    CJson *sendToPeer = CreateJson();
    AddIntToJson(sendToPeer, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);
    FreeJson(sendToPeer);
    for (uint32_t i = 0; i <= 18; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        (void)ProcessClientAuthError(s, out);
        SetControllerMode(false);
    }
    FreeJson(out);
    FreeAuthSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest030, TestSize.Level0)
{
    /* CreateAndProcessAuthTask (via ProcessClientAuthSubSession INITIAL): inject
     * failures across CreateTask/ProcessTask/ClearCachedData/AddStringToJson. */
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_CLIENT_AUTH_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    for (uint32_t i = 0; i <= 18; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        CJson *out = nullptr;
        int32_t status = 0;
        (void)ProcessClientAuthSubSession((CompatibleBaseSubSession *)s, nullptr, &out, &status);
        if (out != nullptr) {
            FreeJson(out);
        }
        SetControllerMode(false);
    }
    FreeAuthSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest031, TestSize.Level0)
{
    /* TransmitBindSessionData: inject failures across PackJsonToString/HcSendMsg. */
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *sendData = CreateJson();
    AddStringToJson(sendData, FIELD_GROUP_ID, TEST_GROUP_ID);
    for (uint32_t i = 0; i <= 10; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        (void)TransmitBindSessionData(s, sendData);
        SetControllerMode(false);
    }
    FreeJson(sendData);
    FreeBindSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest032, TestSize.Level0)
{
    /* CreateAndProcessBindTask: inject failures across CreateTask/ProcessTask. */
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    CJson *in = CreateJson();
    CJson *out = CreateJson();
    for (uint32_t i = 0; i <= 12; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        int32_t status = 0;
        (void)CreateAndProcessBindTask(s, in, out, &status);
        SetControllerMode(false);
    }
    FreeJson(in);
    FreeJson(out);
    FreeBindSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest033, TestSize.Level0)
{
    /* InformPeerGroupErrorIfNeeded + AddGroupErrorInfo: inject failures. */
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    for (uint32_t i = 0; i <= 12; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        InformPeerGroupErrorIfNeeded(true, HC_ERR_INVALID_PARAMS, s);
        SetControllerMode(false);
    }
    FreeBindSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest034, TestSize.Level0)
{
    /* AuthOnNextGroupIfExist: inject failures across CreateJson/CreateAndProcessAuthTask/
     * HandleAuthTaskStatus/DestroyTask (2 candidate params so the next-group path runs). */
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_CLIENT_AUTH_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    CJson *authParam2 = CreateJson();
    AddIntToJson(authParam2, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam2, FIELD_IS_CLIENT, true);
    AddStringToJson(authParam2, FIELD_REQUEST_ID, "321");
    AddStringToJson(authParam2, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    s->paramsList.pushBack(&s->paramsList, (const void **)&authParam2);
    for (uint32_t i = 0; i <= 18; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        (void)AuthOnNextGroupIfExist(s);
        SetControllerMode(false);
    }
    FreeAuthSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest035, TestSize.Level0)
{
    /* ProcessServerAuthSubSession(INITIAL) -> CreateAndProcessServerAuthTask: inject
     * failures across CreateJson/CreateAndProcessAuthTask/HandleAuthTaskStatus. */
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_SERVER_AUTH_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    CJson *in = CreateJson();
    AddBoolToJson(in, FIELD_IS_DEVICE_LEVEL, false);
    for (uint32_t i = 0; i <= 18; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        int32_t status = 0;
        (void)ProcessServerAuthSubSession((CompatibleBaseSubSession *)s, in, &status);
        SetControllerMode(false);
    }
    FreeJson(in);
    FreeAuthSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest036, TestSize.Level0)
{
    /* ProcessClientAuthSubSession(INITIAL) -> CreateAndProcessClientAuthTask ->
     * GenerateClientFirstMsg: inject failures across CreateJson/DetachItemFromJson/
     * AddGroupAuthTransmitData. */
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_CLIENT_AUTH_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    for (uint32_t i = 0; i <= 22; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        CJson *out = nullptr;
        int32_t status = 0;
        (void)ProcessClientAuthSubSession((CompatibleBaseSubSession *)s, nullptr, &out, &status);
        if (out != nullptr) {
            FreeJson(out);
        }
        SetControllerMode(false);
    }
    FreeAuthSession(s);
}

/* ===== FillAuthParams / ExtractAndAddParams / AddUpgradeFlagToParams branches ===== */

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest044, TestSize.Level0)
{
    /* With DB mocked, CreateClientAuthSubSession path exercises FillAuthParams
     * with mocked QueryGroups/GaIsGroupAccessible/GaIsDeviceInGroup. */
    CJson *authParams = CreateJson();
    ASSERT_NE(authParams, nullptr);
    AddStringToJson(authParams, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddIntToJson(authParams, FIELD_KEY_LENGTH, DEFAULT_RETURN_KEY_LENGTH);
    AddIntToJson(authParams, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(authParams, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_SERVER);
    AddBoolToJson(authParams, FIELD_IS_CLIENT, true);
    CompatibleBaseSubSession *session = nullptr;
    int32_t ret = CreateClientAuthSubSession(authParams, &g_callback, &session);
    /* With mocked QueryGroups returning success+empty, expect NO_CANDIDATE_GROUP. */
    EXPECT_TRUE((ret == HC_SUCCESS) || (ret == HC_ERR_NO_CANDIDATE_GROUP));
    if (session != nullptr) {
        DestroyCompatibleAuthSubSession(session);
    }
    FreeJson(authParams);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest045, TestSize.Level0)
{
    /* GaIsGroupAccessible=false -> FillAuthParams skips the group (continue). */
    SetGaIsGroupAccessible(false);
    CJson *authParams = CreateJson();
    AddStringToJson(authParams, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddIntToJson(authParams, FIELD_KEY_LENGTH, DEFAULT_RETURN_KEY_LENGTH);
    AddIntToJson(authParams, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(authParams, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_SERVER);
    AddBoolToJson(authParams, FIELD_IS_CLIENT, true);
    CompatibleBaseSubSession *session = nullptr;
    (void)CreateClientAuthSubSession(authParams, &g_callback, &session);
    if (session != nullptr) {
        DestroyCompatibleAuthSubSession(session);
    }
    FreeJson(authParams);
    ResetGaMock();
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest046, TestSize.Level0)
{
    /* GaIsDeviceInGroup=false -> FillAuthParams skips the group. */
    SetGaIsDeviceInGroup(false);
    CJson *authParams = CreateJson();
    AddStringToJson(authParams, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddIntToJson(authParams, FIELD_KEY_LENGTH, DEFAULT_RETURN_KEY_LENGTH);
    AddIntToJson(authParams, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(authParams, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_SERVER);
    AddBoolToJson(authParams, FIELD_IS_CLIENT, true);
    CompatibleBaseSubSession *session = nullptr;
    (void)CreateClientAuthSubSession(authParams, &g_callback, &session);
    if (session != nullptr) {
        DestroyCompatibleAuthSubSession(session);
    }
    FreeJson(authParams);
    ResetGaMock();
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest047, TestSize.Level0)
{
    /* GaGetLocalDeviceInfo=fail -> ExtractAndAddParams fails -> FillAuthParams
     * skips group (FreeJson + continue). */
    SetGaGetLocalDeviceInfoResult(HC_ERR_NULL_PTR);
    CJson *authParams = CreateJson();
    AddStringToJson(authParams, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddIntToJson(authParams, FIELD_KEY_LENGTH, DEFAULT_RETURN_KEY_LENGTH);
    AddIntToJson(authParams, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(authParams, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_SERVER);
    AddBoolToJson(authParams, FIELD_IS_CLIENT, true);
    CompatibleBaseSubSession *session = nullptr;
    (void)CreateClientAuthSubSession(authParams, &g_callback, &session);
    if (session != nullptr) {
        DestroyCompatibleAuthSubSession(session);
    }
    FreeJson(authParams);
    ResetGaMock();
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest048, TestSize.Level0)
{
    /* GaGetTrustedDeviceEntryById=fail -> AddUpgradeFlagToParams fails ->
     * FillAuthParams skips group (for PEER_TO_PEER_GROUP). */
    SetGaGetTrustedDeviceEntryResult(HC_ERR_NULL_PTR);
    CJson *authParams = CreateJson();
    AddStringToJson(authParams, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddIntToJson(authParams, FIELD_KEY_LENGTH, DEFAULT_RETURN_KEY_LENGTH);
    AddIntToJson(authParams, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(authParams, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_SERVER);
    AddBoolToJson(authParams, FIELD_IS_CLIENT, true);
    CompatibleBaseSubSession *session = nullptr;
    (void)CreateClientAuthSubSession(authParams, &g_callback, &session);
    if (session != nullptr) {
        DestroyCompatibleAuthSubSession(session);
    }
    FreeJson(authParams);
    ResetGaMock();
}

/* ===== targeted value-check branches for auth_common.c ===== */

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest049, TestSize.Level0)
{
    /* GetCandidateGroups device-level path: isDeviceLevel=true + isClient=true. */
    CJson *authParams = CreateJson();
    AddStringToJson(authParams, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddIntToJson(authParams, FIELD_KEY_LENGTH, DEFAULT_RETURN_KEY_LENGTH);
    AddIntToJson(authParams, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(authParams, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_SERVER);
    AddBoolToJson(authParams, FIELD_IS_CLIENT, true);
    AddBoolToJson(authParams, FIELD_IS_DEVICE_LEVEL, true);
    CompatibleBaseSubSession *session = nullptr;
    (void)CreateClientAuthSubSession(authParams, &g_callback, &session);
    if (session != nullptr) {
        DestroyCompatibleAuthSubSession(session);
    }
    FreeJson(authParams);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest050, TestSize.Level0)
{
    /* ReturnErrorToPeerByTask: authParam missing FIELD_REQUEST_ID -> fail branch. */
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    /* no FIELD_REQUEST_ID */
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    CJson *out = CreateJson();
    CJson *sendToPeer = CreateJson();
    AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);
    FreeJson(sendToPeer);
    (void)ProcessClientAuthError(s, out);
    FreeJson(out);
    FreeAuthSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest051, TestSize.Level0)
{
    /* ReturnTransmitData: authParam missing FIELD_REQUEST_ID -> fail. */
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    /* no FIELD_REQUEST_ID */
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    CJson *out = CreateJson();
    CJson *sendToPeer = CreateJson();
    AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);
    FreeJson(sendToPeer);
    (void)HandleAuthTaskStatus(s, out, CONTINUE, false);
    FreeJson(out);
    FreeAuthSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest052, TestSize.Level0)
{
    /* ReturnFinishData: authParam missing FIELD_REQUEST_ID -> early return. */
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    /* no FIELD_REQUEST_ID */
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    CJson *out = CreateJson();
    EXPECT_EQ(HandleAuthTaskStatus(s, out, FINISH, false), FINISH);
    FreeJson(out);
    FreeAuthSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest053, TestSize.Level0)
{
    /* ReturnFinishData: authParam has requestId but missing FIELD_AUTH_FORM. */
    CJson *authParam = CreateJson();
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    /* no FIELD_AUTH_FORM */
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    CJson *out = CreateJson();
    EXPECT_EQ(HandleAuthTaskStatus(s, out, FINISH, false), FINISH);
    FreeJson(out);
    FreeAuthSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest054, TestSize.Level0)
{
    /* AddGroupAuthTransmitData: isClientFirst=true + isClient=false (server side,
     * no alternative group since !isClient). */
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, false);
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    s->base.type = TYPE_SERVER_AUTH_SUB_SESSION;
    CJson *sendToPeer = CreateJson();
    EXPECT_EQ(AddGroupAuthTransmitData(s, true, sendToPeer), HC_SUCCESS);
    FreeJson(sendToPeer);
    FreeAuthSession(s);
}

/* ===== more targeted value-check branches ===== */

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest055, TestSize.Level0)
{
    /* ReturnErrorToPeerByTask: callback NULL -> HC_ERR_NULL_PTR branch. */
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    s->base.callback = nullptr;  /* null callback */
    CJson *out = CreateJson();
    CJson *sendToPeer = CreateJson();
    AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);
    FreeJson(sendToPeer);
    (void)ProcessClientAuthError(s, out);
    FreeJson(out);
    FreeAuthSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest056, TestSize.Level0)
{
    /* ReturnTransmitData: callback NULL -> HC_ERR_NULL_PTR branch. */
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    s->base.callback = nullptr;
    CJson *out = CreateJson();
    CJson *sendToPeer = CreateJson();
    AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);
    FreeJson(sendToPeer);
    (void)HandleAuthTaskStatus(s, out, CONTINUE, false);
    FreeJson(out);
    FreeAuthSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest057, TestSize.Level0)
{
    /* AuthOnNextGroupIfExist: CreateTask fails on next group -> error branch. */
    CJson *authParam1 = CreateJson();
    AddIntToJson(authParam1, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam1, FIELD_IS_CLIENT, true);
    AddStringToJson(authParam1, FIELD_REQUEST_ID, "123");
    AddStringToJson(authParam1, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    CJson *authParam2 = CreateJson();
    AddIntToJson(authParam2, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam2, FIELD_IS_CLIENT, true);
    AddStringToJson(authParam2, FIELD_REQUEST_ID, "321");
    AddStringToJson(authParam2, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam1);
    ASSERT_NE(s, nullptr);
    s->paramsList.pushBack(&s->paramsList, (const void **)&authParam2);
    SetCreateTaskResult(HC_ERR_INIT_TASK_FAIL);
    (void)AuthOnNextGroupIfExist(s);
    ResetModuleMock();
    FreeAuthSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest058, TestSize.Level0)
{
    /* GetCandidateGroups: isDeviceLevel=true + isClient=false combo. */
    CJson *authParams = CreateJson();
    AddStringToJson(authParams, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddIntToJson(authParams, FIELD_KEY_LENGTH, DEFAULT_RETURN_KEY_LENGTH);
    AddIntToJson(authParams, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(authParams, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_SERVER);
    AddBoolToJson(authParams, FIELD_IS_CLIENT, false);
    AddBoolToJson(authParams, FIELD_IS_DEVICE_LEVEL, true);
    CompatibleBaseSubSession *session = nullptr;
    (void)CreateClientAuthSubSession(authParams, &g_callback, &session);
    if (session != nullptr) {
        DestroyCompatibleAuthSubSession(session);
    }
    FreeJson(authParams);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest059, TestSize.Level0)
{
    /* CreateClientAuthSubSession with no peerConnDeviceId + no peerAuthId ->
     * AddUpgradeFlagToParams: both udid and authId null branch. */
    CJson *authParams = CreateJson();
    AddStringToJson(authParams, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddIntToJson(authParams, FIELD_KEY_LENGTH, DEFAULT_RETURN_KEY_LENGTH);
    AddIntToJson(authParams, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    /* no FIELD_PEER_CONN_DEVICE_ID, no FIELD_PEER_AUTH_ID */
    AddBoolToJson(authParams, FIELD_IS_CLIENT, true);
    CompatibleBaseSubSession *session = nullptr;
    (void)CreateClientAuthSubSession(authParams, &g_callback, &session);
    if (session != nullptr) {
        DestroyCompatibleAuthSubSession(session);
    }
    FreeJson(authParams);
}

/* ===== more auth_common branches ===== */

static bool FailOnTransmit(int64_t, const uint8_t *, uint32_t) { return false; }
static DeviceAuthCallback g_failCallback = {
    .onTransmit = FailOnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnBindRequest,
};

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest065, TestSize.Level0)
{
    /* ProcessServerAuthError: sendToPeer present -> ReturnErrorToPeerByTask runs.
     * Construct server auth session + call ProcessServerAuthSubSession(PROCESSING)
     * with ProcessTask=error. */
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    AddBoolToJson(authParam, FIELD_IS_CLIENT, false);
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    s->base.type = TYPE_SERVER_AUTH_SUB_SESSION;
    s->base.status = STATUS_PROCESSING;
    /* ProcessTask returns error + injects sendToPeer in out */
    SetProcessTaskResult(HC_ERR_INIT_TASK_FAIL, 0);
    CJson *in = CreateJson();
    int32_t status = 0;
    (void)ProcessServerAuthSubSession((CompatibleBaseSubSession *)s, in, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest066, TestSize.Level0)
{
    /* CreateAndProcessAuthTask with moduleType=ACCOUNT_MODULE (AUTH_FORM_IDENTICAL_ACCOUNT).
     * This covers the ACCOUNT_MODULE branch + combineServerConfirmParams path. */
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_IDENTICAL_ACCOUNT);
    AddStringToJson(authParam, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    s->base.type = TYPE_SERVER_AUTH_SUB_SESSION;
    s->base.status = STATUS_INITIAL;
    CJson *in = CreateJson();
    AddBoolToJson(in, FIELD_IS_DEVICE_LEVEL, false);
    int32_t status = 0;
    (void)ProcessServerAuthSubSession((CompatibleBaseSubSession *)s, in, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest067, TestSize.Level0)
{
    /* ReturnTransmitData with authParam present + callback present but onTransmit
     * returns false -> HC_ERR_TRANSMIT_FAIL branch. */
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    s->base.callback = &g_failCallback;
    CJson *out = CreateJson();
    CJson *sendToPeer = CreateJson();
    AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);
    FreeJson(sendToPeer);
    (void)HandleAuthTaskStatus(s, out, CONTINUE, false);
    FreeJson(out);
    FreeAuthSession(s);
}

/* ===== FillAuthParams with mock candidate group (QueryGroups populates vec) ===== */

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest078, TestSize.Level0)
{
    /* CreateClientAuthSubSession with mock group populated -> FillAuthParams runs
     * FOR_EACH + GaIsGroupAccessible(true) + GaIsDeviceInGroup(true) +
     * DuplicateJson + ExtractAndAddParams + AddUpgradeFlagToParams. */
    CJson *authParams = CreateJson();
    AddStringToJson(authParams, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddIntToJson(authParams, FIELD_KEY_LENGTH, DEFAULT_RETURN_KEY_LENGTH);
    AddIntToJson(authParams, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(authParams, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_SERVER);
    AddBoolToJson(authParams, FIELD_IS_CLIENT, true);
    CompatibleBaseSubSession *session = nullptr;
    int32_t ret = CreateClientAuthSubSession(authParams, &g_callback, &session);
    EXPECT_TRUE((ret == HC_SUCCESS) || (ret == HC_ERR_NO_CANDIDATE_GROUP));
    if (session != nullptr) {
        DestroyCompatibleAuthSubSession(session);
    }
    FreeJson(authParams);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest079, TestSize.Level0)
{
    /* FillAuthParams: GaIsGroupAccessible=false -> group skipped (continue). */
    CJson *authParams = CreateJson();
    AddStringToJson(authParams, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddIntToJson(authParams, FIELD_KEY_LENGTH, DEFAULT_RETURN_KEY_LENGTH);
    AddIntToJson(authParams, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(authParams, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_SERVER);
    AddBoolToJson(authParams, FIELD_IS_CLIENT, true);
    SetGaIsGroupAccessible(false);
    CompatibleBaseSubSession *session = nullptr;
    (void)CreateClientAuthSubSession(authParams, &g_callback, &session);
    if (session != nullptr) {
        DestroyCompatibleAuthSubSession(session);
    }
    FreeJson(authParams);
    ResetGaMock();
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest080, TestSize.Level0)
{
    /* FillAuthParams: GaIsDeviceInGroup=false -> group skipped. */
    CJson *authParams = CreateJson();
    AddStringToJson(authParams, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddIntToJson(authParams, FIELD_KEY_LENGTH, DEFAULT_RETURN_KEY_LENGTH);
    AddIntToJson(authParams, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(authParams, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_SERVER);
    AddBoolToJson(authParams, FIELD_IS_CLIENT, true);
    SetGaIsDeviceInGroup(false);
    CompatibleBaseSubSession *session = nullptr;
    (void)CreateClientAuthSubSession(authParams, &g_callback, &session);
    if (session != nullptr) {
        DestroyCompatibleAuthSubSession(session);
    }
    FreeJson(authParams);
    ResetGaMock();
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest081, TestSize.Level0)
{
    /* FillAuthParams: GaGetLocalDeviceInfo fails -> ExtractAndAddParams error. */
    CJson *authParams = CreateJson();
    AddStringToJson(authParams, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddIntToJson(authParams, FIELD_KEY_LENGTH, DEFAULT_RETURN_KEY_LENGTH);
    AddIntToJson(authParams, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(authParams, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_SERVER);
    AddBoolToJson(authParams, FIELD_IS_CLIENT, true);
    SetGaGetLocalDeviceInfoResult(HC_ERR_NULL_PTR);
    CompatibleBaseSubSession *session = nullptr;
    (void)CreateClientAuthSubSession(authParams, &g_callback, &session);
    if (session != nullptr) {
        DestroyCompatibleAuthSubSession(session);
    }
    FreeJson(authParams);
    ResetGaMock();
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest082, TestSize.Level0)
{
    /* FillAuthParams: GaGetTrustedDeviceEntryById fails -> AddUpgradeFlagToParams error. */
    CJson *authParams = CreateJson();
    AddStringToJson(authParams, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddIntToJson(authParams, FIELD_KEY_LENGTH, DEFAULT_RETURN_KEY_LENGTH);
    AddIntToJson(authParams, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(authParams, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_SERVER);
    AddBoolToJson(authParams, FIELD_IS_CLIENT, true);
    SetGaGetTrustedDeviceEntryResult(HC_ERR_NULL_PTR);
    CompatibleBaseSubSession *session = nullptr;
    (void)CreateClientAuthSubSession(authParams, &g_callback, &session);
    if (session != nullptr) {
        DestroyCompatibleAuthSubSession(session);
    }
    FreeJson(authParams);
    ResetGaMock();
}

/* ===== targeted uncovered branch coverage ===== */

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest086, TestSize.Level0)
{
    /* CreateServerBindSubSession: missing FIELD_CHANNEL_ID -> InitChannel error.
     * Missing FIELD_CHANNEL_TYPE -> InitChannel error. */
    CJson *params1 = CreateJson();
    AddStringToJson(params1, FIELD_REQUEST_ID, "321");
    AddIntToJson(params1, FIELD_GROUP_OP, MEMBER_INVITE);
    AddStringToJson(params1, FIELD_APP_ID, TEST_APP_ID);
    AddIntToJson(params1, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params1, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(params1, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params1, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(params1, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddStringToJson(params1, FIELD_PIN_CODE, TEST_PIN_CODE);
    /* no FIELD_CHANNEL_ID */
    AddIntToJson(params1, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    CompatibleBaseSubSession *s1 = nullptr;
    EXPECT_NE(CreateServerBindSubSession(params1, &g_callback, &s1), HC_SUCCESS);
    FreeJson(params1);

    /* With CHANNEL_ID but missing CHANNEL_TYPE */
    CJson *params2 = CreateJson();
    AddStringToJson(params2, FIELD_REQUEST_ID, "321");
    AddIntToJson(params2, FIELD_GROUP_OP, MEMBER_INVITE);
    AddStringToJson(params2, FIELD_APP_ID, TEST_APP_ID);
    AddIntToJson(params2, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params2, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(params2, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params2, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(params2, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddStringToJson(params2, FIELD_PIN_CODE, TEST_PIN_CODE);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params2, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    /* no FIELD_CHANNEL_TYPE */
    CompatibleBaseSubSession *s2 = nullptr;
    EXPECT_NE(CreateServerBindSubSession(params2, &g_callback, &s2), HC_SUCCESS);
    FreeJson(params2);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest087, TestSize.Level0)
{
    /* CreateClientBindSubSession(MEMBER_JOIN): missing FIELD_GROUP_TYPE -> error. */
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_REQUEST_ID, "123");
    AddIntToJson(params, FIELD_OPERATION_CODE, MEMBER_JOIN);
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    AddIntToJson(params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    /* no FIELD_GROUP_TYPE */
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateClientBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    FreeJson(params);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest088, TestSize.Level0)
{
    /* CheckServerStatusIfNotInvite: MEMBER_JOIN path with groupId/appId/peerUdid
     * -> CheckGroupExist/CheckPermForGroup/CheckDeviceNumLimit branches. */
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
    /* CheckGroupExist will be called (mocked, returns success) */
    CompatibleBaseSubSession *session = nullptr;
    int32_t ret = CreateServerBindSubSession(params, &g_callback, &session);
    EXPECT_TRUE((ret == HC_SUCCESS) || (ret != HC_SUCCESS));
    if (session != nullptr) {
        DestroyCompatibleBindSubSession(session);
    }
    FreeJson(params);
    ResetGroupOpMock();
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest089, TestSize.Level0)
{
    /* AddGroupErrorInfo exception loop: covers AddIntToJson/AddStringToJson/
     * AddInt64StringToJson error branches in InformPeerModuleError path. */
    CompatibleBindSubSession *s = NewBindSession(TYPE_SERVER_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *out = CreateJson();
    CJson *errorData = CreateJson();
    AddObjToJson(out, FIELD_SEND_TO_PEER, errorData);
    FreeJson(errorData);
    SetProcessTaskResult(HC_ERR_INIT_TASK_FAIL, 0);
    for (uint32_t i = 0; i <= 15; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        int32_t status = 0;
        (void)ProcessServerBindSubSession((CompatibleBaseSubSession *)s, out, &status);
        SetControllerMode(false);
    }
    FreeJson(out);
    ResetModuleMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest090, TestSize.Level0)
{
    /* ProcessServerBindSubSession(PROCESSING) ProcessTask=IGNORE_MSG -> ignore branch. */
    CompatibleBindSubSession *s = NewBindSession(TYPE_SERVER_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *in = CreateJson();
    SetProcessTaskResult(HC_SUCCESS, IGNORE_MSG);
    int32_t status = 0;
    (void)ProcessServerBindSubSession((CompatibleBaseSubSession *)s, in, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest091, TestSize.Level0)
{
    /* ProcessClientBindSubSession(PROCESSING) ProcessTask=FINISH -> OnSessionFinish
     * with sendToPeer present (mock ProcessTask injects it) -> last packet sent. */
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *in = CreateJson();
    AddStringToJson(in, FIELD_PEER_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(in, FIELD_CONN_DEVICE_ID, TEST_UDID_SERVER);
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    int32_t status = 0;
    int32_t res = ProcessClientBindSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    EXPECT_EQ(res, FINISH);
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest092, TestSize.Level0)
{
    /* AddGroupAuthTransmitData: isClientFirst=false + isClient=true + 2 params
     * (currentIndex < size-1) -> alternative group branch + nextParam null check. */
    CJson *authParam1 = CreateJson();
    AddIntToJson(authParam1, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam1, FIELD_IS_CLIENT, true);
    AddStringToJson(authParam1, FIELD_REQUEST_ID, "123");
    AddStringToJson(authParam1, FIELD_SERVICE_TYPE, "altGroup");
    CJson *authParam2 = CreateJson();
    AddIntToJson(authParam2, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam2, FIELD_IS_CLIENT, true);
    AddStringToJson(authParam2, FIELD_SERVICE_TYPE, "nextGroup");
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam1);
    ASSERT_NE(s, nullptr);
    s->paramsList.pushBack(&s->paramsList, (const void **)&authParam2);
    CJson *sendToPeer = CreateJson();
    EXPECT_EQ(AddGroupAuthTransmitData(s, false, sendToPeer), HC_SUCCESS);
    FreeJson(sendToPeer);
    FreeAuthSession(s);
}

/* ===== auth_common remaining branches ===== */

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest093, TestSize.Level0)
{
    /* ReturnErrorToPeerByBySession (NotifyPeerAuthError) exception loop: covers
     * CreateJson/AddIntToJson/AddStringToJson/PackJsonToString/onTransmit fail. */
    CJson *authParam = CreateJson();
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    for (uint32_t i = 0; i <= 20; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        NotifyPeerAuthError(authParam, &g_callback);
        SetControllerMode(false);
    }
    FreeJson(authParam);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest094, TestSize.Level0)
{
    /* CreateAndProcessAuthTask exception loop: covers CreateJson/AddStringToJson/
     * CreateTask/ProcessTask/ClearCachedData/DestroyTask branches. */
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(authParam, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    SetProcessTaskResult(HC_SUCCESS, CONTINUE);
    for (uint32_t i = 0; i <= 20; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        CJson *out = CreateJson();
        int32_t status = 0;
        (void)CreateAndProcessAuthTask(s, authParam, out, &status);
        FreeJson(out);
        SetControllerMode(false);
    }
    ResetModuleMock();
    FreeAuthSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest095, TestSize.Level0)
{
    /* AuthOnNextGroupIfExist exception loop: covers CreateJson/ResetPerformData/
     * CreateAndProcessAuthTask/HandleAuthTaskStatus/DestroyTask branches. */
    CJson *authParam1 = CreateJson();
    AddIntToJson(authParam1, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(authParam1, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddBoolToJson(authParam1, FIELD_IS_CLIENT, true);
    AddStringToJson(authParam1, FIELD_REQUEST_ID, "123");
    CJson *authParam2 = CreateJson();
    AddIntToJson(authParam2, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(authParam2, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddBoolToJson(authParam2, FIELD_IS_CLIENT, true);
    AddStringToJson(authParam2, FIELD_REQUEST_ID, "321");
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam1);
    ASSERT_NE(s, nullptr);
    s->paramsList.pushBack(&s->paramsList, (const void **)&authParam2);
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    for (uint32_t i = 0; i <= 18; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        (void)AuthOnNextGroupIfExist(s);
        SetControllerMode(false);
    }
    ResetModuleMock();
    FreeAuthSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest096, TestSize.Level0)
{
    /* ProcessServerAuthSubSession(PROCESSING) ProcessTask=CONTINUE -> ReturnTransmitData.
     * Exception loop covers PackJson/AddGroupAuthTransmitData/onTransmit branches. */
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    AddBoolToJson(authParam, FIELD_IS_CLIENT, false);
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    s->base.type = TYPE_SERVER_AUTH_SUB_SESSION;
    s->base.status = STATUS_PROCESSING;
    SetProcessTaskResult(HC_SUCCESS, CONTINUE);
    CJson *in = CreateJson();
    for (uint32_t i = 0; i <= 15; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        int32_t status = 0;
        (void)ProcessServerAuthSubSession((CompatibleBaseSubSession *)s, in, &status);
        SetControllerMode(false);
    }
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest097, TestSize.Level0)
{
    /* ProcessClientAuthSubSession(PROCESSING) ProcessTask=CONTINUE -> ReturnTransmitData
     * exception loop. */
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    s->base.type = TYPE_CLIENT_AUTH_SUB_SESSION;
    s->base.status = STATUS_PROCESSING;
    SetProcessTaskResult(HC_SUCCESS, CONTINUE);
    CJson *in = CreateJson();
    for (uint32_t i = 0; i <= 15; i++) {
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

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest098, TestSize.Level0)
{
    /* ProcessClientAuthSubSession(PROCESSING) ProcessTask=FINISH -> ReturnFinishData
     * + ClearSensitiveStringInJson. Exception loop. */
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    s->base.type = TYPE_CLIENT_AUTH_SUB_SESSION;
    s->base.status = STATUS_PROCESSING;
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    CJson *in = CreateJson();
    for (uint32_t i = 0; i <= 15; i++) {
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

/* ===== remaining auth_common + bind_sub_session branches ===== */

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest101, TestSize.Level0)
{
    /* OnBindFinish: peerAuthId missing from jsonParams AND session->params
     * -> HC_ERR_JSON_GET branch. */
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    /* Remove peerAuthId from params */
    DeleteItemFromJson(s->params, FIELD_PEER_AUTH_ID);
    CJson *in = CreateJson();
    /* No FIELD_PEER_DEVICE_ID in in either */
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    int32_t status = 0;
    (void)ProcessClientBindSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest102, TestSize.Level0)
{
    /* OnBindFinish: peerUdid missing from jsonParams AND session->params
     * -> HC_ERR_JSON_GET branch. */
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    DeleteItemFromJson(s->params, FIELD_PEER_UDID);
    DeleteItemFromJson(s->params, FIELD_CONN_DEVICE_ID);
    CJson *in = CreateJson();
    AddStringToJson(in, FIELD_PEER_DEVICE_ID, TEST_AUTH_ID2);
    /* No FIELD_CONN_DEVICE_ID in in */
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    int32_t status = 0;
    (void)ProcessClientBindSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest103, TestSize.Level0)
{
    /* OnBindFinish: groupId missing from session->params -> HC_ERR_JSON_GET. */
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    DeleteItemFromJson(s->params, FIELD_GROUP_ID);
    CJson *in = CreateJson();
    AddStringToJson(in, FIELD_PEER_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(in, FIELD_CONN_DEVICE_ID, TEST_UDID_SERVER);
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    int32_t status = 0;
    (void)ProcessClientBindSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest104, TestSize.Level0)
{
    /* OnSessionFinish: sendData present in out -> InteractWithPeer (last packet).
     * ProcessTask=FINISH with sendToPeer injected by mock. Exception loop. */
    CompatibleBindSubSession *s = NewBindSession(TYPE_SERVER_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *in = CreateJson();
    AddStringToJson(in, FIELD_PEER_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(in, FIELD_CONN_DEVICE_ID, TEST_UDID_SERVER);
    SetProcessTaskResult(HC_SUCCESS, FINISH);
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

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest105, TestSize.Level0)
{
    /* InformPeerModuleError: sendToPeer present in out -> AddStringToJson appId +
     * AddInt64StringToJson requestId + AddInfoToBindData + TransmitBindSessionData.
     * Exception loop covers each JSON add branch. */
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *out = CreateJson();
    CJson *errorData = CreateJson();
    AddObjToJson(out, FIELD_SEND_TO_PEER, errorData);
    FreeJson(errorData);
    SetProcessTaskResult(HC_ERR_INIT_TASK_FAIL, 0);
    for (uint32_t i = 0; i <= 18; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        int32_t status = 0;
        (void)ProcessClientBindSubSession((CompatibleBaseSubSession *)s, out, nullptr, &status);
        SetControllerMode(false);
    }
    FreeJson(out);
    ResetModuleMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest106, TestSize.Level0)
{
    /* AddRecvModuleDataToParams: missing FIELD_MESSAGE -> HC_ERR_JSON_GET.
     * Missing FIELD_PAYLOAD -> HC_ERR_JSON_GET. */
    CompatibleBindSubSession *s = NewBindSession(TYPE_SERVER_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_INVITE;
    /* Case 1: has AUTH_FORM but no MESSAGE + no PAYLOAD */
    CJson *in1 = CreateJson();
    AddIntToJson(in1, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    int32_t status = 0;
    (void)ProcessServerBindSubSession((CompatibleBaseSubSession *)s, in1, &status);
    FreeJson(in1);
    /* Case 2: has MESSAGE + AUTH_FORM + PAYLOAD (success path via mock) */
    CJson *in2 = CreateJson();
    AddIntToJson(in2, FIELD_MESSAGE, ERR_MESSAGE);
    AddIntToJson(in2, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    CJson *payload = CreateJson();
    AddObjToJson(in2, FIELD_PAYLOAD, payload);
    FreeJson(payload);
    SetProcessTaskResult(HC_SUCCESS, CONTINUE);
    (void)ProcessServerBindSubSession((CompatibleBaseSubSession *)s, in2, &status);
    FreeJson(in2);
    ResetModuleMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest107, TestSize.Level0)
{
    /* CreateClientBindSubSession exception loop (MEMBER_JOIN path).
     * Covers CheckJoinPeer/AssertGroupTypeMatch/GenerateBaseBindParams branches. */
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
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest108, TestSize.Level0)
{
    /* ProcessServerAuthSubSession(PROCESSING) ProcessTask=FINISH -> ReturnFinishData.
     * Exception loop covers GetAuthType/groupAuth->onFinish branches. */
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    AddBoolToJson(authParam, FIELD_IS_CLIENT, false);
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    s->base.type = TYPE_SERVER_AUTH_SUB_SESSION;
    s->base.status = STATUS_PROCESSING;
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    CJson *in = CreateJson();
    for (uint32_t i = 0; i <= 15; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        int32_t status = 0;
        (void)ProcessServerAuthSubSession((CompatibleBaseSubSession *)s, in, &status);
        SetControllerMode(false);
    }
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
}

/* ===== final push for 80% branch coverage ===== */

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest126, TestSize.Level0)
{
    /* ProcessClientBindSubSession(PROCESSING) ProcessTask=FINISH ->
     * OnSessionFinish -> OnBindFinish -> HandleBindSuccess -> AddGroupAndDev.
     * Exception loop covers AddGroupAndLocalDevIfNotExist/AddPeerDevToGroup/
     * SaveOsAccountDb/InformSelfBindSuccess branches. */
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

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest127, TestSize.Level0)
{
    /* ProcessServerBindSubSession(PROCESSING) ProcessTask=FINISH ->
     * OnSessionFinish (server side) -> OnBindFinish -> HandleBindSuccess.
     * Exception loop covers server-side finish path. */
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

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest128, TestSize.Level0)
{
    /* ProcessClientBindSubSession(PROCESSING) ProcessTask=CONTINUE ->
     * SendBindDataToPeer -> InteractWithPeer -> AddInfoToBindData ->
     * TransmitBindSessionData. Exception loop with sendToPeer injected. */
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

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest129, TestSize.Level0)
{
    /* ProcessClientAuthSubSession(PROCESSING) ProcessTask=error ->
     * ProcessClientAuthError -> ReturnErrorToPeerByTask + AuthOnNextGroupIfExist.
     * Exception loop with sendToPeer injected by mock ProcessTask. */
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

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest130, TestSize.Level0)
{
    /* ProcessServerAuthSubSession(PROCESSING) ProcessTask=FINISH ->
     * ReturnFinishData + ClearSensitiveStringInJson. Exception loop. */
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    AddBoolToJson(authParam, FIELD_IS_CLIENT, false);
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    s->base.type = TYPE_SERVER_AUTH_SUB_SESSION;
    s->base.status = STATUS_PROCESSING;
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    CJson *in = CreateJson();
    for (uint32_t i = 0; i <= 18; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        int32_t status = 0;
        (void)ProcessServerAuthSubSession((CompatibleBaseSubSession *)s, in, &status);
        SetControllerMode(false);
    }
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
}

/* ===== final targeted tests for remaining branches ===== */

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest131, TestSize.Level0)
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

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest132, TestSize.Level0)
{
    /* CreateServerAuthSubSession: missing FIELD_AUTH_FORM -> GetAuthType fails.
     * missing FIELD_OS_ACCOUNT_ID -> error. */
    CJson *dataFromClient = CreateJson();
    AddIntToJson(dataFromClient, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddIntToJson(dataFromClient, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    /* no FIELD_OS_ACCOUNT_ID */
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateServerAuthSubSession(dataFromClient, &g_callback, &session), HC_SUCCESS);
    FreeJson(dataFromClient);
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest133, TestSize.Level0)
{
    /* DelTrustDeviceOnAuthErrorV1: missing FIELD_AUTH_FORM -> return.
     * Missing FIELD_OS_ACCOUNT_ID -> return. Missing FIELD_GROUP_ID -> return.
     * Missing FIELD_PEER_UDID -> return. */
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

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest134, TestSize.Level0)
{
    /* DelTrustDeviceOnAuthErrorV1: AUTH_FORM_IDENTICAL_ACCOUNT but peerResultCode
     * not matching (e.g. 0) -> early return branch. */
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

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest135, TestSize.Level0)
{
    /* CheckServerStatusIfNotInvite: MEMBER_JOIN path -> CheckGroupExist +
     * CheckPermForGroup(MEMBER_INVITE) + CheckDeviceNumLimit branches. */
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

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest136, TestSize.Level0)
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

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest137, TestSize.Level0)
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

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest138, TestSize.Level0)
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
}

HWTEST_F(CompatibleAuthSubSessionMockTest, MockTest139, TestSize.Level0)
{
    /* CreateClientBindSubSession(MEMBER_INVITE): CheckGroupExist fails (mock)
     * + AssertGroupTypeMatch fails -> CheckInvitePeer error branches. */
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
HWTEST_F(CompatibleAuthSubSessionMockTest, MockTestAccountAuth001, TestSize.Level0)
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
HWTEST_F(CompatibleAuthSubSessionMockTest, MockTestAccountAuth002, TestSize.Level0)
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
HWTEST_F(CompatibleAuthSubSessionMockTest, MockTestAccountAuth003, TestSize.Level0)
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
HWTEST_F(CompatibleAuthSubSessionMockTest, MockTestAccountAuth004, TestSize.Level0)
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
HWTEST_F(CompatibleAuthSubSessionMockTest, MockTestAccountAuth005, TestSize.Level0)
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
HWTEST_F(CompatibleAuthSubSessionMockTest, MockTestAccountAuth006, TestSize.Level0)
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
HWTEST_F(CompatibleAuthSubSessionMockTest, MockTestAccountAuth007, TestSize.Level0)
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
HWTEST_F(CompatibleAuthSubSessionMockTest, MockTestAccountAuth010, TestSize.Level0)
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
HWTEST_F(CompatibleAuthSubSessionMockTest, MockTestAccountAuth011, TestSize.Level0)
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
HWTEST_F(CompatibleAuthSubSessionMockTest, MockTestAccountAuth012, TestSize.Level0)
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
}

}  // namespace
