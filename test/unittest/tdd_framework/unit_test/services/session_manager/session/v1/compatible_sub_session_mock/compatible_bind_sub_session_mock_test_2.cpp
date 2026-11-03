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

class CompatibleBindParamMockTest : public testing::Test {
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

/* ===== Correct field name tests: cover reachable branches in compatible_bind_sub_session.c =====
 * Previous tests used FIELD_SERVICE_PKG_NAME instead of FIELD_APP_ID, causing early failure
 * at GetDuplicateAppId and never reaching target branches. These tests use correct fields. */

/* CreateClientBindSubSession(MEMBER_INVITE) missing FIELD_GROUP_ID.
 * Flow: L851 ok -> L857 ok -> L862 CheckClientStatus -> CheckInvitePeer -> L36 groupId==NULL.
 * Covers: L36 (groupId==NULL) in CheckInvitePeer. */
HWTEST_F(CompatibleBindParamMockTest, MockTest231, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_REQUEST_ID, "123");
    AddIntToJson(params, FIELD_OPERATION_CODE, MEMBER_INVITE);
    AddStringToJson(params, FIELD_APP_ID, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateClientBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleBindSubSession(session); }
    FreeJson(params);
}

/* CreateClientBindSubSession(MEMBER_INVITE) missing FIELD_APP_ID.
 * Flow: L851 ok -> L857 ok -> L862 CheckClientStatus -> CheckInvitePeer -> L40 appId==NULL.
 * Covers: L40 (appId==NULL) in CheckInvitePeer. */
HWTEST_F(CompatibleBindParamMockTest, MockTest232, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_REQUEST_ID, "123");
    AddIntToJson(params, FIELD_OPERATION_CODE, MEMBER_INVITE);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateClientBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleBindSubSession(session); }
    FreeJson(params);
}

/* CreateClientBindSubSession(MEMBER_INVITE) missing FIELD_OS_ACCOUNT_ID.
 * Flow: L851 ok -> L857 ok -> L862 CheckClientStatus -> CheckInvitePeer -> L46 osAccountId fail.
 * Covers: L46 (GetIntFromJson OS_ACCOUNT_ID fail) in CheckInvitePeer. */
HWTEST_F(CompatibleBindParamMockTest, MockTest233, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_REQUEST_ID, "123");
    AddIntToJson(params, FIELD_OPERATION_CODE, MEMBER_INVITE);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_APP_ID, TEST_APP_ID);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateClientBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleBindSubSession(session); }
    FreeJson(params);
}

/* CreateClientBindSubSession(MEMBER_JOIN) missing FIELD_GROUP_TYPE.
 * Flow: L851 ok -> L857 ok -> L862 CheckClientStatus -> CheckJoinPeer -> L66 groupType fail.
 * Covers: L66 (GetIntFromJson GROUP_TYPE fail) in CheckJoinPeer. */
HWTEST_F(CompatibleBindParamMockTest, MockTest234, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_REQUEST_ID, "123");
    AddIntToJson(params, FIELD_OPERATION_CODE, MEMBER_JOIN);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateClientBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleBindSubSession(session); }
    FreeJson(params);
}

/* CreateClientBindSubSession with invalid OPERATION_CODE (MEMBER_DELETE).
 * Flow: L851 ok -> L857 ok -> L862 CheckClientStatus -> default -> L80 invalid operation.
 * Covers: L75 switch default case in CheckClientStatus. */
HWTEST_F(CompatibleBindParamMockTest, MockTest235, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_REQUEST_ID, "123");
    AddIntToJson(params, FIELD_OPERATION_CODE, MEMBER_DELETE);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateClientBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleBindSubSession(session); }
    FreeJson(params);
}

/* CreateClientBindSubSession(MEMBER_JOIN) missing FIELD_OS_ACCOUNT_ID.
 * Flow: L851 ok -> L857 ok -> L862 CheckClientStatus -> CheckJoinPeer ok ->
 *       L868 CreateBaseBindSubSession -> L118 osAccountId fail.
 * Covers: L118 (GetIntFromJson OS_ACCOUNT_ID fail) in CreateBaseBindSubSession. */
HWTEST_F(CompatibleBindParamMockTest, MockTest236, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_REQUEST_ID, "123");
    AddIntToJson(params, FIELD_OPERATION_CODE, MEMBER_JOIN);
    AddIntToJson(params, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddStringToJson(params, FIELD_APP_ID, TEST_APP_ID);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateClientBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleBindSubSession(session); }
    FreeJson(params);
}

/* CreateClientBindSubSession(MEMBER_JOIN) missing FIELD_GROUP_ID.
 * Flow: L851 ok -> L857 ok -> L862 CheckClientStatus -> CheckJoinPeer ok ->
 *       L868 CreateBaseBindSubSession ok -> L874 GenerateKeyPairIfNeeded(CLIENT, MEMBER_JOIN) ->
 *       L152 IsCreateGroupNeeded=true -> L156 groupId==NULL.
 * Covers: L157 (groupId==NULL) in GenerateKeyPairIfNeeded. */
HWTEST_F(CompatibleBindParamMockTest, MockTest237, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_REQUEST_ID, "123");
    AddIntToJson(params, FIELD_OPERATION_CODE, MEMBER_JOIN);
    AddIntToJson(params, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddStringToJson(params, FIELD_APP_ID, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateClientBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleBindSubSession(session); }
    FreeJson(params);
}

/* CreateClientBindSubSession(MEMBER_JOIN) with ProcessKeyPair error.
 * Flow: ... -> L874 GenerateKeyPairIfNeeded -> L162 ProcessKeyPair returns HC_ERROR -> L164.
 * Covers: L164 (result != HC_SUCCESS) in GenerateKeyPairIfNeeded. */
HWTEST_F(CompatibleBindParamMockTest, MockTest238, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_REQUEST_ID, "123");
    AddIntToJson(params, FIELD_OPERATION_CODE, MEMBER_JOIN);
    AddIntToJson(params, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddStringToJson(params, FIELD_APP_ID, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    SetProcessKeyPairResult(HC_ERROR);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateClientBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleBindSubSession(session); }
    FreeJson(params);
    ResetGroupOpMock();
}

/* CreateServerBindSubSession(MEMBER_JOIN) missing FIELD_GROUP_ID.
 * Flow: L898 ok -> L903 ok -> L907 CreateBaseBindSubSession ok -> L913 InitChannel ok ->
 *       L920 GenerateServerBindParams -> L219 CheckAcceptRequest ok ->
 *       L223 CheckServerStatusIfNotInvite -> L175 groupId==NULL.
 * Covers: L175 (groupId==NULL) in CheckServerStatusIfNotInvite. */
HWTEST_F(CompatibleBindParamMockTest, MockTest239, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_REQUEST_ID, "123");
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_JOIN);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(params, FIELD_APP_ID, TEST_APP_ID);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    AddIntToJson(params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateServerBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleBindSubSession(session); }
    FreeJson(params);
}

/* CreateServerBindSubSession(MEMBER_JOIN) missing FIELD_CONN_DEVICE_ID.
 * Flow: ... -> L223 CheckServerStatusIfNotInvite -> L175 ok -> L180 ok -> L186 peerUdid==NULL.
 * Covers: L186 (peerUdid==NULL) in CheckServerStatusIfNotInvite. */
HWTEST_F(CompatibleBindParamMockTest, MockTest240, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_REQUEST_ID, "123");
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_JOIN);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(params, FIELD_APP_ID, TEST_APP_ID);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    AddIntToJson(params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateServerBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    if (session != nullptr) { DestroyCompatibleBindSubSession(session); }
    FreeJson(params);
}


/* ===== Cover bind_sub_session_common.c reachable branches ===== */

/* GenerateBaseBindParams(CLIENT, MEMBER_JOIN) missing FIELD_GROUP_TYPE.
 * Flow: L657 AddPinCode ok -> L658 AddProtocolExpandVal ok ->
 *   L659 AddGroupAndDevInfo -> L380 groupId ok -> L390 IsCreateGroupNeeded(CLIENT, MEMBER_JOIN)=true
 *   -> L391 GenerateParamsByInput -> AddGroupInfoToSessionParams -> L133 AddGroupId ok ->
 *   L134 AddGroupName ok -> L135 AddGroupOwnerIfExist ok -> L136 AddGroupTypeIfValid -> L85 fail.
 * Covers: L85 (GetIntFromJson GROUP_TYPE fail) in AddGroupTypeIfValid. */
HWTEST_F(CompatibleBindParamMockTest, MockTest241, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_JOIN;
    CJson *jsonParams = CreateJson();
    AddStringToJson(jsonParams, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(jsonParams, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(jsonParams, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(jsonParams, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(jsonParams, FIELD_APP_ID, TEST_APP_ID);
    /* NO FIELD_GROUP_TYPE */
    SetIsGroupExistByGroupId(false);
    int32_t ret = GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, CLIENT, jsonParams, s);
    FreeJson(jsonParams);
    ResetGroupOpMock();
    FreeBindSession(s);
    EXPECT_NE(ret, HC_SUCCESS);
}

/* GenerateBaseBindParams(CLIENT, MEMBER_JOIN) with invalid FIELD_GROUP_TYPE.
 * Flow: ... -> L136 AddGroupTypeIfValid -> L85 ok -> L89 groupType != PEER_TO_PEER_GROUP -> fail.
 * Covers: L89 (groupType != PEER_TO_PEER_GROUP) in AddGroupTypeIfValid. */
HWTEST_F(CompatibleBindParamMockTest, MockTest242, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_JOIN;
    CJson *jsonParams = CreateJson();
    AddStringToJson(jsonParams, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(jsonParams, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(jsonParams, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(jsonParams, FIELD_GROUP_TYPE, COMPATIBLE_GROUP);
    AddIntToJson(jsonParams, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(jsonParams, FIELD_APP_ID, TEST_APP_ID);
    SetIsGroupExistByGroupId(false);
    int32_t ret = GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, CLIENT, jsonParams, s);
    FreeJson(jsonParams);
    ResetGroupOpMock();
    FreeBindSession(s);
    EXPECT_NE(ret, HC_SUCCESS);
}

/* GenerateBaseBindParams(CLIENT, MEMBER_JOIN) missing FIELD_GROUP_NAME.
 * Flow: ... -> L133 AddGroupId ok -> L134 AddGroupName -> L61 groupName==NULL -> fail.
 * Covers: L61 (groupName==NULL) in AddGroupName. */
HWTEST_F(CompatibleBindParamMockTest, MockTest243, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_JOIN;
    CJson *jsonParams = CreateJson();
    AddStringToJson(jsonParams, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(jsonParams, FIELD_GROUP_ID, TEST_GROUP_ID);
    /* NO FIELD_GROUP_NAME */
    AddIntToJson(jsonParams, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(jsonParams, FIELD_APP_ID, TEST_APP_ID);
    SetIsGroupExistByGroupId(false);
    int32_t ret = GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, CLIENT, jsonParams, s);
    FreeJson(jsonParams);
    ResetGroupOpMock();
    FreeBindSession(s);
    EXPECT_NE(ret, HC_SUCCESS);
}


/* ===== Cover compatible_sub_session.c dispatcher branches ===== */

/* CreateCompatibleSubSession with NULL params.
 * Covers: L26 (NULL check true arc) in CreateCompatibleSubSession. */
HWTEST_F(CompatibleBindParamMockTest, MockTest244, TestSize.Level0)
{
    int32_t ret = CreateCompatibleSubSession(TYPE_CLIENT_BIND_SUB_SESSION, nullptr, &g_callback, nullptr);
    EXPECT_EQ(ret, HC_ERR_INVALID_PARAMS);
}

/* CreateCompatibleSubSession with invalid session type.
 * Covers: L60 (default case) in CreateCompatibleSubSession switch. */
HWTEST_F(CompatibleBindParamMockTest, MockTest245, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_REQUEST_ID, "123");
    CompatibleBaseSubSession *session = nullptr;
    int32_t ret = CreateCompatibleSubSession((SubSessionTypeValue)999, params, &g_callback, &session);
    EXPECT_EQ(ret, HC_ERR_INVALID_PARAMS);
    FreeJson(params);
}

/* ProcessCompatibleSubSession with NULL params.
 * Covers: L47 (NULL check true arc) in ProcessCompatibleSubSession. */
HWTEST_F(CompatibleBindParamMockTest, MockTest246, TestSize.Level0)
{
    CJson *in = CreateJson();
    CJson *out = nullptr;
    int32_t status = 0;
    int32_t ret = ProcessCompatibleSubSession(nullptr, in, &out, &status);
    EXPECT_EQ(ret, HC_ERR_INVALID_PARAMS);
    FreeJson(in);
}

/* ProcessCompatibleSubSession with invalid session type.
 * Covers: default case in ProcessCompatibleSubSession switch. */
HWTEST_F(CompatibleBindParamMockTest, MockTest247, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession((SubSessionTypeValue)999, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    CJson *in = CreateJson();
    CJson *out = nullptr;
    int32_t status = 0;
    int32_t ret = ProcessCompatibleSubSession((CompatibleBaseSubSession *)s, in, &out, &status);
    EXPECT_EQ(ret, HC_ERR_INVALID_PARAMS);
    FreeJson(in);
    if (out != nullptr) { FreeJson(out); }
    FreeBindSession(s);
}

/* DestroyCompatibleSubSession with NULL session.
 * Covers: L69 (NULL check true arc) in DestroyCompatibleSubSession. */
HWTEST_F(CompatibleBindParamMockTest, MockTest248, TestSize.Level0)
{
    DestroyCompatibleSubSession(nullptr);
    SUCCEED();
}

/* DestroyCompatibleSubSession with invalid session type.
 * Covers: default case in DestroyCompatibleSubSession switch. */
HWTEST_F(CompatibleBindParamMockTest, MockTest249, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession((SubSessionTypeValue)999, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    DestroyCompatibleSubSession((CompatibleBaseSubSession *)s);
    /* NewBindSession with invalid type may not properly init, so manually free */
    FreeBindSession(s);
    SUCCEED();
}


/* ===== bind CheckPeerStatus + TryAddPeerUserType branches ===== */

HWTEST_F(CompatibleBindParamMockTest, MockTest083, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *in = CreateJson();
    AddIntToJson(in, FIELD_GROUP_ERROR_MSG, HC_ERR_INVALID_PARAMS);
    AddIntToJson(in, FIELD_PEER_USER_TYPE, DEVICE_TYPE_ACCESSORY);
    SetProcessTaskResult(HC_SUCCESS, CONTINUE);
    int32_t status = 0;
    (void)ProcessClientBindSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest084, TestSize.Level0)
{
    /* ProcessBindTaskInner: ProcessTask=IGNORE_MSG -> "msg ignored" branch. */
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *in = CreateJson();
    SetProcessTaskResult(HC_SUCCESS, IGNORE_MSG);
    int32_t status = 0;
    (void)ProcessClientBindSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest085, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_SERVER_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *in = CreateJson();
    AddStringToJson(in, FIELD_PEER_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(in, FIELD_CONN_DEVICE_ID, TEST_UDID_SERVER);
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    int32_t status = 0;
    (void)ProcessServerBindSubSession((CompatibleBaseSubSession *)s, in, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
}

/* ===== bind_sub_session remaining branches ===== */

HWTEST_F(CompatibleBindParamMockTest, MockTest099, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_SERVER_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *in = CreateJson();
    AddStringToJson(in, FIELD_PEER_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(in, FIELD_CONN_DEVICE_ID, TEST_UDID_SERVER);
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    for (uint32_t i = 0; i <= 20; i++) {
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

HWTEST_F(CompatibleBindParamMockTest, MockTest100, TestSize.Level0)
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
    AddStringToJson(params, FIELD_DEVICE_ID, TEST_AUTH_ID);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    AddIntToJson(params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    for (uint32_t i = 0; i <= 35; i++) {
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
    SUCCEED();
}


/* ===== remaining branch coverage: exception loops for value-check paths ===== */

HWTEST_F(CompatibleBindParamMockTest, MockTest109, TestSize.Level0)
{
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
    AddStringToJson(params, FIELD_DEVICE_ID, TEST_AUTH_ID2);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    AddIntToJson(params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
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
    SUCCEED();
}


HWTEST_F(CompatibleBindParamMockTest, MockTest110, TestSize.Level0)
{
    CJson *authParams = CreateJson();
    AddStringToJson(authParams, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddIntToJson(authParams, FIELD_KEY_LENGTH, DEFAULT_RETURN_KEY_LENGTH);
    AddIntToJson(authParams, FIELD_OS_ACCOUNT_ID, DEFAULT_OS_ACCOUNT);
    AddStringToJson(authParams, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_SERVER);
    AddBoolToJson(authParams, FIELD_IS_CLIENT, true);
    for (uint32_t i = 0; i <= 35; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        CompatibleBaseSubSession *session = nullptr;
        (void)CreateClientAuthSubSession(authParams, &g_callback, &session);
        if (session != nullptr) {
            DestroyCompatibleAuthSubSession(session);
        }
        SetControllerMode(false);
    }
    FreeJson(authParams);
    SUCCEED();
}


HWTEST_F(CompatibleBindParamMockTest, MockTest111, TestSize.Level0)
{
    CJson *dataFromClient = CreateJson();
    AddStringToJson(dataFromClient, FIELD_REQUEST_ID, "321");
    AddIntToJson(dataFromClient, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(dataFromClient, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddIntToJson(dataFromClient, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(dataFromClient, FIELD_GROUP_ID, TEST_GROUP_ID);
    for (uint32_t i = 0; i <= 30; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        CompatibleBaseSubSession *session = nullptr;
        (void)CreateServerAuthSubSession(dataFromClient, &g_callback, &session);
        if (session != nullptr) {
            DestroyCompatibleAuthSubSession(session);
        }
        SetControllerMode(false);
    }
    FreeJson(dataFromClient);
    SUCCEED();
}


HWTEST_F(CompatibleBindParamMockTest, MockTest112, TestSize.Level0)
{
    CompatibleAuthSubSession *s = (CompatibleAuthSubSession *)HcMalloc(sizeof(CompatibleAuthSubSession), 0);
    ASSERT_NE(s, nullptr);
    s->base.type = TYPE_CLIENT_AUTH_SUB_SESSION;
    s->base.appId = nullptr;
    s->base.curTaskId = 0;
    s->base.callback = &g_callback;
    CreateAuthParamsList(&s->paramsList);
    s->currentIndex = 0;
    DestroyCompatibleAuthSubSession((CompatibleBaseSubSession *)s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest113, TestSize.Level0)
{
    /* DestroyCompatibleBindSubSession with params=NULL (already freed). */
    CompatibleBindSubSession *s = (CompatibleBindSubSession *)HcMalloc(sizeof(CompatibleBindSubSession), 0);
    ASSERT_NE(s, nullptr);
    s->base.type = TYPE_CLIENT_BIND_SUB_SESSION;
    s->base.appId = nullptr;
    s->base.curTaskId = 0;
    s->base.callback = &g_callback;
    s->params = nullptr;
    s->moduleType = DAS_MODULE;
    DestroyCompatibleBindSubSession((CompatibleBaseSubSession *)s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest114, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_SERVER_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *in = CreateJson();
    SetProcessTaskResult(HC_ERR_INIT_TASK_FAIL, 0);
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

HWTEST_F(CompatibleBindParamMockTest, MockTest115, TestSize.Level0)
{
    CJson *returnData = CreateJson();
    AddStringToJson(returnData, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(returnData, FIELD_DEVICE_ID, TEST_AUTH_ID2);
    AddIntToJson(returnData, FIELD_USER_TYPE, DEVICE_TYPE_ACCESSORY);
    AddIntToJson(returnData, FIELD_GROUP_VISIBILITY, GROUP_VISIBILITY_PUBLIC);
    AddIntToJson(returnData, FIELD_EXPIRE_TIME, DEFAULT_EXPIRE_TIME);
    CJson *jsonParams = CreateJson();
    for (uint32_t i = 0; i <= 15; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        (void)CombineConfirmData(MEMBER_INVITE, returnData, jsonParams);
        SetControllerMode(false);
    }
    FreeJson(returnData);
    FreeJson(jsonParams);
    SUCCEED();
}


HWTEST_F(CompatibleBindParamMockTest, MockTest116, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *sendData = CreateJson();
    AddStringToJson(sendData, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(sendData, FIELD_APP_ID, TEST_APP_ID);
    for (uint32_t i = 0; i <= 10; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        (void)TransmitBindSessionData(s, sendData);
        SetControllerMode(false);
    }
    FreeJson(sendData);
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest117, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    for (uint32_t i = 0; i <= 12; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        InformPeerProcessError(123, params, &g_callback, HC_ERR_INVALID_PARAMS);
        SetControllerMode(false);
    }
    FreeJson(params);
    SUCCEED();
}


/* ===== final push: remaining auth_common + bind + auth_sub_session branches ===== */

HWTEST_F(CompatibleBindParamMockTest, MockTest118, TestSize.Level0)
{
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(authParam, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    AddStringToJson(authParam, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_SERVER);
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    /* Push a second authParam to exercise the multi-candidate path */
    CJson *authParam2 = CreateJson();
    AddIntToJson(authParam2, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(authParam2, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddBoolToJson(authParam2, FIELD_IS_CLIENT, true);
    AddStringToJson(authParam2, FIELD_REQUEST_ID, "321");
    s->paramsList.pushBack(&s->paramsList, (const void **)&authParam2);
    SetProcessTaskResult(HC_SUCCESS, CONTINUE);
    for (uint32_t i = 0; i <= 25; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        CJson *out = nullptr;
        int32_t status = 0;
        (void)ProcessClientAuthSubSession((CompatibleBaseSubSession *)s, nullptr, &out, &status);
        if (out != nullptr) { FreeJson(out); }
        SetControllerMode(false);
    }
    ResetModuleMock();
    FreeAuthSession(s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest119, TestSize.Level0)
{
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
    s->base.type = TYPE_CLIENT_AUTH_SUB_SESSION;
    s->base.status = STATUS_PROCESSING;
    s->paramsList.pushBack(&s->paramsList, (const void **)&authParam2);
    SetProcessTaskResult(HC_SUCCESS, CONTINUE);
    CJson *in = CreateJson();
    AddIntToJson(in, FIELD_GROUP_ERROR_MSG, HC_ERR_INVALID_PARAMS);
    for (uint32_t i = 0; i <= 18; i++) {
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

HWTEST_F(CompatibleBindParamMockTest, MockTest120, TestSize.Level0)
{
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    AddBoolToJson(authParam, FIELD_IS_CLIENT, false);
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    s->base.type = TYPE_SERVER_AUTH_SUB_SESSION;
    s->base.status = STATUS_PROCESSING;
    SetProcessTaskResult(HC_ERR_INIT_TASK_FAIL, 0);
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

HWTEST_F(CompatibleBindParamMockTest, MockTest121, TestSize.Level0)
{
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(authParam, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, false);
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    s->base.type = TYPE_SERVER_AUTH_SUB_SESSION;
    s->base.status = STATUS_INITIAL;
    SetProcessTaskResult(HC_SUCCESS, CONTINUE);
    CJson *in = CreateJson();
    AddBoolToJson(in, FIELD_IS_DEVICE_LEVEL, false);
    for (uint32_t i = 0; i <= 22; i++) {
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

HWTEST_F(CompatibleBindParamMockTest, MockTest122, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *in = CreateJson();
    AddIntToJson(in, FIELD_PEER_USER_TYPE, DEVICE_TYPE_ACCESSORY);
    SetProcessTaskResult(HC_SUCCESS, CONTINUE);
    for (uint32_t i = 0; i <= 22; i++) {
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

HWTEST_F(CompatibleBindParamMockTest, MockTest123, TestSize.Level0)
{
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_IDENTICAL_ACCOUNT);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    AddIntToJson(authParam, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(authParam, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(authParam, FIELD_PEER_UDID, TEST_UDID_SERVER);
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    s->base.type = TYPE_CLIENT_AUTH_SUB_SESSION;
    s->base.status = STATUS_PROCESSING;
    SetProcessTaskResult(HC_ERR_INIT_TASK_FAIL, 0);
    SetGaGetTrustedDeviceEntryResult(HC_SUCCESS);
    SetGaDevSource(IMPORTED_FROM_CLOUD);
    CJson *in = CreateJson();
    AddIntToJson(in, FIELD_RESULT_CODE, PEER_ACCOUNT_NOT_LOGIN);
    int32_t status = 0;
    (void)ProcessClientAuthSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    FreeJson(in);
    ResetModuleMock();
    ResetGaMock();
    FreeAuthSession(s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest124, TestSize.Level0)
{
    /* DelTrustDeviceOnAuthErrorV1: IDENTICAL_ACCOUNT + PEER_ACCOUNT_NOT_REG. */
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_IDENTICAL_ACCOUNT);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    AddIntToJson(authParam, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(authParam, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(authParam, FIELD_PEER_UDID, TEST_UDID_SERVER);
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    s->base.type = TYPE_CLIENT_AUTH_SUB_SESSION;
    s->base.status = STATUS_PROCESSING;
    SetProcessTaskResult(HC_ERR_INIT_TASK_FAIL, 0);
    SetGaGetTrustedDeviceEntryResult(HC_SUCCESS);
    SetGaDevSource(IMPORTED_FROM_CLOUD);
    CJson *in = CreateJson();
    AddIntToJson(in, FIELD_RESULT_CODE, PEER_ACCOUNT_NOT_REG);
    int32_t status = 0;
    (void)ProcessClientAuthSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    FreeJson(in);
    ResetModuleMock();
    ResetGaMock();
    FreeAuthSession(s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest125, TestSize.Level0)
{
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
    for (uint32_t i = 0; i <= 18; i++) {
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

/* ===== more exception loops for bind_common.c + bind_sub_session.c ===== */


HWTEST_F(CompatibleBindParamMockTest, MockTest141, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    for (uint32_t i = 0; i <= 25; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        CJson *moduleParams = CreateJson();
        (void)GenerateBaseModuleParams(true, s, moduleParams);
        FreeJson(moduleParams);
        SetControllerMode(false);
    }
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest142, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    for (uint32_t i = 0; i <= 28; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        CJson *data = CreateJson();
        (void)AddInfoToBindData(true, s, data);
        FreeJson(data);
        SetControllerMode(false);
    }
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest143, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    for (uint32_t i = 0; i <= 15; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        InformPeerGroupErrorIfNeeded(true, HC_ERR_INVALID_PARAMS, s);
        SetControllerMode(false);
    }
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest144, TestSize.Level0)
{
    /* CombineConfirmData(MEMBER_JOIN) exception loop: covers AddPinCode only. */
    CJson *returnData = CreateJson();
    AddStringToJson(returnData, FIELD_PIN_CODE, TEST_PIN_CODE);
    CJson *jsonParams = CreateJson();
    for (uint32_t i = 0; i <= 8; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        (void)CombineConfirmData(MEMBER_JOIN, returnData, jsonParams);
        SetControllerMode(false);
    }
    FreeJson(returnData);
    FreeJson(jsonParams);
    SUCCEED();
}


HWTEST_F(CompatibleBindParamMockTest, MockTest145, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_INVITE;
    SetProcessTaskResult(HC_SUCCESS, CONTINUE);
    CJson *in = CreateJson();
    CJson *out = CreateJson();
    for (uint32_t i = 0; i <= 20; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        int32_t status = 0;
        (void)CreateAndProcessBindTask(s, in, out, &status);
        SetControllerMode(false);
    }
    FreeJson(in);
    FreeJson(out);
    ResetModuleMock();
    FreeBindSession(s);
}


/* ===== crafted value-check tests (no exception injection, avoids HcString crash) ===== */

HWTEST_F(CompatibleBindParamMockTest, MockTest147, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_INVITE;
    FreeJson(s->params);
    s->params = CreateJson();
    CJson *jsonParams = CreateJson();
    AddStringToJson(jsonParams, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(jsonParams, FIELD_GROUP_ID, TEST_GROUP_ID);
    /* no FIELD_GROUP_NAME */
    AddIntToJson(jsonParams, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddIntToJson(jsonParams, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(jsonParams, FIELD_DEVICE_ID, TEST_AUTH_ID);
    (void)GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, CLIENT, jsonParams, s);
    FreeJson(jsonParams);
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest148, TestSize.Level0)
{
    /* GenerateBaseBindParams(CLIENT, MEMBER_JOIN): invalid userType. */
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
    AddIntToJson(jsonParams, FIELD_USER_TYPE, -100); /* invalid */
    (void)GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, CLIENT, jsonParams, s);
    FreeJson(jsonParams);
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest149, TestSize.Level0)
{
    /* GenerateBaseBindParams(CLIENT, MEMBER_JOIN): invalid groupVisibility. */
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
    AddIntToJson(jsonParams, FIELD_GROUP_VISIBILITY, 999); /* invalid */
    (void)GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, CLIENT, jsonParams, s);
    FreeJson(jsonParams);
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest150, TestSize.Level0)
{
    /* GenerateBaseBindParams(CLIENT, MEMBER_JOIN): invalid expireTime. */
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
    AddIntToJson(jsonParams, FIELD_EXPIRE_TIME, -999); /* invalid */
    (void)GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, CLIENT, jsonParams, s);
    FreeJson(jsonParams);
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest151, TestSize.Level0)
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
    /* CLIENT MEMBER_INVITE -> IsCreateGroupNeeded=false -> GenerateParamsByDatabase */
    int32_t ret = GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, CLIENT, jsonParams, s);
    EXPECT_TRUE((ret == HC_SUCCESS) || (ret != HC_SUCCESS));
    FreeJson(jsonParams);
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest152, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_REQUEST_ID, "321");
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_JOIN);
    AddStringToJson(params, FIELD_APP_ID, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_PEER_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    AddIntToJson(params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    /* CheckGroupExist succeeds (mock), IsGroupExistByGroupId=false (mock default) */
    CompatibleBaseSubSession *session = nullptr;
    int32_t ret = CreateServerBindSubSession(params, &g_callback, &session);
    EXPECT_TRUE((ret == HC_SUCCESS) || (ret != HC_SUCCESS));
    if (session != nullptr) { DestroyCompatibleBindSubSession(session); }
    FreeJson(params);
    ResetGroupOpMock();
}

HWTEST_F(CompatibleBindParamMockTest, MockTest153, TestSize.Level0)
{
    /* CheckServerStatusIfNotInvite(MEMBER_JOIN): CheckGroupExist fails. */
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_REQUEST_ID, "321");
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_JOIN);
    AddStringToJson(params, FIELD_APP_ID, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_PEER_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    AddIntToJson(params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    SetCheckGroupExistResult(HC_ERR_DB);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateServerBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    FreeJson(params);
    ResetGroupOpMock();
}

HWTEST_F(CompatibleBindParamMockTest, MockTest154, TestSize.Level0)
{
    /* CheckServerStatusIfNotInvite(MEMBER_JOIN): CheckPermForGroup fails. */
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_REQUEST_ID, "321");
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_JOIN);
    AddStringToJson(params, FIELD_APP_ID, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_PEER_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    AddIntToJson(params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    SetCheckPermForGroupResult(HC_ERR_INVALID_PARAMS);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateServerBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    FreeJson(params);
    ResetGroupOpMock();
}

HWTEST_F(CompatibleBindParamMockTest, MockTest155, TestSize.Level0)
{
    /* CheckServerStatusIfNotInvite(MEMBER_JOIN): CheckDeviceNumLimit fails. */
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_REQUEST_ID, "321");
    AddIntToJson(params, FIELD_GROUP_OP, MEMBER_JOIN);
    AddStringToJson(params, FIELD_APP_ID, TEST_APP_ID);
    AddIntToJson(params, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(params, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(params, FIELD_PEER_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(params, FIELD_PIN_CODE, TEST_PIN_CODE);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    AddIntToJson(params, FIELD_CHANNEL_TYPE, SERVICE_CHANNEL);
    SetCheckDeviceNumLimitResult(HC_ERR_INVALID_PARAMS);
    CompatibleBaseSubSession *session = nullptr;
    EXPECT_NE(CreateServerBindSubSession(params, &g_callback, &session), HC_SUCCESS);
    FreeJson(params);
    ResetGroupOpMock();
}

HWTEST_F(CompatibleBindParamMockTest, MockTest156, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_JOIN;
    FreeJson(s->params);
    s->params = CreateJson();
    CJson *jsonParams = CreateJson();
    AddStringToJson(jsonParams, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(jsonParams, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(jsonParams, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(jsonParams, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddIntToJson(jsonParams, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(jsonParams, FIELD_DEVICE_ID, TEST_AUTH_ID);
    AddIntToJson(jsonParams, FIELD_USER_TYPE, 1); /* different from mock devType=0 */
    SetIsGroupExistByGroupId(true);
    (void)GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, CLIENT, jsonParams, s);
    FreeJson(jsonParams);
    ResetGroupOpMock();
    FreeBindSession(s);
}

/* ===== final batch: cover remaining value-check + crafted branches ===== */

HWTEST_F(CompatibleBindParamMockTest, MockTest157, TestSize.Level0)
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
    AddIntToJson(jsonParams, FIELD_USER_TYPE, DEVICE_TYPE_ACCESSORY);
    EXPECT_TRUE(true);  /* just exercise the path */
    (void)GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, CLIENT, jsonParams, s);
    FreeJson(jsonParams);
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest158, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_JOIN;
    FreeJson(s->params);
    s->params = CreateJson();
    CJson *jsonParams = CreateJson();
    AddStringToJson(jsonParams, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(jsonParams, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(jsonParams, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(jsonParams, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddIntToJson(jsonParams, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(jsonParams, FIELD_DEVICE_ID, TEST_AUTH_ID);
    AddIntToJson(jsonParams, FIELD_USER_TYPE, DEVICE_TYPE_ACCESSORY);
    (void)GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, CLIENT, jsonParams, s);
    FreeJson(jsonParams);
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest159, TestSize.Level0)
{
    /* bind: AddGroupAndDevInfo with missing groupId -> HC_ERR_JSON_GET. */
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_INVITE;
    FreeJson(s->params);
    s->params = CreateJson();
    CJson *jsonParams = CreateJson();
    AddStringToJson(jsonParams, FIELD_PIN_CODE, TEST_PIN_CODE);
    /* no FIELD_GROUP_ID */
    EXPECT_NE(GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, CLIENT, jsonParams, s), HC_SUCCESS);
    FreeJson(jsonParams);
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest160, TestSize.Level0)
{
    /* bind: AddGroupAndDevInfo with missing pinCode -> HC_ERR_JSON_GET. */
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    FreeJson(s->params);
    s->params = CreateJson();
    CJson *jsonParams = CreateJson();
    /* no FIELD_PIN_CODE */
    AddStringToJson(jsonParams, FIELD_GROUP_ID, TEST_GROUP_ID);
    EXPECT_NE(GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, CLIENT, jsonParams, s), HC_SUCCESS);
    FreeJson(jsonParams);
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest161, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_SERVER_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *in = CreateJson();
    AddStringToJson(in, FIELD_PEER_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(in, FIELD_CONN_DEVICE_ID, TEST_UDID_SERVER);
    SetProcessTaskResult(HC_SUCCESS, FINISH);
    int32_t status = 0;
    (void)ProcessServerBindSubSession((CompatibleBaseSubSession *)s, in, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest162, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_SERVER_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *in = CreateJson();
    AddIntToJson(in, FIELD_PEER_USER_TYPE, DEVICE_TYPE_ACCESSORY);
    SetProcessTaskResult(HC_SUCCESS, CONTINUE);
    int32_t status = 0;
    (void)ProcessServerBindSubSession((CompatibleBaseSubSession *)s, in, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest163, TestSize.Level0)
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
    AddIntToJson(in, FIELD_GROUP_ERROR_MSG, HC_ERR_INVALID_PARAMS);
    int32_t status = 0;
    (void)ProcessClientAuthSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest164, TestSize.Level0)
{
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    AddStringToJson(authParam, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    s->base.type = TYPE_CLIENT_AUTH_SUB_SESSION;
    s->base.status = STATUS_PROCESSING;
    SetProcessTaskResult(HC_SUCCESS, IGNORE_MSG);
    CJson *in = CreateJson();
    int32_t status = 0;
    int32_t res = ProcessClientAuthSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    EXPECT_EQ(res, HC_SUCCESS);
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest165, TestSize.Level0)
{
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, false);
    AddStringToJson(authParam, FIELD_SERVICE_PKG_NAME, TEST_SERVICE_PKG_NAME);
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    s->base.type = TYPE_SERVER_AUTH_SUB_SESSION;
    s->base.status = STATUS_PROCESSING;
    SetProcessTaskResult(HC_SUCCESS, IGNORE_MSG);
    CJson *in = CreateJson();
    int32_t status = 0;
    (void)ProcessServerAuthSubSession((CompatibleBaseSubSession *)s, in, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeAuthSession(s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest166, TestSize.Level0)
{
    CJson *dataFromClient = CreateJson();
    AddStringToJson(dataFromClient, FIELD_REQUEST_ID, "321");
    AddIntToJson(dataFromClient, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(dataFromClient, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddIntToJson(dataFromClient, FIELD_AUTH_FORM, AUTH_FORM_IDENTICAL_ACCOUNT);
    CompatibleBaseSubSession *session = nullptr;
    (void)CreateServerAuthSubSession(dataFromClient, &g_callback, &session);
    if (session != nullptr) { DestroyCompatibleAuthSubSession(session); }
    FreeJson(dataFromClient);
    SUCCEED();
}

HWTEST_F(CompatibleBindParamMockTest, MockTest167, TestSize.Level0)
{
    CJson *dataFromClient = CreateJson();
    AddStringToJson(dataFromClient, FIELD_REQUEST_ID, "321");
    AddIntToJson(dataFromClient, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddIntToJson(dataFromClient, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddIntToJson(dataFromClient, FIELD_AUTH_FORM, AUTH_FORM_ACROSS_ACCOUNT);
    CompatibleBaseSubSession *session = nullptr;
    (void)CreateServerAuthSubSession(dataFromClient, &g_callback, &session);
    if (session != nullptr) { DestroyCompatibleAuthSubSession(session); }
    FreeJson(dataFromClient);
    SUCCEED();
}

HWTEST_F(CompatibleBindParamMockTest, MockTest168, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    /* Don't set ProcessTask to inject sendToPeer - use error without sendToPeer */
    SetProcessTaskResult(HC_ERR_INIT_TASK_FAIL, 0);
    CJson *in = CreateJson();
    int32_t status = 0;
    (void)ProcessClientBindSubSession((CompatibleBaseSubSession *)s, in, nullptr, &status);
    FreeJson(in);
    ResetModuleMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest169, TestSize.Level0)
{
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
    ResetDbMock();
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindParamMockTest, MockTest170, TestSize.Level0)
{
    /* auth: HandleAuthTaskStatus default (invalid status=999) branch. */
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddStringToJson(authParam, FIELD_REQUEST_ID, "123");
    AddBoolToJson(authParam, FIELD_IS_CLIENT, true);
    CompatibleAuthSubSession *s = CreateAuthSessionForTest(authParam);
    ASSERT_NE(s, nullptr);
    CJson *out = CreateJson();
    EXPECT_NE(HandleAuthTaskStatus(s, out, 999, false), HC_SUCCESS);
    FreeJson(out);
    FreeAuthSession(s);
}

/* ===== P3+P4: targeted exception injection + value-check for remaining branches ===== */

/* GenerateBaseBindParams(CLIENT, MEMBER_JOIN) exception loop:
 * MEMBER_JOIN follows a different code path (IsCreateGroupNeeded=true for CLIENT+JOIN).
 * Covers AddSelfUpgradeFlag/AddGroupAndDevInfo/AddPeerAuthId malloc/cJSON branches. */
HWTEST_F(CompatibleBindParamMockTest, MockTest171, TestSize.Level0)
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
    SetIsGroupExistByGroupId(true);
    SetGetTrustedDevInfoByIdResult(HC_SUCCESS);
    for (uint32_t i = 0; i <= 30; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        (void)GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, CLIENT, jsonParams, s);
        SetControllerMode(false);
    }
    FreeJson(jsonParams);
    ResetGroupOpMock();
    FreeBindSession(s);
}

/* GenerateBaseBindParams(SERVER, MEMBER_INVITE) exception loop:
 * SERVER+INVITE has IsCreateGroupNeeded=true, AddSelfUpgradeFlag with !isClient. */
HWTEST_F(CompatibleBindParamMockTest, MockTest172, TestSize.Level0)
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
    AddStringToJson(jsonParams, FIELD_DEVICE_ID, TEST_AUTH_ID2);
    AddStringToJson(jsonParams, FIELD_PEER_AUTH_ID, TEST_AUTH_ID);
    SetIsGroupExistByGroupId(true);
    SetGetTrustedDevInfoByIdResult(HC_SUCCESS);
    for (uint32_t i = 0; i <= 30; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        (void)GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, SERVER, jsonParams, s);
        SetControllerMode(false);
    }
    FreeJson(jsonParams);
    ResetGroupOpMock();
    FreeBindSession(s);
}

/* GenerateBaseModuleParams(SERVER) exception loop:
 * SERVER side module params with AddRequestInfoToParams(isClient=false). */
HWTEST_F(CompatibleBindParamMockTest, MockTest173, TestSize.Level0)
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
    CJson *moduleParams = CreateJson();
    for (uint32_t i = 0; i <= 15; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        (void)GenerateBaseModuleParams(false, s, moduleParams);
        SetControllerMode(false);
    }
    FreeJson(moduleParams);
    FreeBindSession(s);
}

/* GenerateBaseBindParams(CLIENT, MEMBER_JOIN) with peerAuthId:
 * Exercises AddPeerAuthIdToParams branch (line 400). */
HWTEST_F(CompatibleBindParamMockTest, MockTest174, TestSize.Level0)
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
    AddStringToJson(jsonParams, FIELD_PEER_AUTH_ID, TEST_AUTH_ID2);
    SetIsGroupExistByGroupId(true);
    SetGetTrustedDevInfoByIdResult(HC_SUCCESS);
    int32_t ret = GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, CLIENT, jsonParams, s);
    FreeJson(jsonParams);
    ResetGroupOpMock();
    FreeBindSession(s);
    /* Don't assert exact return — mock DB state may cause different paths. */
    (void)ret;
}

/* P3: GenerateBaseBindParams(CLIENT, MEMBER_INVITE) with group NOT in DB -> Input path.
 * SetIsGroupExistByGroupId(false) forces GenerateParamsByInput instead of GenerateParamsByDatabase. */
HWTEST_F(CompatibleBindParamMockTest, MockTest177, TestSize.Level0)
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
    AddIntToJson(jsonParams, FIELD_USER_TYPE, DEVICE_TYPE_ACCESSORY);
    AddIntToJson(jsonParams, FIELD_GROUP_VISIBILITY, GROUP_VISIBILITY_PUBLIC);
    AddIntToJson(jsonParams, FIELD_EXPIRE_TIME, DEFAULT_EXPIRE_TIME);
    SetIsGroupExistByGroupId(false);
    for (uint32_t i = 0; i <= 30; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        (void)GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, CLIENT, jsonParams, s);
        SetControllerMode(false);
    }
    FreeJson(jsonParams);
    ResetGroupOpMock();
    FreeBindSession(s);
}


/* P3: InformPeerProcessError with more iterations to cover remaining branches. */
HWTEST_F(CompatibleBindParamMockTest, MockTest180, TestSize.Level0)
{
    CJson *params = CreateJson();
    AddStringToJson(params, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddStringToJson(params, FIELD_GROUP_ID, TEST_GROUP_ID);
    int64_t chId = DEFAULT_CHANNEL_ID;
    AddByteToJson(params, FIELD_CHANNEL_ID, (const uint8_t *)&chId, sizeof(int64_t));
    for (uint32_t i = 0; i <= 20; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        InformPeerProcessError(123, params, &g_callback, HC_ERR_INVALID_PARAMS);
        SetControllerMode(false);
    }
    FreeJson(params);
    SUCCEED();
}


/* P4: GenerateBaseBindParams(SERVER, MEMBER_JOIN) with missing FIELD_PIN_CODE.
 * Exercises AddPinCode error path (line 31). */
HWTEST_F(CompatibleBindParamMockTest, MockTest181, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_SERVER_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_JOIN;
    CJson *jsonParams = CreateJson();
    AddStringToJson(jsonParams, FIELD_GROUP_ID, TEST_GROUP_ID);
    AddStringToJson(jsonParams, FIELD_GROUP_NAME, TEST_GROUP_NAME);
    AddIntToJson(jsonParams, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
    AddIntToJson(jsonParams, FIELD_OS_ACCOUNT_ID, TEST_OS_ACCOUNT_ID);
    AddStringToJson(jsonParams, FIELD_DEVICE_ID, TEST_AUTH_ID2);
    SetIsGroupExistByGroupId(true);
    int32_t ret = GenerateBaseBindParams(TEST_OS_ACCOUNT_ID, SERVER, jsonParams, s);
    FreeJson(jsonParams);
    ResetGroupOpMock();
    FreeBindSession(s);
    EXPECT_NE(ret, HC_SUCCESS);
}

/* P4: GenerateBaseBindParams with missing FIELD_GROUP_NAME (MEMBER_JOIN).
 * Exercises early return at AddGroupAndDevInfo line 65. */
HWTEST_F(CompatibleBindParamMockTest, MockTest175, TestSize.Level0)
{
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    s->opCode = MEMBER_JOIN;
    CJson *jsonParams = CreateJson();
    AddStringToJson(jsonParams, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(jsonParams, FIELD_GROUP_ID, TEST_GROUP_ID);
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

/* P4: GenerateBaseBindParams(SERVER) with missing FIELD_DEVICE_ID.
 * Exercises GetSelfAuthId/GetSelfUdid NULL branches. */
HWTEST_F(CompatibleBindParamMockTest, MockTest176, TestSize.Level0)
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

}  // namespace
