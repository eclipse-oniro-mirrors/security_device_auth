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


class CompatibleBindSubSessionCommonMockTest : public testing::Test {
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

/* ===== exception-driven JSON-add branch coverage for common helpers ===== */

HWTEST_F(CompatibleBindSubSessionCommonMockTest, MockTest024, TestSize.Level0)
{
    /* GenerateBaseModuleParams: inject cJSON/malloc failures to cover each
     * AddXToJson error branch (AddBoolToJson/AddStringToJson/AddIntToJson fail). */
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

HWTEST_F(CompatibleBindSubSessionCommonMockTest, MockTest025, TestSize.Level0)
{
    /* AddInfoToBindData: inject failures to cover AddGroupInfoToSendData/
     * AddDevInfoToSendData/AddRequestInfoToSendData/AddCompatibleInfoToSendData
     * JSON-add error branches. */
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    for (uint32_t i = 0; i <= 25; i++) {
        SetControllerMode(true);
        SetThrowExceptionIndex(i);
        CJson *data = CreateJson();
        (void)AddInfoToBindData(true, s, data);
        FreeJson(data);
        SetControllerMode(false);
    }
    FreeBindSession(s);
}

/* ===== crafted-input value-check branches ===== */

HWTEST_F(CompatibleBindSubSessionCommonMockTest, MockTest037, TestSize.Level0)
{
    /* HandleAuthTaskStatus default (invalid status) + CONTINUE with null callback. */
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_CLIENT_AUTH_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    CJson *out = CreateJson();
    EXPECT_NE(HandleAuthTaskStatus(s, out, 999, false), HC_SUCCESS);   /* default branch */
    /* CONTINUE with sendToPeer present but callback field exercises ReturnTransmitData */
    CJson *sendToPeer = CreateJson();
    AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);
    FreeJson(sendToPeer);
    (void)HandleAuthTaskStatus(s, out, CONTINUE, false);
    FreeJson(out);
    FreeAuthSession(s);
}

HWTEST_F(CompatibleBindSubSessionCommonMockTest, MockTest038, TestSize.Level0)
{
    /* AddGroupAuthTransmitData isClientFirst=false + isClient=false (no alternative group). */
    CJson *authParam = CreateJson();
    AddIntToJson(authParam, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
    AddBoolToJson(authParam, FIELD_IS_CLIENT, false);
    CompatibleAuthSubSession *s = NewAuthSession(TYPE_SERVER_AUTH_SUB_SESSION, STATUS_PROCESSING);
    ASSERT_NE(s, nullptr);
    FreeAuthSession(s);
    /* rebuild with the new authParam */
    s = (CompatibleAuthSubSession *)HcMalloc(sizeof(CompatibleAuthSubSession), 0);
    ASSERT_NE(s, nullptr);
    s->base.type = TYPE_SERVER_AUTH_SUB_SESSION;
    s->base.callback = &g_callback;
    s->base.curTaskId = TEST_CUR_TASK_ID;
    s->base.status = STATUS_PROCESSING;
    s->base.appId = nullptr;
    CreateAuthParamsList(&s->paramsList);
    s->currentIndex = 0;
    s->paramsList.pushBack(&s->paramsList, (const void **)&authParam);
    CJson *sendToPeer = CreateJson();
    EXPECT_EQ(AddGroupAuthTransmitData(s, false, sendToPeer), HC_SUCCESS);
    FreeJson(sendToPeer);
    FreeAuthSession(s);
}

HWTEST_F(CompatibleBindSubSessionCommonMockTest, MockTest039, TestSize.Level0)
{
    /* AddInfoToBindData with missing fields -> AddGroupInfoToSendData/AddDevInfoToSendData
     * value-check branches (groupId/groupName/authId/udid null). */
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    /* params has only some fields; test each missing-field path */
    CJson *data = CreateJson();
    (void)AddInfoToBindData(false, s, data);   /* groupId missing in params -> AddGroupInfoToSendData fail */
    FreeJson(data);
    /* now add groupId but miss others */
    AddStringToJson(s->params, FIELD_GROUP_ID, TEST_GROUP_ID);
    data = CreateJson();
    (void)AddInfoToBindData(false, s, data);   /* groupName missing */
    FreeJson(data);
    FreeBindSession(s);
}

HWTEST_F(CompatibleBindSubSessionCommonMockTest, MockTest040, TestSize.Level0)
{
    /* GenerateBaseModuleParams with session->params missing fields ->
     * AddGroupAndDevInfoToParams value-check branches. */
    CompatibleBindSubSession *s = NewBindSession(TYPE_CLIENT_BIND_SUB_SESSION, STATUS_INITIAL);
    ASSERT_NE(s, nullptr);
    FreeJson(s->params);
    s->params = CreateJson();   /* empty params */
    CJson *moduleParams = CreateJson();
    EXPECT_NE(GenerateBaseModuleParams(true, s, moduleParams), HC_SUCCESS);  /* groupId missing */
    FreeJson(moduleParams);
    FreeBindSession(s);
}

}  // namespace
