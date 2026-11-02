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

#include "test_helper.h"
#include "common_defs.h"
#include "hc_dev_info_mock.h"
#include "hc_log.h"
#include "hc_types.h"
#include "securec.h"
#include <cstdlib>
#include <unistd.h>

/* ===== async status ===== */
enum { ASYNC_WAITING = 0, ASYNC_TRANSMIT = 1, ASYNC_FINISH = 2, ASYNC_ERROR = 3 };

static volatile int g_asyncStatus = ASYNC_WAITING;
static uint8_t g_transmitData[V1_TEST_TRANS_BUFFER_SIZE] = { 0 };
static uint32_t g_transmitDataLen = 0;
static bool g_onFinishCalled = false;

void V1ResetTransmitBuffer(V1TestContext *ctx)
{
    if (ctx != nullptr) {
        (void)memset_s(ctx->transmitData, ctx->transmitDataMaxLen, 0, ctx->transmitDataMaxLen);
        ctx->transmitDataLen = 0;
        ctx->asyncStatus = ASYNC_WAITING;
    }
    (void)memset_s(g_transmitData, V1_TEST_TRANS_BUFFER_SIZE, 0, V1_TEST_TRANS_BUFFER_SIZE);
    g_transmitDataLen = 0;
    g_asyncStatus = ASYNC_WAITING;
    g_onFinishCalled = false;
}

static bool OnTransmit(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    (void)requestId;
    if ((data == nullptr) || (dataLen == 0) || (dataLen > V1_TEST_TRANS_BUFFER_SIZE)) {
        return false;
    }
    if (memcpy_s(g_transmitData, V1_TEST_TRANS_BUFFER_SIZE, data, dataLen) != 0) {
        return false;
    }
    g_transmitDataLen = dataLen;
    g_asyncStatus = ASYNC_TRANSMIT;
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
    g_asyncStatus = ASYNC_FINISH;
    g_onFinishCalled = true;
}

static void OnError(int64_t requestId, int operationCode, int errorCode, const char *errorReturn)
{
    (void)requestId;
    (void)operationCode;
    (void)errorCode;
    (void)errorReturn;
    g_asyncStatus = ASYNC_ERROR;
}

static char *OnBindRequest(int64_t requestId, int operationCode, const char *reqParam)
{
    (void)requestId;
    (void)operationCode;
    (void)reqParam;
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, V1_TEST_OS_ACCOUNT_ID);
    AddStringToJson(json, FIELD_PIN_CODE, V1_TEST_PIN_CODE);
    AddStringToJson(json, FIELD_DEVICE_ID, V1_TEST_AUTH_ID2);
    AddStringToJson(json, FIELD_SERVICE_PKG_NAME, V1_TEST_SERVICE_PKG_NAME);
    AddStringToJson(json, FIELD_PEER_CONN_DEVICE_ID, V1_TEST_UDID_CLIENT);
    char *str = PackJsonToString(json);
    FreeJson(json);
    return str;
}

static DeviceAuthCallback g_gmCallback = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnBindRequest,
};

static bool FailOnTransmit(int64_t, const uint8_t *, uint32_t) { return false; }
static DeviceAuthCallback g_failCallback = {
    .onTransmit = FailOnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnBindRequest,
};

const DeviceAuthCallback *V1GetGmCallback(void) { return &g_gmCallback; }
const DeviceAuthCallback *V1GetFailCallback(void) { return &g_failCallback; }

/* ===== database cleanup ===== */
void V1DeleteDatabase(void)
{
    (void)system("rm -rf " V1_TEST_GROUP_DATA_PATH);
    (void)system("rm -rf " V1_TEST_HKS_MAIN_DATA_PATH);
}

int32_t V1CreateDemoGroup(int32_t osAccountId, int64_t reqId, const char *appId, const char *createParams)
{
    g_asyncStatus = ASYNC_WAITING;
    g_onFinishCalled = false;
    const DeviceGroupManager *gm = GetGmInstance();
    if (gm == nullptr) {
        return HC_ERROR;
    }
    int32_t ret = gm->createGroup(osAccountId, reqId, appId, createParams);
    if (ret != HC_SUCCESS) {
        return ret;
    }
    int32_t wait = 0;
    while (!g_onFinishCalled && (wait < V1_TEST_MAX_WAIT_ROUNDS)) {
        usleep(V1_TEST_SLEEP_TIME);
        ++wait;
    }
    usleep(V1_TEST_SLEEP_TIME);
    return g_onFinishCalled ? HC_SUCCESS : HC_ERROR;
}

/* ===== session construction helpers ===== */
static void FillBindParams(CompatibleBindSubSession *session)
{
    AddStringToJson(session->params, FIELD_GROUP_ID, V1_TEST_GROUP_ID);
    AddStringToJson(session->params, FIELD_GROUP_NAME, V1_TEST_GROUP_NAME);
    AddStringToJson(session->params, FIELD_AUTH_ID, V1_TEST_AUTH_ID);
    AddStringToJson(session->params, FIELD_CONN_DEVICE_ID, V1_TEST_UDID_CLIENT);
    AddStringToJson(session->params, FIELD_PEER_AUTH_ID, V1_TEST_AUTH_ID2);
    AddStringToJson(session->params, FIELD_PEER_UDID, V1_TEST_UDID_SERVER);
    AddIntToJson(session->params, FIELD_USER_TYPE, DEVICE_TYPE_ACCESSORY);
}

CompatibleBindSubSession *V1NewBindSession(int32_t type, int32_t status)
{
    CompatibleBindSubSession *s = (CompatibleBindSubSession *)HcMalloc(sizeof(CompatibleBindSubSession), 0);
    if (s == nullptr) { return nullptr; }
    s->base.type = type;
    s->base.appId = (char *)HcMalloc(HcStrlen(V1_TEST_APP_ID) + 1, 0);
    if (s->base.appId != nullptr) {
        (void)memcpy_s(s->base.appId, HcStrlen(V1_TEST_APP_ID) + 1, V1_TEST_APP_ID, HcStrlen(V1_TEST_APP_ID) + 1);
    }
    s->base.curTaskId = V1_TEST_CUR_TASK_ID;
    s->base.status = (SubSessionStatusValue)status;
    s->base.callback = V1GetGmCallback();
    s->opCode = MEMBER_INVITE;
    s->moduleType = DAS_MODULE;
    s->reqId = V1_TEST_SESSION_REQ_ID;
    s->osAccountId = V1_TEST_OS_ACCOUNT_ID;
    s->channelType = SERVICE_CHANNEL;
    s->channelId = DEFAULT_CHANNEL_ID;
    s->params = CreateJson();
    FillBindParams(s);
    return s;
}

void V1FreeBindSession(CompatibleBindSubSession *session)
{
    if (session == nullptr) { return; }
    HcFree(session->base.appId);
    session->base.appId = nullptr;
    FreeJson(session->params);
    session->params = nullptr;
    HcFree(session);
}

CompatibleAuthSubSession *V1NewAuthSession(int32_t type, int32_t status, CJson *authParam)
{
    CompatibleAuthSubSession *s = (CompatibleAuthSubSession *)HcMalloc(sizeof(CompatibleAuthSubSession), 0);
    if (s == nullptr) { return nullptr; }
    s->base.type = type;
    s->base.appId = nullptr;
    s->base.curTaskId = V1_TEST_CUR_TASK_ID;
    s->base.status = (SubSessionStatusValue)status;
    s->base.callback = V1GetGmCallback();
    CreateAuthParamsList(&s->paramsList);
    s->currentIndex = 0;
    if (authParam != nullptr) {
        s->paramsList.pushBack(&s->paramsList, (const void **)&authParam);
    }
    return s;
}

void V1FreeAuthSession(CompatibleAuthSubSession *session)
{
    if (session == nullptr) { return; }
    HcFree(session->base.appId);
    session->base.appId = nullptr;
    uint32_t index;
    void **p = nullptr;
    FOR_EACH_HC_VECTOR(session->paramsList, index, p) {
        FreeJson((CJson *)*p);
    }
    DestroyAuthParamsList(&session->paramsList);
    HcFree(session);
}
