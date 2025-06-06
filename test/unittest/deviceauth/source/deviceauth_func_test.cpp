/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>
#include <unistd.h>

#include "account_module_defines.h"
#include "alg_loader.h"
#include "common_defs.h"
#include "creds_manager.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "device_auth_ext.h"
#include "deviceauth_standard_test.h"
#include "hc_dev_info_mock.h"
#include "json_utils.h"
#include "json_utils_mock.h"
#include "protocol_task_main_mock.h"
#include "securec.h"
#include "key_manager.h"

using namespace std;
using namespace testing::ext;

namespace {
#define TEST_REQ_ID 123
#define TEST_REQ_ID2 321
#define TEST_REQ_ID3 1234
#define TEST_REQ_ID4 4321
#define TEST_APP_ID "TestAppId"
#define TEST_UDID "TestUdid"
#define TEST_UDID_CLIENT "5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242B3930"
#define TEST_UDID_SERVER "52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C"
#define TEST_PIN_CODE "123456"
#define TEST_PIN_CODE1 "654321"
#define TEST_USER_ID "4269DC28B639681698809A67EDAD08E39F207900038F91FEF95DD042FE2874E4"
#define TEST_AUTH_ID2 "TestAuthId2"
#define TEST_GROUP_ID "E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C2874C230C7C21"
#define TEST_PSEUDONYM_ID "TestPseudonymId"
#define TEST_INDEX_KEY "TestIndexKey"
#define TEST_REQUEST_JSON_STR "TestRequestJsonStr"
#define TEST_INVALID_AUTH_PARAMS "TestInvalidAuthParams"
#define TEST_INVALID_ADD_PARAMS "TestInvalidAddParams"
#define TEST_GROUP_DATA_PATH "/data/service/el1/public/deviceauthMock"
#define TEST_HKS_MAIN_DATA_PATH "/data/service/el1/public/huks_service/tmp/+0+0+0+0"
#define TEST_DEV_AUTH_SLEEP_TIME 50000
#define TEST_DEV_AUTH_SLEEP_TIME2 60000
#define TEST_DEV_AUTH_TEMP_KEY_PAIR_LEN 32
static const int32_t TEST_AUTH_OS_ACCOUNT_ID = 100;
static const int TEST_DEV_AUTH_BUFFER_SIZE = 128;

static const char *AUTH_WITH_PIN_PARAMS = "{\"osAccountId\":100,\"acquireType\":0,\"pinCode\":\"123456\"}";

static const char *AUTH_DIRECT_PARAMS =
    "{\"osAccountId\":100,\"acquireType\":0,\"serviceType\":\"service.type.import\",\"peerConnDeviceId\":"
    "\"52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C"
    "749558BD2E6492C\",\"peerOsAccountId\":100}";

static const char *DEVICE_LEVEL_AUTH_PARAMS =
    "{\"peerConnDeviceId\":\"52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C\","
    "\"serviceType\":\"service.type.import\",\"servicePkgName\":\"TestAppId\",\"isClient\":true,"
    "\"isDeviceLevel\":true,\"peerOsAccountId\":100}";

static const char *GET_REGISTER_INFO_PARAMS =
    "{\"version\":\"1.0.0\",\"deviceId\":\"TestAuthIdClient\",\"userId\":\"4269DC28B639681698809A67EDAD08E39F20"
    "7900038F91FEF95DD042FE2874E4\"}";

static const char *GET_REGISTER_INFO_PARAMS1 =
    "{\"version\":\"1.0.0\",\"deviceId\":\"TestAuthIdServer\",\"userId\":\"4269DC28B639681698809A67EDAD08E39F20"
    "7900038F91FEF95DD042FE2874E4\"}";

static const char *AUTH_PARAMS = "{\"peerConnDeviceId\":\"52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C"
    "749558BD2E6492C\",\"servicePkgName\":\"TestAppId\",\"isClient\":true}";

static const char *CREATE_PARAMS = "{\"groupName\":\"TestGroup\",\"deviceId\":\"TestAuthId\",\"groupType\":256,\"group"
    "Visibility\":-1,\"userType\":0,\"expireTime\":-1}";

static const char *ADD_PARAMS =
    "{\"groupId\":\"E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C2874C230C7C21\","
    "\"groupType\":256,\"pinCode\":\"123456\"}";

static const char *DISBAND_PARAMS =
    "{\"groupId\":\"E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C2874C230C7C21\"}";

enum AsyncStatus {
    ASYNC_STATUS_WAITING = 0,
    ASYNC_STATUS_TRANSMIT = 1,
    ASYNC_STATUS_FINISH = 2,
    ASYNC_STATUS_ERROR = 3
};

static AsyncStatus volatile g_asyncStatus;
static const uint32_t TRANSMIT_DATA_MAX_LEN = 2048;
static uint8_t g_transmitData[TRANSMIT_DATA_MAX_LEN] = { 0 };
static uint32_t g_transmitDataLen = 0;

static bool OnTransmit(int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    if (memcpy_s(g_transmitData, TRANSMIT_DATA_MAX_LEN, data, dataLen) != EOK) {
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
    return;
}

static void OnFinish(int64_t requestId, int operationCode, const char *authReturn)
{
    g_asyncStatus = ASYNC_STATUS_FINISH;
}

static void OnError(int64_t requestId, int operationCode, int errorCode, const char *errorReturn)
{
    g_asyncStatus = ASYNC_STATUS_ERROR;
}

static char *OnBindRequest(int64_t requestId, int operationCode, const char* reqParam)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, TEST_AUTH_OS_ACCOUNT_ID);
    AddStringToJson(json, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(json, FIELD_DEVICE_ID, TEST_AUTH_ID2);
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
}

static char *OnBindRequestMismatch(int64_t requestId, int operationCode, const char* reqParam)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, TEST_AUTH_OS_ACCOUNT_ID);
    AddStringToJson(json, FIELD_PIN_CODE, TEST_PIN_CODE1);
    AddStringToJson(json, FIELD_DEVICE_ID, TEST_AUTH_ID2);
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
}

static char *OnBindRequest1(int64_t requestId, int operationCode, const char* reqParam)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, TEST_AUTH_OS_ACCOUNT_ID);
    AddStringToJson(json, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(json, FIELD_DEVICE_ID, TEST_AUTH_ID2);
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
}

static char *OnBindRequest2(int64_t requestId, int operationCode, const char* reqParam)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, INVALID_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(json, FIELD_DEVICE_ID, TEST_AUTH_ID2);
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
}

static char *OnAuthRequest(int64_t requestId, int operationCode, const char *reqParam)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, TEST_AUTH_OS_ACCOUNT_ID);
    AddStringToJson(json, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_CLIENT);
    AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
}

static char *OnRejectRequest(int64_t requestId, int operationCode, const char *reqParam)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_CONFIRMATION, REQUEST_REJECTED);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, TEST_AUTH_OS_ACCOUNT_ID);
    AddStringToJson(json, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_CLIENT);
    AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
}

static char *OnInvalidRequest(int64_t requestId, int operationCode, const char *reqParam)
{
    (void)requestId;
    (void)operationCode;
    (void)reqParam;
    return nullptr;
}

static char *OnInvalidRequest1(int64_t requestId, int operationCode, const char *reqParam)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, TEST_AUTH_OS_ACCOUNT_ID);
    AddStringToJson(json, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_CLIENT);
    AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
}

static char *OnInvalidRequest2(int64_t requestId, int operationCode, const char *reqParam)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, INVALID_OS_ACCOUNT);
    AddStringToJson(json, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_CLIENT);
    AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
}

static char *OnInvalidRequest3(int64_t requestId, int operationCode, const char *reqParam)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, TEST_AUTH_OS_ACCOUNT_ID);
    AddStringToJson(json, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_CLIENT);
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
}

static char *OnInvalidRequest4(int64_t requestId, int operationCode, const char *reqParam)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, TEST_AUTH_OS_ACCOUNT_ID);
    AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
}

static char *OnAuthRequestDirectTmp(int64_t requestId, int operationCode, const char *reqParam)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(json, FIELD_PIN_CODE, TEST_PIN_CODE);
    AddStringToJson(json, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_CLIENT);
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
}

static char *OnAuthRequestDirect(int64_t requestId, int operationCode, const char *reqParam)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddStringToJson(json, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_CLIENT);
    AddStringToJson(json, FIELD_SERVICE_TYPE, SERVICE_TYPE_IMPORT);
    AddIntToJson(json, FIELD_PEER_OS_ACCOUNT_ID, TEST_AUTH_OS_ACCOUNT_ID);
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
}

static char *OnDaAuthRequest(int64_t requestId, int operationCode, const char *reqParam)
{
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_CONFIRMATION, REQUEST_ACCEPTED);
    AddIntToJson(json, FIELD_OS_ACCOUNT_ID, TEST_AUTH_OS_ACCOUNT_ID);
    AddIntToJson(json, FIELD_PEER_OS_ACCOUNT_ID, TEST_AUTH_OS_ACCOUNT_ID);
    AddStringToJson(json, FIELD_PEER_CONN_DEVICE_ID, TEST_UDID_CLIENT);
    AddStringToJson(json, FIELD_SERVICE_PKG_NAME, TEST_APP_ID);
    AddStringToJson(json, FIELD_SERVICE_TYPE, SERVICE_TYPE_IMPORT);
    char *returnDataStr = PackJsonToString(json);
    FreeJson(json);
    return returnDataStr;
}

static DeviceAuthCallback g_gmCallback = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnBindRequest
};

static DeviceAuthCallback g_gmMismatchCallback = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnBindRequestMismatch
};

static DeviceAuthCallback g_invalidBindCallback = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnBindRequest1
};

static DeviceAuthCallback g_invalidBindCallback1 = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnBindRequest2
};

static DeviceAuthCallback g_gaCallback = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnAuthRequest
};

static DeviceAuthCallback g_rejectCallback = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnRejectRequest
};

static DeviceAuthCallback g_invalidCallback = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnInvalidRequest
};

static DeviceAuthCallback g_invalidCallback1 = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnInvalidRequest1
};

static DeviceAuthCallback g_invalidCallback2 = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnInvalidRequest2
};

static DeviceAuthCallback g_invalidCallback3 = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnInvalidRequest3
};

static DeviceAuthCallback g_invalidCallback4 = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnInvalidRequest4
};

static DeviceAuthCallback g_daTmpCallback = { .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnAuthRequestDirectTmp
};

static DeviceAuthCallback g_daLTCallback = { .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnAuthRequestDirect
};

static DeviceAuthCallback g_daCallback = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnDaAuthRequest
};

static void AuthDeviceDirectWithPinDemo(const char *startAuthParams, const DeviceAuthCallback *callback)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    bool isClient = true;
    SetDeviceStatus(isClient);

    int32_t ret = StartAuthDevice(TEST_REQ_ID, startAuthParams, callback);
    if (ret != HC_SUCCESS) {
        g_asyncStatus = ASYNC_STATUS_ERROR;
        return;
    }
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    while (g_asyncStatus == ASYNC_STATUS_TRANSMIT) {
        isClient = !isClient;
        SetDeviceStatus(isClient);
        g_asyncStatus = ASYNC_STATUS_WAITING;
        CJson *json = CreateJson();
        AddIntToJson(json, FIELD_OS_ACCOUNT_ID, TEST_AUTH_OS_ACCOUNT_ID);
        AddStringToJson(json, "data", (const char *)g_transmitData);
        char *autParams = PackJsonToString(json);
        FreeJson(json);
        if (isClient) {
            ret = ProcessAuthDevice(TEST_REQ_ID, autParams, callback);
        } else {
            ret = ProcessAuthDevice(TEST_REQ_ID2, autParams, callback);
        }
        FreeJsonString(autParams);
        (void)memset_s(g_transmitData, TRANSMIT_DATA_MAX_LEN, 0, TRANSMIT_DATA_MAX_LEN);
        g_transmitDataLen = 0;
        if (ret != HC_SUCCESS) {
            g_asyncStatus = ASYNC_STATUS_ERROR;
            return;
        }
        while (g_asyncStatus == ASYNC_STATUS_WAITING) {
            usleep(TEST_DEV_AUTH_SLEEP_TIME);
        }
        if (g_asyncStatus == ASYNC_STATUS_ERROR) {
            break;
        }
        if (g_transmitDataLen > 0) {
            g_asyncStatus = ASYNC_STATUS_TRANSMIT;
        }
    }
    SetDeviceStatus(true);
}

static void AuthDeviceDirectDemo(const char *startAuthParams, const DeviceAuthCallback *callback)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    bool isClient = true;
    SetDeviceStatus(isClient);

    int32_t ret = StartAuthDevice(TEST_REQ_ID, startAuthParams, callback);
    if (ret != HC_SUCCESS) {
        g_asyncStatus = ASYNC_STATUS_ERROR;
        return;
    }
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    while (g_asyncStatus == ASYNC_STATUS_TRANSMIT) {
        isClient = !isClient;
        SetDeviceStatus(isClient);
        g_asyncStatus = ASYNC_STATUS_WAITING;
        CJson *json = CreateJson();
        AddIntToJson(json, FIELD_OS_ACCOUNT_ID, TEST_AUTH_OS_ACCOUNT_ID);
        AddStringToJson(json, "data", (const char *)g_transmitData);
        char *autParams = PackJsonToString(json);
        FreeJson(json);
        if (isClient) {
            ret = ProcessAuthDevice(TEST_REQ_ID, autParams, callback);
        } else {
            ret = ProcessAuthDevice(TEST_REQ_ID2, autParams, callback);
        }
        FreeJsonString(autParams);
        (void)memset_s(g_transmitData, TRANSMIT_DATA_MAX_LEN, 0, TRANSMIT_DATA_MAX_LEN);
        g_transmitDataLen = 0;
        if (ret != HC_SUCCESS) {
            g_asyncStatus = ASYNC_STATUS_ERROR;
            return;
        }
        while (g_asyncStatus == ASYNC_STATUS_WAITING) {
            usleep(TEST_DEV_AUTH_SLEEP_TIME);
        }
        if (g_asyncStatus == ASYNC_STATUS_ERROR) {
            break;
        }
        if (g_transmitDataLen > 0) {
            g_asyncStatus = ASYNC_STATUS_TRANSMIT;
        }
    }
    SetDeviceStatus(true);
}

static void DeviceLevelAuthDemo(void)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    bool isClient = true;
    SetDeviceStatus(isClient);
    const GroupAuthManager *ga = GetGaInstance();
    ASSERT_NE(ga, nullptr);
    int32_t ret = ga->authDevice(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, DEVICE_LEVEL_AUTH_PARAMS, &g_daCallback);
    if (ret != HC_SUCCESS) {
        g_asyncStatus = ASYNC_STATUS_ERROR;
        return;
    }
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    while (g_asyncStatus == ASYNC_STATUS_TRANSMIT) {
        isClient = !isClient;
        SetDeviceStatus(isClient);
        g_asyncStatus = ASYNC_STATUS_WAITING;
        if (isClient) {
            ret = ga->processData(TEST_REQ_ID, g_transmitData, g_transmitDataLen, &g_daCallback);
        } else {
            ret = ga->processData(TEST_REQ_ID2, g_transmitData, g_transmitDataLen, &g_daCallback);
        }
        (void)memset_s(g_transmitData, TRANSMIT_DATA_MAX_LEN, 0, TRANSMIT_DATA_MAX_LEN);
        g_transmitDataLen = 0;
        if (ret != HC_SUCCESS) {
            g_asyncStatus = ASYNC_STATUS_ERROR;
            return;
        }
        while (g_asyncStatus == ASYNC_STATUS_WAITING) {
            usleep(TEST_DEV_AUTH_SLEEP_TIME);
        }
        if (g_asyncStatus == ASYNC_STATUS_ERROR) {
            break;
        }
        if (g_transmitDataLen > 0) {
            g_asyncStatus = ASYNC_STATUS_TRANSMIT;
        }
    }
    SetDeviceStatus(true);
}

static void CreateCredentialParamsJson(int32_t osAccountId, const char *deviceId, int32_t flag,
    const char *serviceType, CJson *out)
{
    AddIntToJson(out, FIELD_OS_ACCOUNT_ID, osAccountId);
    AddStringToJson(out, FIELD_DEVICE_ID, deviceId);
    AddStringToJson(out, FIELD_SERVICE_TYPE, serviceType);
    AddIntToJson(out, FIELD_ACQURIED_TYPE, P2P_BIND);
    (void)AddIntToJson(out, FIELD_PEER_OS_ACCOUNT_ID, TEST_AUTH_OS_ACCOUNT_ID);

    if (flag >= 0) {
        AddIntToJson(out, FIELD_CRED_OP_FLAG, flag);
    }
    return;
}

static int32_t ProcessCredentiaCreateDemo(const int32_t osAccountId, const bool isClient, const char *udid)
{
    int32_t flag = RETURN_FLAG_PUBLIC_KEY;
    CJson *json = CreateJson();
    if (json == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    CreateCredentialParamsJson(osAccountId, udid, flag, DEFAULT_SERVICE_TYPE, json);
    char *requestParams = PackJsonToString(json);
    FreeJson(json);
    char *returnData = nullptr;
    SetDeviceStatus(isClient);

    int32_t res = ProcessCredential(CRED_OP_CREATE, requestParams, &returnData);
    FreeJsonString(requestParams);
    if (returnData) {
        printf("returnData: %s\n", returnData);
        FreeJsonString(returnData);
    }
    SetDeviceStatus(true);
    return res;
}

static int32_t ProcessCredentialQueryDemo(
    const int32_t osAccountId, const bool isClient, const char *udid, char **publicKey)
{
    int32_t flag = RETURN_FLAG_PUBLIC_KEY;

    char *returnData = nullptr;
    SetDeviceStatus(isClient);
    CJson *json = CreateJson();
    if (json == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    CreateCredentialParamsJson(osAccountId, udid, flag, DEFAULT_SERVICE_TYPE, json);
    char *requestParams = PackJsonToString(json);
    FreeJson(json);

    int32_t res = ProcessCredential(CRED_OP_QUERY, requestParams, &returnData);
    FreeJsonString(requestParams);
    if (returnData) {
        printf("returnData: %s\n", returnData);
        CJson *in = CreateJsonFromString(returnData);
        if (in == nullptr) {
            printf("CreateJsonFromString returnData failed !\n");
        } else {
            const char *returnPk = GetStringFromJson(in, FIELD_PUBLIC_KEY);
            (void)DeepCopyString(returnPk, publicKey);
            FreeJson(in);
        }
        FreeJsonString(returnData);
    }
    SetDeviceStatus(true);
    return res;
}

static int32_t ProcessCredentialDemoImpPubKey(
    const int32_t osAccountId, const bool isClient, const char *udid, const char *publicKey)
{
    CJson *json = CreateJson();
    if (json == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    CreateCredentialParamsJson(osAccountId, udid, RETURN_FLAG_INVALID, SERVICE_TYPE_IMPORT, json);
    AddStringToJson(json, FIELD_PUBLIC_KEY, publicKey);
    char *requestParams = PackJsonToString(json);
    FreeJson(json);
    char *returnData = nullptr;
    SetDeviceStatus(isClient);

    int32_t res = ProcessCredential(CRED_OP_IMPORT, requestParams, &returnData);
    FreeJsonString(requestParams);
    if (returnData != nullptr) {
        FreeJsonString(returnData);
    }
    SetDeviceStatus(true);
    return res;
}

static int32_t CreateServerKeyPair()
{
    SetDeviceStatus(false);
    CJson *json = CreateJson();
    if (json == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    CreateCredentialParamsJson(TEST_AUTH_OS_ACCOUNT_ID, TEST_UDID_SERVER,
        RETURN_FLAG_PUBLIC_KEY, DEFAULT_SERVICE_TYPE, json);
    char *requestParams = PackJsonToString(json);
    FreeJson(json);
    char *returnData = nullptr;

    printf("ProcessCredentialDemo: operationCode=%d\n", CRED_OP_CREATE);
    int32_t res = ProcessCredential(CRED_OP_CREATE, requestParams, &returnData);
    FreeJsonString(requestParams);
    if (returnData) {
        printf("returnData: %s\n", returnData);
        FreeJsonString(returnData);
    }
    SetDeviceStatus(true);
    return res;
}

static int32_t DeleteServerKeyPair()
{
    SetDeviceStatus(false);
    CJson *json = CreateJson();
    if (json == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    CreateCredentialParamsJson(TEST_AUTH_OS_ACCOUNT_ID, TEST_UDID_SERVER,
        RETURN_FLAG_PUBLIC_KEY, DEFAULT_SERVICE_TYPE, json);
    char *requestParams = PackJsonToString(json);
    FreeJson(json);
    char *returnData = nullptr;

    printf("ProcessCredentialDemo: operationCode=%d\n", CRED_OP_DELETE);
    int32_t res = ProcessCredential(CRED_OP_DELETE, requestParams, &returnData);
    FreeJsonString(requestParams);
    if (returnData) {
        printf("returnData: %s\n", returnData);
        FreeJsonString(returnData);
    }
    SetDeviceStatus(true);
    return res;
}

static int32_t DeleteAllCredentails()
{
    SetDeviceStatus(false);
    CJson *json = CreateJson();
    if (json == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    CreateCredentialParamsJson(TEST_AUTH_OS_ACCOUNT_ID, TEST_UDID_SERVER,
        RETURN_FLAG_DEFAULT, DEFAULT_SERVICE_TYPE, json);
    char *requestParams = PackJsonToString(json);
    FreeJson(json);
    char *returnData = nullptr;
    ProcessCredential(CRED_OP_DELETE, requestParams, &returnData);
    FreeJsonString(requestParams);

    json = CreateJson();
    if (json == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    CreateCredentialParamsJson(TEST_AUTH_OS_ACCOUNT_ID, TEST_UDID_CLIENT,
        RETURN_FLAG_DEFAULT, SERVICE_TYPE_IMPORT, json);
    requestParams = PackJsonToString(json);
    FreeJson(json);
    ProcessCredential(CRED_OP_DELETE, requestParams, &returnData);
    FreeJsonString(requestParams);

    SetDeviceStatus(true);
    json = CreateJson();
    if (json == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    CreateCredentialParamsJson(TEST_AUTH_OS_ACCOUNT_ID, TEST_UDID_CLIENT,
        RETURN_FLAG_DEFAULT, DEFAULT_SERVICE_TYPE, json);
    requestParams = PackJsonToString(json);
    FreeJson(json);
    ProcessCredential(CRED_OP_DELETE, requestParams, &returnData);
    FreeJsonString(requestParams);

    json = CreateJson();
    if (json == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    CreateCredentialParamsJson(TEST_AUTH_OS_ACCOUNT_ID, TEST_UDID_SERVER,
        RETURN_FLAG_DEFAULT, SERVICE_TYPE_IMPORT, json);
    requestParams = PackJsonToString(json);
    FreeJson(json);
    ProcessCredential(CRED_OP_DELETE, requestParams, &returnData);
    FreeJsonString(requestParams);

    return HC_SUCCESS;
}

static int32_t ProcessCredentialDemo(int operationCode, const char *serviceType)
{
    int32_t flag = RETURN_FLAG_INVALID;
    if (operationCode == CRED_OP_CREATE || operationCode == CRED_OP_QUERY) {
        flag = RETURN_FLAG_PUBLIC_KEY;
    }
    CJson *json = CreateJson();
    if (json == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    CreateCredentialParamsJson(TEST_AUTH_OS_ACCOUNT_ID, TEST_UDID, flag, serviceType, json);
    char *requestParams = PackJsonToString(json);
    FreeJson(json);
    char *returnData = nullptr;
    SetDeviceStatus(true);

    printf("ProcessCredentialDemo: operationCode=%d\n", operationCode);
    int32_t res = ProcessCredential(operationCode, requestParams, &returnData);
    FreeJsonString(requestParams);
    if (returnData) {
        printf("returnData: %s\n", returnData);
        FreeJsonString(returnData);
    }
    SetDeviceStatus(true);
    return res;
}

static int32_t ProcessCredentialDemoImport(const char *importServiceType)
{
    CJson *json = CreateJson();
    if (json == NULL) {
        return HC_ERR_ALLOC_MEMORY;
    }
    CreateCredentialParamsJson(TEST_AUTH_OS_ACCOUNT_ID, TEST_UDID, RETURN_FLAG_INVALID, importServiceType, json);
    AddStringToJson(json, FIELD_PUBLIC_KEY,
        "CA32A9DFACB944B1F6292C9AE10783F6376A987A9CE30C13300BC866917DFF2E");
    char *requestParams = PackJsonToString(json);
    FreeJson(json);
    char *returnData = nullptr;
    SetDeviceStatus(false);

    printf("ProcessCredentialDemoImport\n");
    int32_t res = ProcessCredential(CRED_OP_IMPORT, requestParams, &returnData);
    FreeJsonString(requestParams);
    if (returnData) {
        FreeJsonString(returnData);
    }
    SetDeviceStatus(true);
    return res;
}

static void CreateDemoGroup(int32_t osAccountId, int64_t reqId, const char *appId, const char *createParams)
{
    SetDeviceStatus(true);
    g_asyncStatus = ASYNC_STATUS_WAITING;
    const DeviceGroupManager *gm = GetGmInstance();
    int32_t ret = gm->createGroup(osAccountId, reqId, appId, createParams);
    if (ret != HC_SUCCESS) {
        g_asyncStatus = ASYNC_STATUS_ERROR;
        return;
    }
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    usleep(TEST_DEV_AUTH_SLEEP_TIME);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

static void DeleteDemoGroup(int32_t osAccountId, int64_t reqId, const char *appId,
    const char *disbandParams)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->deleteGroup(osAccountId, reqId, appId, disbandParams);
    ASSERT_EQ(ret, HC_SUCCESS);
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

static void AddDemoMember(void)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    bool isClient = true;
    SetDeviceStatus(isClient);
    const DeviceGroupManager *gm = GetGmInstance();
    int32_t ret = gm->addMemberToGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, ADD_PARAMS);
    if (ret != HC_SUCCESS) {
        g_asyncStatus = ASYNC_STATUS_ERROR;
        return;
    }
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    while (g_asyncStatus == ASYNC_STATUS_TRANSMIT) {
        isClient = !isClient;
        SetDeviceStatus(isClient);
        g_asyncStatus = ASYNC_STATUS_WAITING;
        uint8_t tmpTransmitData[2048] = { 0 };
        uint32_t tmpTransmitDataLen = 0;
        if (memcpy_s(tmpTransmitData, sizeof(tmpTransmitData), g_transmitData, g_transmitDataLen) != EOK) {
            g_asyncStatus = ASYNC_STATUS_ERROR;
            return;
        }
        tmpTransmitDataLen = g_transmitDataLen;
        (void)memset_s(g_transmitData, TRANSMIT_DATA_MAX_LEN, 0, TRANSMIT_DATA_MAX_LEN);
        g_transmitDataLen = 0;
        if (isClient) {
            ret = gm->processData(TEST_REQ_ID, tmpTransmitData, tmpTransmitDataLen);
        } else {
            ret = gm->processData(TEST_REQ_ID2, tmpTransmitData, tmpTransmitDataLen);
        }
        if (ret != HC_SUCCESS) {
            g_asyncStatus = ASYNC_STATUS_ERROR;
            return;
        }
        while (g_asyncStatus == ASYNC_STATUS_WAITING) {
            usleep(TEST_DEV_AUTH_SLEEP_TIME);
        }
        if (g_asyncStatus == ASYNC_STATUS_ERROR) {
            break;
        }
        if (g_transmitDataLen > 0) {
            g_asyncStatus = ASYNC_STATUS_TRANSMIT;
        }
    }
    usleep(TEST_DEV_AUTH_SLEEP_TIME2);
    SetDeviceStatus(true);
}

static bool GenerateTempKeyPair(Uint8Buff *keyAlias)
{
    int ret = GetLoaderInstance()->checkKeyExist(keyAlias, false, DEFAULT_OS_ACCOUNT);
    if (ret != HC_SUCCESS) {
        printf("Key pair not exist, start to generate\n");
        int32_t authId = 0;
        Uint8Buff authIdBuff = { reinterpret_cast<uint8_t *>(&authId), sizeof(int32_t)};
        ExtraInfo extInfo = {authIdBuff, -1, -1};
        KeyParams keyParams = { { keyAlias->val, keyAlias->length, true }, false, DEFAULT_OS_ACCOUNT };
        ret = GetLoaderInstance()->generateKeyPairWithStorage(&keyParams, TEST_DEV_AUTH_TEMP_KEY_PAIR_LEN, P256,
            KEY_PURPOSE_SIGN_VERIFY, &extInfo);
    } else {
        printf("Server key pair already exists\n");
    }

    if (ret != HC_SUCCESS) {
        printf("Generate key pair failed\n");
        return false;
    } else {
        printf("Generate key pair for server success\n");
    }
    return true;
}

static CJson *GetAsyCredentialJson(string registerInfo)
{
    uint8_t keyAliasValue[] = "TestServerKeyPair";
    int32_t keyAliasLen = 18;
    Uint8Buff keyAlias = {
        .val = keyAliasValue,
        .length = keyAliasLen
    };
    if (!GenerateTempKeyPair(&keyAlias)) {
        return nullptr;
    }
    uint8_t *serverPkVal = reinterpret_cast<uint8_t *>(HcMalloc(SERVER_PK_SIZE, 0));
    Uint8Buff serverPk = {
        .val = serverPkVal,
        .length = SERVER_PK_SIZE
    };

    KeyParams keyAliasParams = { { keyAlias.val, keyAlias.length, true }, false, DEFAULT_OS_ACCOUNT };
    int32_t ret = GetLoaderInstance()->exportPublicKey(&keyAliasParams, &serverPk);
    if (ret != HC_SUCCESS) {
        printf("export PublicKey failed\n");
        HcFree(serverPkVal);
        return nullptr;
    }

    Uint8Buff messageBuff = {
        .val = reinterpret_cast<uint8_t *>(const_cast<char *>(registerInfo.c_str())),
        .length = registerInfo.length() + 1
    };
    uint8_t *signatureValue = reinterpret_cast<uint8_t *>(HcMalloc(SIGNATURE_SIZE, 0));
    Uint8Buff signature = {
        .val = signatureValue,
        .length = SIGNATURE_SIZE
    };
    ret = GetLoaderInstance()->sign(&keyAliasParams, &messageBuff, P256, &signature);
    if (ret != HC_SUCCESS) {
        printf("Sign pkInfo failed.\n");
        HcFree(serverPkVal);
        HcFree(signatureValue);
        return nullptr;
    }

    CJson *pkInfoJson = CreateJsonFromString(registerInfo.c_str());
    CJson *credentialJson = CreateJson();
    (void)AddIntToJson(credentialJson, FIELD_CREDENTIAL_TYPE, ASYMMETRIC_CRED);
    (void)AddByteToJson(credentialJson, FIELD_SERVER_PK, serverPkVal, serverPk.length);
    (void)AddByteToJson(credentialJson, FIELD_PK_INFO_SIGNATURE, signatureValue, signature.length);
    (void)AddObjToJson(credentialJson, FIELD_PK_INFO, pkInfoJson);
    FreeJson(pkInfoJson);
    return credentialJson;
}

static void CreateClientIdenticalAccountGroup(void)
{
    SetDeviceStatus(true);
    GenerateDeviceKeyPair(DEFAULT_OS_ACCOUNT);
    g_asyncStatus = ASYNC_STATUS_WAITING;
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    int32_t ret = gm->getRegisterInfo(GET_REGISTER_INFO_PARAMS, &returnData);
    ASSERT_EQ(ret, HC_SUCCESS);
    ASSERT_NE(returnData, nullptr);
    string registerInfo(returnData);

    CJson *credJson = GetAsyCredentialJson(registerInfo);
    ASSERT_NE(credJson, nullptr);
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_GROUP_TYPE, IDENTICAL_ACCOUNT_GROUP);
    AddStringToJson(json, FIELD_USER_ID, TEST_USER_ID);
    AddObjToJson(json, FIELD_CREDENTIAL, credJson);
    char *jsonStr = PackJsonToString(json);
    FreeJson(credJson);
    FreeJson(json);
    gm->destroyInfo(&returnData);
    ASSERT_NE(jsonStr, nullptr);
    ret = gm->createGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, jsonStr);
    FreeJsonString(jsonStr);
    ASSERT_EQ(ret, HC_SUCCESS);
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

static void CreateServerIdenticalAccountGroup(void)
{
    SetDeviceStatus(false);
    GenerateDeviceKeyPair(DEFAULT_OS_ACCOUNT);
    g_asyncStatus = ASYNC_STATUS_WAITING;
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    char *returnData = nullptr;
    int32_t ret = gm->getRegisterInfo(GET_REGISTER_INFO_PARAMS1, &returnData);
    ASSERT_EQ(ret, HC_SUCCESS);
    ASSERT_NE(returnData, nullptr);
    string registerInfo(returnData);

    CJson *credJson = GetAsyCredentialJson(registerInfo);
    ASSERT_NE(credJson, nullptr);
    CJson *json = CreateJson();
    AddIntToJson(json, FIELD_GROUP_TYPE, IDENTICAL_ACCOUNT_GROUP);
    AddStringToJson(json, FIELD_USER_ID, TEST_USER_ID);
    AddObjToJson(json, FIELD_CREDENTIAL, credJson);
    char *jsonStr = PackJsonToString(json);
    FreeJson(credJson);
    FreeJson(json);
    gm->destroyInfo(&returnData);
    ASSERT_NE(jsonStr, nullptr);
    ret = gm->createGroup(TEST_AUTH_OS_ACCOUNT_ID, TEST_REQ_ID, TEST_APP_ID, jsonStr);
    FreeJsonString(jsonStr);
    ASSERT_EQ(ret, HC_SUCCESS);
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

static void AuthDemoMember(void)
{
    g_asyncStatus = ASYNC_STATUS_WAITING;
    bool isClient = true;
    SetDeviceStatus(isClient);
    const GroupAuthManager *ga = GetGaInstance();
    ASSERT_NE(ga, nullptr);
    int32_t ret = ga->authDevice(DEFAULT_OS_ACCOUNT, TEST_REQ_ID3, AUTH_PARAMS, &g_gaCallback);
    if (ret != HC_SUCCESS) {
        g_asyncStatus = ASYNC_STATUS_ERROR;
        return;
    }
    while (g_asyncStatus == ASYNC_STATUS_WAITING) {
        usleep(TEST_DEV_AUTH_SLEEP_TIME);
    }
    while (g_asyncStatus == ASYNC_STATUS_TRANSMIT) {
        isClient = !isClient;
        SetDeviceStatus(isClient);
        g_asyncStatus = ASYNC_STATUS_WAITING;
        if (isClient) {
            ret = ga->processData(TEST_REQ_ID3, g_transmitData, g_transmitDataLen, &g_gaCallback);
        } else {
            ret = ga->processData(TEST_REQ_ID4, g_transmitData, g_transmitDataLen, &g_gaCallback);
        }
        (void)memset_s(g_transmitData, TRANSMIT_DATA_MAX_LEN, 0, TRANSMIT_DATA_MAX_LEN);
        g_transmitDataLen = 0;
        if (ret != HC_SUCCESS) {
            g_asyncStatus = ASYNC_STATUS_ERROR;
            return;
        }
        while (g_asyncStatus == ASYNC_STATUS_WAITING) {
            usleep(TEST_DEV_AUTH_SLEEP_TIME);
        }
        if (g_asyncStatus == ASYNC_STATUS_ERROR) {
            break;
        }
        if (g_transmitDataLen > 0) {
            g_asyncStatus = ASYNC_STATUS_TRANSMIT;
        }
    }
    SetDeviceStatus(true);
}

static void RemoveDir(const char *path)
{
    char strBuf[TEST_DEV_AUTH_BUFFER_SIZE] = {0};
    if (path == nullptr) {
        return;
    }
    if (sprintf_s(strBuf, sizeof(strBuf) - 1, "rm -rf %s", path) < 0) {
        return;
    }
    system(strBuf);
}

static void DeleteDatabase()
{
    RemoveDir(TEST_GROUP_DATA_PATH);
    RemoveDir(TEST_HKS_MAIN_DATA_PATH);
}

class DaAuthDeviceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DaAuthDeviceTest::SetUpTestCase() {}

void DaAuthDeviceTest::TearDownTestCase() {}

void DaAuthDeviceTest::SetUp()
{
    int32_t ret = InitDeviceAuthService();
    ASSERT_EQ(ret, HC_SUCCESS);
}

void DaAuthDeviceTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest001, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    AuthDeviceDirectWithPinDemo(AUTH_WITH_PIN_PARAMS, &g_daTmpCallback);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}
HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest002, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    AuthDeviceDirectDemo(AUTH_DIRECT_PARAMS, &g_daLTCallback);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest003, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    int32_t res = ProcessCredentialDemo(CRED_OP_DELETE, DEFAULT_SERVICE_TYPE);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_QUERY, DEFAULT_SERVICE_TYPE);
    ASSERT_NE(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_CREATE, DEFAULT_SERVICE_TYPE);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_QUERY, DEFAULT_SERVICE_TYPE);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_DELETE, DEFAULT_SERVICE_TYPE);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_QUERY, DEFAULT_SERVICE_TYPE);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest004, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);

    int32_t res = ProcessCredentialDemo(CRED_OP_CREATE, DEFAULT_SERVICE_TYPE);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_QUERY, DEFAULT_SERVICE_TYPE);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_DELETE, DEFAULT_SERVICE_TYPE);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_QUERY, DEFAULT_SERVICE_TYPE);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest005, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    int32_t res = CreateServerKeyPair();
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemoImport(SERVICE_TYPE_IMPORT);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_QUERY, SERVICE_TYPE_IMPORT);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_DELETE, SERVICE_TYPE_IMPORT);
    ASSERT_EQ(res, HC_SUCCESS);
    res = ProcessCredentialDemo(CRED_OP_QUERY, SERVICE_TYPE_IMPORT);
    ASSERT_NE(res, HC_SUCCESS);
    res = DeleteServerKeyPair();
    ASSERT_EQ(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest006, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    ProcessCredentiaCreateDemo(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_CLIENT);
    ProcessCredentiaCreateDemo(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_SERVER);
    char *publicKey = nullptr;
    ProcessCredentialQueryDemo(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_SERVER, &publicKey);
    ProcessCredentialDemoImpPubKey(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_SERVER, publicKey);
    HcFree(publicKey);
    publicKey = nullptr;
    ProcessCredentialQueryDemo(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_CLIENT, &publicKey);
    ProcessCredentialDemoImpPubKey(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_CLIENT, publicKey);
    HcFree(publicKey);
    DeviceLevelAuthDemo();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest007, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);

    CJson *in = CreateJsonFromString("{\"testKey\":\"testValue\"}");
    CertInfo *certInfo = (CertInfo *)HcMalloc(sizeof(CertInfo *), 0);
    IdentityInfo *identityInfo = (IdentityInfo *)HcMalloc(sizeof(IdentityInfo *), 0);

    int32_t res = GetCredInfoByPeerCert(in, certInfo, &identityInfo);

    HcFree(identityInfo);
    HcFree(certInfo);
    FreeJson(in);

    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest008, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);

    CJson *in = CreateJsonFromString("{\"osAccountId\":\"100\"}");
    CertInfo *certInfo = (CertInfo *)HcMalloc(sizeof(CertInfo *), 0);
    uint8_t val[] = { 0, 0 };
    Uint8Buff sharedSecret = { val, sizeof(val) };

    int32_t res = GetSharedSecretByPeerCert(in, certInfo, ALG_EC_SPEKE, &sharedSecret);
    HcFree(certInfo);
    FreeJson(in);
    ASSERT_NE(res, HC_SUCCESS);

    res = GetSharedSecretByPeerCert(nullptr, nullptr, ALG_EC_SPEKE, &sharedSecret);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest009, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);

    CJson *in = CreateJsonFromString("{\"osAccountId\":\"100\"}");
    uint8_t val[] = { 0, 0 };
    Uint8Buff sharedSecret = { val, sizeof(val) };
    Uint8Buff presharedUrl = { val, sizeof(val) };

    int32_t res = GetSharedSecretByUrl(in, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJson(in);
    ASSERT_NE(res, HC_SUCCESS);

    res = GetSharedSecretByUrl(nullptr, &presharedUrl, ALG_ISO, &sharedSecret);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest010, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);

    CJson *in = CreateJsonFromString("{\"pinCode\":\"123456\",\"osAccountId\":0,\"seed\":"
                                     "\"CA32A9DFACB944B1F6292C9AE10783F6376A987A9CE30C13300BC866917DFF2E\"}");
    uint8_t val[] = { 0, 0 };
    Uint8Buff sharedSecret = { val, sizeof(val) };
    Uint8Buff presharedUrl = { val, sizeof(val) };

    int32_t res = GetSharedSecretByUrl(in, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJson(in);
    ASSERT_EQ(res, HC_SUCCESS);

    res = GetSharedSecretByUrl(nullptr, &presharedUrl, ALG_ISO, &sharedSecret);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest011, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);

    const AuthIdentityManager *authIdentityManager = GetAuthIdentityManager();
    ASSERT_NE(authIdentityManager, nullptr);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest012, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);

    const AuthIdentity *authIdentity = GetAuthIdentityByType(AUTH_IDENTITY_TYPE_INVALID);
    ASSERT_EQ(authIdentity, nullptr);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest013, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);

    CJson *in = CreateJsonFromString("{\"groupId\":\"123456\",\"seed\":"
                                     "\"CA32A9DFACB944B1F6292C9AE10783F6376A987A9CE30C13300BC866917DFF2E\"}");
    uint8_t val[] = { 0, 0 };
    Uint8Buff sharedSecret = { val, sizeof(val) };
    const char *credUrl = "{\"credentialType\":0,\"keyType\":1,\"trustType\":1,\"groupId\":\"123456\"}";
    Uint8Buff presharedUrl = { (uint8_t *)credUrl, HcStrlen(credUrl) };

    int32_t res = GetSharedSecretByUrl(in, &presharedUrl, ALG_ISO, &sharedSecret);
    FreeJson(in);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest014, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);

    const CredentialOperator *credentialOperator = GetCredentialOperator();

    int32_t res = credentialOperator->queryCredential(nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->genarateCredential(nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->importCredential(nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->deleteCredential(nullptr, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest015, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);

    const CredentialOperator *credentialOperator = GetCredentialOperator();

    const char *reqJsonStr = "{\"deviceId\":\"123456\",\"osAccountId\":0,\"peerOsAccountId\":0,\"acquireType\":0}";
    char *returnData = nullptr;
    int32_t res = credentialOperator->queryCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->genarateCredential(reqJsonStr, &returnData);
    ASSERT_EQ(res, HC_SUCCESS);

    res = credentialOperator->importCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->deleteCredential(reqJsonStr, &returnData);
    ASSERT_EQ(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest016, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);

    const CredentialOperator *credentialOperator = GetCredentialOperator();

    const char *reqJsonStr = "{\"osAccountId\":0,\"acquireType\":0}";
    char *returnData = nullptr;
    int32_t res = credentialOperator->queryCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->genarateCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->importCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->deleteCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest017, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);

    const CredentialOperator *credentialOperator = GetCredentialOperator();

    const char *reqJsonStr = "{\"deviceId\":\"123456\",\"acquireType\":0}";
    char *returnData = nullptr;
    int32_t res = credentialOperator->queryCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->genarateCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->importCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->deleteCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest018, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);

    const CredentialOperator *credentialOperator = GetCredentialOperator();

    const char *reqJsonStr = "{\"deviceId\":\"123456\",\"osAccountId\":0}";
    char *returnData = nullptr;
    int32_t res = credentialOperator->queryCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->genarateCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->importCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);

    res = credentialOperator->deleteCredential(reqJsonStr, &returnData);
    ASSERT_NE(res, HC_SUCCESS);
}

// auth with pin (Test019 ~ Test027)
HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest019, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    AuthDeviceDirectWithPinDemo(AUTH_WITH_PIN_PARAMS, nullptr);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest020, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    AuthDeviceDirectWithPinDemo(nullptr, &g_daTmpCallback);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest021, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    const char *startAuthParams = "{\"osAccountId\":100,\"acquireType\":1,\"pinCode\":\"123456\"}";
    AuthDeviceDirectWithPinDemo(startAuthParams, &g_daTmpCallback);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest022, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    const char *startAuthParams = "{\"acquireType\":0,\"pinCode\":\"123456\"}";
    AuthDeviceDirectWithPinDemo(startAuthParams, &g_daTmpCallback);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest023, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    const char *startAuthParams = "{\"osAccountId\":-2,\"acquireType\":0,\"pinCode\":\"123456\"}";
    AuthDeviceDirectWithPinDemo(startAuthParams, &g_daTmpCallback);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest024, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    const char *startAuthParams = "{\"osAccountId\":-1,\"acquireType\":0,\"pinCode\":\"123456\"}";
    AuthDeviceDirectWithPinDemo(startAuthParams, &g_daTmpCallback);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest025, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    const char *startAuthParams = "{\"osAccountId\":0,\"acquireType\":0,\"pinCode\":\"654321\"}";
    AuthDeviceDirectWithPinDemo(startAuthParams, &g_daTmpCallback);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest026, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    const char *startAuthParams = "{\"osAccountId\":100,\"acquireType\":0}";
    AuthDeviceDirectWithPinDemo(startAuthParams, &g_daTmpCallback);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest027, TestSize.Level0)
{
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    const char *startAuthParams = "{\"osAccountId\":100,\"pinCode\":\"123456\"}";
    AuthDeviceDirectWithPinDemo(startAuthParams, &g_daTmpCallback);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

// auth with key-pair (Test028 ~ Test032)
HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest028, TestSize.Level0)
{
    DeleteAllCredentails();
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    ProcessCredentiaCreateDemo(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_CLIENT);
    AuthDeviceDirectDemo(AUTH_DIRECT_PARAMS, &g_daLTCallback);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest029, TestSize.Level0)
{
    DeleteAllCredentails();
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    ProcessCredentiaCreateDemo(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_CLIENT);
    ProcessCredentiaCreateDemo(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_SERVER);
    char *publicKey = nullptr;
    ProcessCredentialQueryDemo(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_SERVER, &publicKey);
    ProcessCredentialDemoImpPubKey(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_SERVER, publicKey);
    HcFree(publicKey);
    publicKey = nullptr;
    ProcessCredentialQueryDemo(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_CLIENT, &publicKey);
    ProcessCredentialDemoImpPubKey(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_CLIENT, publicKey);
    HcFree(publicKey);
    AuthDeviceDirectDemo(AUTH_DIRECT_PARAMS, &g_daLTCallback);
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest030, TestSize.Level0)
{
    DeleteAllCredentails();
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    ProcessCredentiaCreateDemo(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_CLIENT);
    ProcessCredentiaCreateDemo(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_SERVER);
    char *publicKey = nullptr;
    ProcessCredentialQueryDemo(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_SERVER, &publicKey);
    ProcessCredentialDemoImpPubKey(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_SERVER, publicKey);
    HcFree(publicKey);
    publicKey = nullptr;
    ProcessCredentialQueryDemo(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_CLIENT, &publicKey);
    ProcessCredentialDemoImpPubKey(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_CLIENT, publicKey);
    HcFree(publicKey);
    const char *statAuthParams =
    "{\"osAccountId\":100,\"acquireType\":0,\"serviceType\":\"service.type.import\"}";
    AuthDeviceDirectDemo(statAuthParams, &g_daLTCallback);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest031, TestSize.Level0)
{
    DeleteAllCredentails();
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    ProcessCredentiaCreateDemo(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_CLIENT);
    ProcessCredentiaCreateDemo(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_SERVER);
    char *publicKey = nullptr;
    ProcessCredentialQueryDemo(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_SERVER, &publicKey);
    ProcessCredentialDemoImpPubKey(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_SERVER, publicKey);
    HcFree(publicKey);
    publicKey = nullptr;
    ProcessCredentialQueryDemo(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_CLIENT, &publicKey);
    ProcessCredentialDemoImpPubKey(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_CLIENT, publicKey);
    HcFree(publicKey);
    const char *statAuthParams =
    "{\"osAccountId\":100,\"acquireType\":0,\"serviceType\":\"service.type.import\",\"peerConnDeviceId\":"
    "\"52E2706717D5C39D736E134CC1\"}";
    AuthDeviceDirectDemo(statAuthParams, &g_daLTCallback);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(DaAuthDeviceTest, DaAuthDeviceTest032, TestSize.Level0)
{
    DeleteAllCredentails();
    SetIsoSupported(false);
    SetPakeV1Supported(true);
    SetDeviceStatus(true);
    ProcessCredentiaCreateDemo(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_CLIENT);
    ProcessCredentiaCreateDemo(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_SERVER);
    char *publicKey = nullptr;
    ProcessCredentialQueryDemo(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_SERVER, &publicKey);
    ProcessCredentialDemoImpPubKey(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_SERVER, publicKey);
    HcFree(publicKey);
    publicKey = nullptr;
    ProcessCredentialQueryDemo(TEST_AUTH_OS_ACCOUNT_ID, true, TEST_UDID_CLIENT, &publicKey);
    ProcessCredentialDemoImpPubKey(TEST_AUTH_OS_ACCOUNT_ID, false, TEST_UDID_CLIENT, publicKey);
    HcFree(publicKey);
    const char *statAuthParams =
    "{\"osAccountId\":100,\"acquireType\":8,\"serviceType\":\"service.type.import\",\"peerConnDeviceId\":"
    "\"52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C"
    "749558BD2E6492C\"}";
    AuthDeviceDirectDemo(statAuthParams, &g_daLTCallback);
    ASSERT_NE(g_asyncStatus, ASYNC_STATUS_FINISH);
}

class AsymAccountAuthTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AsymAccountAuthTest::SetUpTestCase() {}
void AsymAccountAuthTest::TearDownTestCase() {}

void AsymAccountAuthTest::SetUp()
{
    DeleteDatabase();
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void AsymAccountAuthTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(AsymAccountAuthTest, AsymAccountAuthTest001, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateClientIdenticalAccountGroup();
    CreateServerIdenticalAccountGroup();
    AuthDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
}

HWTEST_F(AsymAccountAuthTest, AsymAccountAuthTest002, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateClientIdenticalAccountGroup();
    CreateServerIdenticalAccountGroup();
    SetSessionV2Supported(false);
    AuthDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    SetSessionV2Supported(true);
}

HWTEST_F(AsymAccountAuthTest, AsymAccountAuthTest003, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    AddDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    CreateClientIdenticalAccountGroup();
    SetSessionV2Supported(false);
    AuthDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    SetSessionV2Supported(true);
}

class DeviceAuthFuncTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DeviceAuthFuncTest::SetUpTestCase() {}
void DeviceAuthFuncTest::TearDownTestCase() {}

void DeviceAuthFuncTest::SetUp()
{
    DeleteDatabase();
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, HC_SUCCESS);
}

void DeviceAuthFuncTest::TearDown()
{
    DestroyDeviceAuthService();
}

HWTEST_F(DeviceAuthFuncTest, DeviceAuthFuncTest001, TestSize.Level0)
{
    const GroupAuthManager *ga = GetGaInstance();
    ASSERT_NE(ga, nullptr);
    int32_t ret = ga->getRealInfo(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = ga->getRealInfo(DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    char *realInfo = nullptr;
    ret = ga->getRealInfo(DEFAULT_OS_ACCOUNT, TEST_PSEUDONYM_ID, &realInfo);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(DeviceAuthFuncTest, DeviceAuthFuncTest002, TestSize.Level0)
{
    const GroupAuthManager *ga = GetGaInstance();
    ASSERT_NE(ga, nullptr);
    int32_t ret = ga->getPseudonymId(DEFAULT_OS_ACCOUNT, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = ga->getPseudonymId(DEFAULT_OS_ACCOUNT, TEST_INDEX_KEY, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    char *pseudonymId = nullptr;
    ret = ga->getPseudonymId(DEFAULT_OS_ACCOUNT, TEST_INDEX_KEY, &pseudonymId);
    EXPECT_EQ(ret, HC_SUCCESS);
}

HWTEST_F(DeviceAuthFuncTest, DeviceAuthFuncTest003, TestSize.Level0)
{
    int32_t ret = ProcessCredential(CRED_OP_QUERY, nullptr, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = ProcessCredential(CRED_OP_QUERY, TEST_REQUEST_JSON_STR, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    char *returnData = nullptr;
    ret = ProcessCredential(CRED_OP_QUERY, TEST_REQUEST_JSON_STR, &returnData);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = ProcessCredential(CRED_OP_INVALID, TEST_REQUEST_JSON_STR, &returnData);
    EXPECT_NE(ret, HC_SUCCESS);
}

HWTEST_F(DeviceAuthFuncTest, DeviceAuthFuncTest004, TestSize.Level0)
{
    int32_t ret = ProcessAuthDevice(TEST_REQ_ID, nullptr, &g_gaCallback);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = ProcessAuthDevice(TEST_REQ_ID, TEST_INVALID_AUTH_PARAMS, &g_gaCallback);
    EXPECT_NE(ret, HC_SUCCESS);
    CJson *authParams = CreateJson();
    ASSERT_NE(authParams, nullptr);
    char *authParamsStr = PackJsonToString(authParams);
    ASSERT_NE(authParamsStr, nullptr);
    ret = ProcessAuthDevice(TEST_REQ_ID, authParamsStr, &g_gaCallback);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJsonString(authParamsStr);
    (void)AddStringToJson(authParams, "data", "testParams");
    authParamsStr = PackJsonToString(authParams);
    ASSERT_NE(authParamsStr, nullptr);
    ret = ProcessAuthDevice(TEST_REQ_ID, authParamsStr, &g_gaCallback);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJsonString(authParamsStr);
    CJson *dataJson = CreateJson();
    ASSERT_NE(dataJson, nullptr);
    char *dataStr = PackJsonToString(dataJson);
    FreeJson(dataJson);
    ASSERT_NE(dataStr, nullptr);
    (void)AddStringToJson(authParams, "data", dataStr);
    FreeJsonString(dataStr);
    authParamsStr = PackJsonToString(authParams);
    ASSERT_NE(authParamsStr, nullptr);
    ret = ProcessAuthDevice(TEST_REQ_ID, authParamsStr, &g_rejectCallback);
    EXPECT_EQ(ret, HC_SUCCESS);
    ret = ProcessAuthDevice(TEST_REQ_ID2, authParamsStr, &g_invalidCallback);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = ProcessAuthDevice(TEST_REQ_ID2, authParamsStr, &g_invalidCallback1);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = ProcessAuthDevice(TEST_REQ_ID2, authParamsStr, &g_invalidCallback2);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = ProcessAuthDevice(TEST_REQ_ID2, authParamsStr, &g_invalidCallback4);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJsonString(authParamsStr);
    FreeJson(authParams);
    DestroyDeviceAuthService();
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_EQ(gm, nullptr);
    const GroupAuthManager *ga = GetGaInstance();
    ASSERT_EQ(ga, nullptr);
}

HWTEST_F(DeviceAuthFuncTest, DeviceAuthFuncTest005, TestSize.Level0)
{
    int32_t ret = StartAuthDevice(TEST_REQ_ID2, TEST_INVALID_AUTH_PARAMS, &g_gaCallback);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = CancelAuthRequest(TEST_REQ_ID3, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = CancelAuthRequest(TEST_REQ_ID3, TEST_INVALID_AUTH_PARAMS);
    EXPECT_EQ(ret, HC_SUCCESS);
    const GroupAuthManager *ga = GetGaInstance();
    ASSERT_NE(ga, nullptr);
    ret = ga->processData(TEST_REQ_ID4, (const uint8_t *)TEST_INVALID_AUTH_PARAMS,
        HcStrlen(TEST_INVALID_AUTH_PARAMS), &g_gaCallback);
    EXPECT_NE(ret, HC_SUCCESS);
    CJson *dataJson = CreateJson();
    ASSERT_NE(dataJson, nullptr);
    char *dataStr = PackJsonToString(dataJson);
    FreeJson(dataJson);
    ASSERT_NE(dataStr, nullptr);
    ret = ga->processData(TEST_REQ_ID4, (const uint8_t *)dataStr, HcStrlen(dataStr), nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = ga->processData(TEST_REQ_ID4, (const uint8_t *)dataStr, HcStrlen(dataStr), &g_invalidCallback3);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = ga->processData(TEST_REQ_ID4, (const uint8_t *)dataStr, HcStrlen(dataStr), &g_invalidCallback1);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = ga->processData(TEST_REQ_ID4, (const uint8_t *)dataStr, HcStrlen(dataStr), &g_invalidCallback2);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = ga->processData(TEST_REQ_ID4, (const uint8_t *)dataStr, HcStrlen(dataStr), &g_invalidCallback4);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJsonString(dataStr);
}

HWTEST_F(DeviceAuthFuncTest, DeviceAuthFuncTest006, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    CJson *dataJson = CreateJson();
    ASSERT_NE(dataJson, nullptr);
    char *dataStr = PackJsonToString(dataJson);
    ASSERT_NE(dataStr, nullptr);
    int32_t ret = gm->processData(TEST_REQ_ID, (const uint8_t *)dataStr, HcStrlen(dataStr));
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJsonString(dataStr);
    (void)AddStringToJson(dataJson, FIELD_APP_ID, TEST_APP_ID);
    dataStr = PackJsonToString(dataJson);
    ASSERT_NE(dataStr, nullptr);
    ret = gm->regCallback(TEST_APP_ID, &g_invalidBindCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    ret = gm->processData(TEST_REQ_ID, (const uint8_t *)dataStr, HcStrlen(dataStr));
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJsonString(dataStr);
    (void)AddStringToJson(dataJson, FIELD_GROUP_ID, TEST_GROUP_ID);
    dataStr = PackJsonToString(dataJson);
    ASSERT_NE(dataStr, nullptr);
    ret = gm->unRegCallback(TEST_APP_ID);
    ASSERT_EQ(ret, HC_SUCCESS);
    ret = gm->regCallback(TEST_APP_ID, &g_invalidBindCallback1);
    ASSERT_EQ(ret, HC_SUCCESS);
    ret = gm->processData(TEST_REQ_ID, (const uint8_t *)dataStr, HcStrlen(dataStr));
    EXPECT_NE(ret, HC_SUCCESS);
    ret = gm->unRegCallback(TEST_APP_ID);
    ASSERT_EQ(ret, HC_SUCCESS);
    ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    ret = gm->processData(TEST_REQ_ID, (const uint8_t *)dataStr, HcStrlen(dataStr));
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJsonString(dataStr);
    (void)AddIntToJson(dataJson, FIELD_OP_CODE, MEMBER_INVITE);
    dataStr = PackJsonToString(dataJson);
    ASSERT_NE(dataStr, nullptr);
    ret = gm->processData(TEST_REQ_ID, (const uint8_t *)dataStr, HcStrlen(dataStr));
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(dataJson);
    FreeJsonString(dataStr);
}

HWTEST_F(DeviceAuthFuncTest, DeviceAuthFuncTest007, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->addMemberToGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, nullptr);
    EXPECT_NE(ret, HC_SUCCESS);
    ret = gm->addMemberToGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, TEST_INVALID_ADD_PARAMS);
    EXPECT_NE(ret, HC_SUCCESS);
    CJson *addParamsJson = CreateJson();
    ASSERT_NE(addParamsJson, nullptr);
    (void)AddIntToJson(addParamsJson, FIELD_PROTOCOL_EXPAND, LITE_PROTOCOL_STANDARD_MODE);
    char *addParamsStr = PackJsonToString(addParamsJson);
    ASSERT_NE(addParamsStr, nullptr);
    ret = gm->addMemberToGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, addParamsStr);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJsonString(addParamsStr);
    (void)AddIntToJson(addParamsJson, FIELD_PROTOCOL_EXPAND, LITE_PROTOCOL_COMPATIBILITY_MODE);
    ASSERT_NE(addParamsJson, nullptr);
    addParamsStr = PackJsonToString(addParamsJson);
    ASSERT_NE(addParamsStr, nullptr);
    ret = gm->addMemberToGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, addParamsStr);
    EXPECT_NE(ret, HC_SUCCESS);
    FreeJson(addParamsJson);
    FreeJsonString(addParamsStr);
}

HWTEST_F(DeviceAuthFuncTest, DeviceAuthFuncTest008, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    AddDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    SetDeviceStatus(false);
    DeleteDemoGroup(TEST_AUTH_OS_ACCOUNT_ID, TEST_REQ_ID, TEST_APP_ID, DISBAND_PARAMS);
    SetDeviceStatus(true);
    SetSessionV2Supported(false);
    AuthDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_ERROR);
    SetSessionV2Supported(true);
}

HWTEST_F(DeviceAuthFuncTest, DeviceAuthFuncTest009, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    AddDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_FINISH);
    SetDeviceStatus(false);
    DeleteDemoGroup(TEST_AUTH_OS_ACCOUNT_ID, TEST_REQ_ID, TEST_APP_ID, DISBAND_PARAMS);
    SetDeviceStatus(true);
    AuthDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_ERROR);
}

HWTEST_F(DeviceAuthFuncTest, DeviceAuthFuncTest010, TestSize.Level0)
{
    const DeviceGroupManager *gm = GetGmInstance();
    ASSERT_NE(gm, nullptr);
    int32_t ret = gm->regCallback(TEST_APP_ID, &g_gmMismatchCallback);
    ASSERT_EQ(ret, HC_SUCCESS);
    CreateDemoGroup(DEFAULT_OS_ACCOUNT, TEST_REQ_ID, TEST_APP_ID, CREATE_PARAMS);
    AddDemoMember();
    ASSERT_EQ(g_asyncStatus, ASYNC_STATUS_ERROR);
}

HWTEST_F(DeviceAuthFuncTest, DeviceAuthFuncTest011, TestSize.Level0)
{
    const CredAuthManager *cm = GetCredAuthInstance();
    ASSERT_NE(cm, nullptr);
}
} // namespace
