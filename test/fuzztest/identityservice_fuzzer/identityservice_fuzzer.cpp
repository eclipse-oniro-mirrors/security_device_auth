/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "identityservice_fuzzer.h"

#include <cinttypes>
#include <unistd.h>
#include "alg_loader.h"
#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "device_auth_ext.h"
#include "hc_dev_info_mock.h"
#include "json_utils_mock.h"
#include "json_utils.h"
#include "protocol_task_main_mock.h"
#include "securec.h"
#include "hc_file.h"
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "hc_log.h"
#include "hc_types.h"

namespace OHOS {
#define TEST_RESULT_SUCCESS 0
#define TEST_APP_ID "TestAppId"
#define TEST_APP_ID1 "TestAppId1"
#define TEST_DEVICE_ID "TestDeviceId"
#define QUERY_RESULT_NUM 0
#define QUERY_RESULT_NUM_2 2

#define TEST_CRED_DATA_PATH "/data/service/el1/public/deviceauthMock/hccredential.dat"

static const char *ADD_PARAMS =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"keyValue\":\"TestKeyValue\",\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";

static const char *ADD_PARAMS1 =
    "{\"credType\":0,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"keyValue\":\"TestKeyValue\",\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";

static const char *ADD_PARAMS2 =
    "{\"credType\":1,\"keyFormat\":0,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"keyValue\":\"TestKeyValue\",\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";

static const char *ADD_PARAMS3 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":0,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"keyValue\":\"TestKeyValue\",\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";

static const char *ADD_PARAMS4 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":0,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"keyValue\":\"TestKeyValue\",\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";

static const char *ADD_PARAMS5 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":0,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"keyValue\":\"TestKeyValue\",\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";

static const char *ADD_PARAMS6 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":0,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"keyValue\":\"TestKeyValue\",\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";

static const char *ADD_PARAMS7 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":0,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"keyValue\":\"TestKeyValue\",\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";

static const char *ADD_PARAMS8 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":0,\"userId\":\"TestUserId\","
    "\"keyValue\":\"TestKeyValue\",\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";

static const char *ADD_PARAMS9 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"keyValue\":\"TestKeyValue\",\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";

static const char *ADD_PARAMS10 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"keyValue\":\"TestKeyValue\",\"deviceId\":\"TestDeviceId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";

static const char *ADD_PARAMS11 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,"
    "\"keyValue\":\"TestKeyValue\",\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";

static const char *ADD_PARAMS12 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":2,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";

static const char *ADD_PARAMS13 =
    "{\"credType\":2,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":2,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"keyValue\":\"9A9A9A9A\",\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";

static const char *ADD_PARAMS14 =
    "{\"credType\":1,\"keyFormat\":4,\"algorithmType\":3,\"subject\":1,\"issuer\":1,"
    "\"proofType\":1,\"method\":1,\"authorizedScope\":1,\"userId\":\"TestUserId\","
    "\"keyValue\":\"TestKeyValue\",\"deviceId\":\"TestDeviceId\",\"credOwner\":\"TestAppId1\","
    "\"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\"],"
    "\"peerUserSpaceId\":100,\"extendInfo\":\"\"}";

static const char *REQUEST_PARAMS =
    "{\"authorizedScope\":1, \"authorizedAccoutList\":[\"TestName1\",\"TestName2\",\"TestName3\","
    "\"TestName4\"],\"extendInfo\":\"\"}";

static const char *QUERY_PARAMS = "{\"deviceId\":\"TestDeviceId\"}";
static const char *QUERY_PARAMS1 = "{\"deviceId\":\"TestDeviceId1\"}";

enum CredListenerStatus {
    CRED_LISTENER_INIT = 0,
    CRED_LISTENER_ON_ADD = 1,
    CRED_LISTENER_ON_UPDATE = 2,
    CRED_LISTENER_ON_DELETE = 3,
};

static CredListenerStatus volatile g_credListenerStatus;

static void TestOnCredAdd(const char *credId, const char *credInfo)
{
    (void)credId;
    (void)credInfo;
    g_credListenerStatus = CRED_LISTENER_ON_ADD;
}

static void TestOnCredUpdate(const char *credId, const char *credInfo)
{
    (void)credId;
    (void)credInfo;
    g_credListenerStatus = CRED_LISTENER_ON_UPDATE;
}

static void TestOnCredDelete(const char *credId, const char *credInfo)
{
    (void)credId;
    (void)credInfo;
    g_credListenerStatus = CRED_LISTENER_ON_DELETE;
}

static CredChangeListener g_credChangeListener = {
    .onCredAdd = TestOnCredAdd,
    .onCredUpdate = TestOnCredUpdate,
    .onCredDelete = TestOnCredDelete,
};

static void DeleteDatabase()
{
    HcFileRemove(TEST_CRED_DATA_PATH);
}

static int32_t IdentityServiceTestCase001(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        char *returnData = nullptr;
        const CredManager *cm = GetCredMgrInstance();
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &returnData);
        HcFree(returnData);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase002(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        char *returnData = nullptr;
        const CredManager *cm = GetCredMgrInstance();
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, nullptr, &returnData);
        HcFree(returnData);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase003(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, nullptr);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase004(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *returnData = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS1, &returnData);
        HcFree(returnData);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase005(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *returnData = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS2, &returnData);
        HcFree(returnData);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase006(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *returnData = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS3, &returnData);
        HcFree(returnData);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase007(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *returnData = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS4, &returnData);
        HcFree(returnData);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase008(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *returnData = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS5, &returnData);
        HcFree(returnData);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase009(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *returnData = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS6, &returnData);
        HcFree(returnData);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase010(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *returnData = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS7, &returnData);
        HcFree(returnData);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase011(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *returnData = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS8, &returnData);
        HcFree(returnData);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase012(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *returnData = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS9, &returnData);
        HcFree(returnData);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase013(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *returnData = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS10, &returnData);
        HcFree(returnData);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase014(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *returnData = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS11, &returnData);
        HcFree(returnData);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase015(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *returnData = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS12, &returnData);
        HcFree(returnData);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase016(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *returnData = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS13, &returnData);
        HcFree(returnData);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase017(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *credId = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
        char *returnData = nullptr;
        ret = cm->exportCredential(DEFAULT_OS_ACCOUNT, credId, &returnData);
        HcFree(credId);
        HcFree(returnData);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase018(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *credId = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS2, &credId);
        char *returnData = nullptr;
        ret = cm->exportCredential(DEFAULT_OS_ACCOUNT, credId, &returnData);
        HcFree(credId);
        HcFree(returnData);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase019(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *credId = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
        ret = cm->exportCredential(DEFAULT_OS_ACCOUNT, credId, nullptr);
        HcFree(credId);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase020(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *credId = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
        char *returnData = nullptr;
        ret = cm->exportCredential(DEFAULT_OS_ACCOUNT, nullptr, &returnData);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase021(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *returnData = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &returnData);
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS14, &returnData);
        char *credIdList = nullptr;
        ret = cm->queryCredentialByParams(DEFAULT_OS_ACCOUNT, QUERY_PARAMS, &credIdList);
        CJson *jsonArr = CreateJsonFromString(credIdList);
        HcFree(credIdList);
        FreeJson(jsonArr);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase022(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *credIdList = nullptr;
        ret = cm->queryCredentialByParams(DEFAULT_OS_ACCOUNT, nullptr, &credIdList);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase023(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        ret = cm->queryCredentialByParams(DEFAULT_OS_ACCOUNT, QUERY_PARAMS, nullptr);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase024(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *returnData = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &returnData);
        char *credIdList = nullptr;
        ret = cm->queryCredentialByParams(DEFAULT_OS_ACCOUNT, QUERY_PARAMS1, &credIdList);
        CJson *jsonArr = CreateJsonFromString(credIdList);
        HcFree(credIdList);
        FreeJson(jsonArr);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase025(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *credId = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
        char *returnCredInfo = nullptr;
        ret = cm->queryCredInfoByCredId(DEFAULT_OS_ACCOUNT, credId, &returnCredInfo);
        HcFree(credId);
        CJson *credInfoJson = CreateJsonFromString(returnCredInfo);
        HcFree(returnCredInfo);
        FreeJson(credInfoJson);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase026(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *returnCredInfo = nullptr;
        ret = cm->queryCredInfoByCredId(DEFAULT_OS_ACCOUNT, nullptr, &returnCredInfo);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase027(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *returnCredInfo = nullptr;
        ret = cm->queryCredInfoByCredId(DEFAULT_OS_ACCOUNT, nullptr, &returnCredInfo);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase028(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *credId = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS14, &credId);
        ret = cm->queryCredInfoByCredId(DEFAULT_OS_ACCOUNT, credId, nullptr);
        HcFree(credId);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase029(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *credId = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
        ret = cm->deleteCredential(DEFAULT_OS_ACCOUNT, TEST_APP_ID, credId);
        HcFree(credId);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase030(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *credId = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
        ret = cm->deleteCredential(DEFAULT_OS_ACCOUNT, nullptr, credId);
        HcFree(credId);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase031(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        ret = cm->deleteCredential(DEFAULT_OS_ACCOUNT, TEST_APP_ID, nullptr);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase032(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *credId = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
        ret = cm->deleteCredential(DEFAULT_OS_ACCOUNT, TEST_APP_ID1, credId);
        HcFree(credId);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase033(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *credId = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
        ret = cm->updateCredInfo(DEFAULT_OS_ACCOUNT, TEST_APP_ID, credId, REQUEST_PARAMS);
        HcFree(credId);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase034(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *credId = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
        ret = cm->updateCredInfo(DEFAULT_OS_ACCOUNT, TEST_APP_ID, credId, "");
        HcFree(credId);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase035(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *credId = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
        ret = cm->updateCredInfo(DEFAULT_OS_ACCOUNT, nullptr, credId, REQUEST_PARAMS);
        HcFree(credId);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase036(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *credId = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
        ret = cm->updateCredInfo(DEFAULT_OS_ACCOUNT, TEST_APP_ID, nullptr, REQUEST_PARAMS);
        HcFree(credId);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase037(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        char *credId = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
        ret = cm->updateCredInfo(DEFAULT_OS_ACCOUNT, TEST_APP_ID1, credId, REQUEST_PARAMS);
        HcFree(credId);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase038(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        CredChangeListener listener;
        ret = cm->registerChangeListener(TEST_APP_ID, &listener);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase039(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        CredChangeListener listener;
        ret = cm->registerChangeListener(TEST_APP_ID, &listener);
        ret = cm->registerChangeListener(TEST_APP_ID, &listener);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase040(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        CredChangeListener listener;
        ret = cm->registerChangeListener(nullptr, &listener);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase041(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        ret = cm->registerChangeListener(TEST_APP_ID, nullptr);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase042(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        g_credListenerStatus = CRED_LISTENER_INIT;
        const CredManager *cm = GetCredMgrInstance();
        ret = cm->registerChangeListener(TEST_APP_ID, &g_credChangeListener);
        char *credId = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
        HcFree(credId);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase043(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        g_credListenerStatus = CRED_LISTENER_INIT;
        const CredManager *cm = GetCredMgrInstance();
        ret = cm->registerChangeListener(TEST_APP_ID, &g_credChangeListener);
        char *credId = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
        ret = cm->updateCredInfo(DEFAULT_OS_ACCOUNT, TEST_APP_ID, credId, REQUEST_PARAMS);
        HcFree(credId);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase044(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        g_credListenerStatus = CRED_LISTENER_INIT;
        const CredManager *cm = GetCredMgrInstance();
        ret = cm->registerChangeListener(TEST_APP_ID, &g_credChangeListener);
        char *credId = nullptr;
        ret = cm->addCredential(DEFAULT_OS_ACCOUNT, ADD_PARAMS, &credId);
        ret = cm->deleteCredential(DEFAULT_OS_ACCOUNT, TEST_APP_ID, credId);
        HcFree(credId);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase045(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        CredChangeListener listener;
        ret = cm->registerChangeListener(TEST_APP_ID, &listener);
        ret = cm->unregisterChangeListener(TEST_APP_ID);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase046(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        ret = cm->unregisterChangeListener(TEST_APP_ID);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static int32_t IdentityServiceTestCase047(void)
{
    DeleteDatabase();
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        return ret;
    }
    do {
        const CredManager *cm = GetCredMgrInstance();
        ret = cm->unregisterChangeListener(nullptr);
    } while (0);
    DestroyDeviceAuthService();
    return ret;
}

static void AddCredFuzzPart(void)
{
    (void)IdentityServiceTestCase001();
    (void)IdentityServiceTestCase002();
    (void)IdentityServiceTestCase003();
    (void)IdentityServiceTestCase004();
    (void)IdentityServiceTestCase005();
    (void)IdentityServiceTestCase006();
    (void)IdentityServiceTestCase007();
    (void)IdentityServiceTestCase008();
    (void)IdentityServiceTestCase009();
    (void)IdentityServiceTestCase010();
    (void)IdentityServiceTestCase011();
    (void)IdentityServiceTestCase012();
    (void)IdentityServiceTestCase013();
    (void)IdentityServiceTestCase014();
    (void)IdentityServiceTestCase015();
    (void)IdentityServiceTestCase016();
}

static void ExportCredFuzzPart(void)
{
    (void)IdentityServiceTestCase017();
    (void)IdentityServiceTestCase018();
    (void)IdentityServiceTestCase019();
    (void)IdentityServiceTestCase020();
}

static void QueryCredFuzzPart(void)
{
    (void)IdentityServiceTestCase021();
    (void)IdentityServiceTestCase022();
    (void)IdentityServiceTestCase023();
    (void)IdentityServiceTestCase024();
    (void)IdentityServiceTestCase025();
    (void)IdentityServiceTestCase026();
    (void)IdentityServiceTestCase027();
    (void)IdentityServiceTestCase028();
}

static void DelCredFuzzPart(void)
{
    (void)IdentityServiceTestCase029();
    (void)IdentityServiceTestCase030();
    (void)IdentityServiceTestCase031();
    (void)IdentityServiceTestCase032();
}

static void UpdateCredFuzzPart(void)
{
    (void)IdentityServiceTestCase033();
    (void)IdentityServiceTestCase034();
    (void)IdentityServiceTestCase035();
    (void)IdentityServiceTestCase036();
    (void)IdentityServiceTestCase037();
}

static void CredListenerFuzzPart(void)
{
    (void)IdentityServiceTestCase038();
    (void)IdentityServiceTestCase039();
    (void)IdentityServiceTestCase040();
    (void)IdentityServiceTestCase041();
    (void)IdentityServiceTestCase042();
    (void)IdentityServiceTestCase043();
    (void)IdentityServiceTestCase044();
    (void)IdentityServiceTestCase045();
    (void)IdentityServiceTestCase046();
    (void)IdentityServiceTestCase047();
}


bool FuzzDoCallback(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    (void)AddCredFuzzPart();
    (void)ExportCredFuzzPart();
    (void)QueryCredFuzzPart();
    (void)DelCredFuzzPart();
    (void)UpdateCredFuzzPart();
    (void)CredListenerFuzzPart();
    return true;
}
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoCallback(data, size);
    return 0;
}
