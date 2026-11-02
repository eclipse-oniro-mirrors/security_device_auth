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

#ifndef V1_TEST_HELPER_H
#define V1_TEST_HELPER_H

#include <cstdint>
#include "compatible_bind_sub_session.h"
#include "compatible_auth_sub_session.h"
#include "compatible_auth_sub_session_common.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "json_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ===== shared constants ===== */
#define V1_TEST_APP_ID "TestAppId"
#define V1_TEST_GROUP_NAME "TestGroup"
#define V1_TEST_AUTH_ID "TestAuthId"
#define V1_TEST_AUTH_ID2 "TestAuthId2"
#define V1_TEST_PIN_CODE "123456"
#define V1_TEST_SERVICE_PKG_NAME "TestAppId"
#define V1_TEST_GROUP_ID "E2EE6F830B176B2C96A9F99BFAE2A61F5D1490B9F4A090E9D8C2874C230C7C21"
#define V1_TEST_UDID_CLIENT "5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242B3930"
#define V1_TEST_UDID_SERVER "52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C"
#define V1_TEST_GROUP_DATA_PATH "/data/service/el1/public/deviceauthMock"
#define V1_TEST_HKS_MAIN_DATA_PATH "/data/service/el1/public/huks_service/tmp/+0+0+0+0"
#define V1_TEST_SLEEP_TIME 50000
#define V1_TEST_BUFFER_SIZE 128
#define V1_TEST_TRANS_BUFFER_SIZE 4096
#define V1_TEST_OS_ACCOUNT_ID 100
#define V1_TEST_CUR_TASK_ID 1001
#define V1_TEST_SESSION_REQ_ID 123
#define V1_TEST_MAX_WAIT_ROUNDS 200

/* ===== shared callback ===== */
typedef struct {
    volatile int asyncStatus;
    uint8_t *transmitData;
    uint32_t transmitDataLen;
    uint32_t transmitDataMaxLen;
} V1TestContext;

void V1ResetTransmitBuffer(V1TestContext *ctx);
const DeviceAuthCallback *V1GetGmCallback(void);
const DeviceAuthCallback *V1GetFailCallback(void);

/* ===== shared helpers ===== */
void V1DeleteDatabase(void);
int32_t V1CreateDemoGroup(int32_t osAccountId, int64_t reqId, const char *appId, const char *createParams);

/* ===== session construction helpers ===== */
CompatibleBindSubSession *V1NewBindSession(int32_t type, int32_t status);
void V1FreeBindSession(CompatibleBindSubSession *session);
CompatibleAuthSubSession *V1NewAuthSession(int32_t type, int32_t status, CJson *authParam);
void V1FreeAuthSession(CompatibleAuthSubSession *session);

#ifdef __cplusplus
}
#endif
#endif
