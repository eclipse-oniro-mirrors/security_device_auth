/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "mini_session_fuzzer.h"

#include <cstdint>
#include <cstddef>
#include <fuzzer/FuzzedDataProvider.h>
#include "common_defs.h"
#include "device_auth.h"
#include "mini_session_manager.h"
#include "securec.h"

/* mini_session_manager.c calls ProcessErrorCallback (defined in
 * callback_manager.c) only on the session-timeout path, which never fires
 * during a short fuzz run. Provide a no-op stub so the fuzzer links without
 * pulling callback_manager.c and its transitive deps (mirrors
 * mini_session_manager_test.cpp). */
extern "C" void ProcessErrorCallback(int64_t reqId, int operationCode, int errorCode,
    const char *errorReturn, const DeviceAuthCallback *callback)
{
    (void)reqId;
    (void)operationCode;
    (void)errorCode;
    (void)errorReturn;
    (void)callback;
}

namespace OHOS {
static const int32_t FUZZ_OS_ACCOUNT_ID = 100;
static const int64_t FUZZ_LIGHT_SESSION_REQ_ID = 0x1234;
static const int32_t FUZZ_LIGHT_SESSION_OP_CODE = 1;
static const uint32_t FUZZ_LIGHT_SESSION_RANDOM_LEN = sizeof(uint64_t);
static uint8_t g_lightSessionRandom[FUZZ_LIGHT_SESSION_RANDOM_LEN] = { 0 };
/* mirrors MAX_SESSION_NUM_LIGHT_AUTH in mini_session_manager.c */
static const uint32_t FUZZ_LIGHT_SESSION_MAX_NUM = 30;

static void InitFuzzLightSessionParams(LightSessionInitParams *params, DeviceAuthCallback *callback,
    int64_t requestId)
{
    (void)memset_s(params, sizeof(*params), 0, sizeof(*params));
    (void)memset_s(callback, sizeof(*callback), 0, sizeof(*callback));
    params->requestId = requestId;
    params->osAccountId = FUZZ_OS_ACCOUNT_ID;
    params->opCode = FUZZ_LIGHT_SESSION_OP_CODE;
    params->serviceId = "fuzz_service";
    params->randomBuff.data = g_lightSessionRandom;
    params->randomBuff.length = FUZZ_LIGHT_SESSION_RANDOM_LEN;
    params->callback = callback;
}

/* AddLightSession guards null params/callback/serviceId and returns early
   before touching g_lightSessionInfoList, so Init is not required here. */
static void LightSessionNullParamTest001()
{
    (void)AddLightSession(nullptr);
    LightSessionInitParams params;
    DeviceAuthCallback callback;
    InitFuzzLightSessionParams(&params, &callback, FUZZ_LIGHT_SESSION_REQ_ID);
    params.callback = nullptr;
    (void)AddLightSession(&params);
    InitFuzzLightSessionParams(&params, &callback, FUZZ_LIGHT_SESSION_REQ_ID);
    params.serviceId = nullptr;
    (void)AddLightSession(&params);
}

static void LightSessionLifecycleTest001()
{
    if (InitLightSessionManager() != HC_SUCCESS) {
        return;
    }
    LightSessionInitParams params;
    DeviceAuthCallback callback;
    InitFuzzLightSessionParams(&params, &callback, FUZZ_LIGHT_SESSION_REQ_ID);
    if (AddLightSession(&params) != HC_SUCCESS) {
        DestroyLightSessionManager();
        return;
    }
    uint8_t *randomVal = nullptr;
    uint32_t randomLen = 0;
    char *serviceId = nullptr;
    (void)QueryLightSession(FUZZ_LIGHT_SESSION_REQ_ID, FUZZ_OS_ACCOUNT_ID, &randomVal, &randomLen, &serviceId);
    if (randomVal != nullptr) {
        HcFree(randomVal);
    }
    if (serviceId != nullptr) {
        HcFree(serviceId);
    }
    (void)QueryLightSession(FUZZ_LIGHT_SESSION_REQ_ID + 1, FUZZ_OS_ACCOUNT_ID, &randomVal, &randomLen, &serviceId);
    (void)DeleteLightSession(FUZZ_LIGHT_SESSION_REQ_ID, FUZZ_OS_ACCOUNT_ID);
    (void)DeleteLightSession(FUZZ_LIGHT_SESSION_REQ_ID + 1, FUZZ_OS_ACCOUNT_ID);
    DestroyLightSessionManager();
}

/* Exercise the max-session-number limit branch; FUZZ_LIGHT_SESSION_MAX_NUM
   mirrors MAX_SESSION_NUM_LIGHT_AUTH in mini_session_manager.c. */
static void LightSessionAddLimitTest001()
{
    if (InitLightSessionManager() != HC_SUCCESS) {
        return;
    }
    LightSessionInitParams params;
    DeviceAuthCallback callback;
    uint32_t index;
    for (index = 0; index <= FUZZ_LIGHT_SESSION_MAX_NUM; ++index) {
        InitFuzzLightSessionParams(&params, &callback, FUZZ_LIGHT_SESSION_REQ_ID + index);
        (void)AddLightSession(&params);
    }
    DestroyLightSessionManager();
}

using TestFunc = void(*)(void);
static TestFunc g_testFuncs[] = {
    LightSessionNullParamTest001,
    LightSessionLifecycleTest001,
    LightSessionAddLimitTest001,
};
constexpr size_t TEST_FUNC_COUNT = sizeof(g_testFuncs) / sizeof(g_testFuncs[0]);

bool FuzzDoCallback(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return false;
    }
    FuzzedDataProvider fdp(data, size);
    uint32_t testId = fdp.ConsumeIntegral<uint32_t>();
    g_testFuncs[testId % TEST_FUNC_COUNT]();
    return true;
}
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::FuzzDoCallback(data, size);
    return 0;
}
