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
#include <vector>
#include <string>
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
/* mirrors MAX_SESSION_NUM_LIGHT_AUTH in mini_session_manager.c */
static const uint32_t FUZZ_LIGHT_SESSION_MAX_NUM = 30;
/* upper bounds for fuzz-generated random buffer / serviceId length */
static const uint32_t FUZZ_LIGHT_SESSION_RANDOM_MAX_LEN = 64;
static const uint32_t FUZZ_LIGHT_SESSION_SERVICE_MAX_LEN = 32;
/* fixed non-empty random buffer for the add-limit case, where every
   AddLightSession must succeed (non-empty random) to reach the count limit */
static uint8_t g_lightSessionRandom[FUZZ_LIGHT_SESSION_RANDOM_MAX_LEN] = { 0 };

/* Build a fully fuzzed LightSessionInitParams. The random vector and the
   serviceId string are kept by reference in the caller so their storage
   outlives the AddLightSession call that copies from them. */
static void BuildFuzzedSessionParams(FuzzedDataProvider &fdp, LightSessionInitParams *params,
    DeviceAuthCallback *callback, std::vector<uint8_t> &random, std::string &serviceId)
{
    (void)memset_s(params, sizeof(*params), 0, sizeof(*params));
    (void)memset_s(callback, sizeof(*callback), 0, sizeof(*callback));
    params->requestId = fdp.ConsumeIntegral<int64_t>();
    params->osAccountId = fdp.ConsumeIntegral<int32_t>();
    params->opCode = fdp.ConsumeIntegral<int32_t>();
    uint32_t randomLen = fdp.ConsumeIntegralInRange<uint32_t>(0, FUZZ_LIGHT_SESSION_RANDOM_MAX_LEN);
    random = fdp.ConsumeBytes<uint8_t>(randomLen);
    params->randomBuff.data = random.data();
    params->randomBuff.length = static_cast<uint32_t>(random.size());
    serviceId = fdp.ConsumeRandomLengthString(FUZZ_LIGHT_SESSION_SERVICE_MAX_LEN);
    params->serviceId = serviceId.c_str();
    params->callback = callback;
}

/* AddLightSession guards null params/callback/serviceId and returns early
   before touching g_lightSessionInfoList, so Init is not required here. The
   null inputs are inherently non-random (null is null). */
static void LightSessionNullParamTest001(FuzzedDataProvider &fdp)
{
    (void)fdp;
    (void)AddLightSession(nullptr);
    LightSessionInitParams params;
    DeviceAuthCallback callback;
    (void)memset_s(&params, sizeof(params), 0, sizeof(params));
    (void)memset_s(&callback, sizeof(callback), 0, sizeof(callback));
    params.callback = nullptr;
    (void)AddLightSession(&params);
    params.callback = &callback;
    params.serviceId = nullptr;
    (void)AddLightSession(&params);
}

static void LightSessionLifecycleTest001(FuzzedDataProvider &fdp)
{
    if (InitLightSessionManager() != HC_SUCCESS) {
        return;
    }
    LightSessionInitParams params;
    DeviceAuthCallback callback;
    std::vector<uint8_t> random;
    std::string serviceId;
    BuildFuzzedSessionParams(fdp, &params, &callback, random, serviceId);
    int64_t reqId = params.requestId;
    int32_t osAccountId = params.osAccountId;
    if (AddLightSession(&params) != HC_SUCCESS) {
        DestroyLightSessionManager();
        return;
    }
    uint8_t *queryRandom = nullptr;
    uint32_t queryLen = 0;
    char *queryServiceId = nullptr;
    (void)QueryLightSession(reqId, osAccountId, &queryRandom, &queryLen, &queryServiceId);
    if (queryRandom != nullptr) {
        HcFree(queryRandom);
        queryRandom = nullptr;
    }
    if (queryServiceId != nullptr) {
        HcFree(queryServiceId);
        queryServiceId = nullptr;
    }
    /* A second fuzzed requestId for the non-matching path; if it happens to
       equal reqId the matching path is exercised again, which is harmless. */
    int64_t nonMatchReqId = fdp.ConsumeIntegral<int64_t>();
    (void)QueryLightSession(nonMatchReqId, osAccountId, &queryRandom, &queryLen, &queryServiceId);
    if (queryRandom != nullptr) {
        HcFree(queryRandom);
        queryRandom = nullptr;
    }
    if (queryServiceId != nullptr) {
        HcFree(queryServiceId);
        queryServiceId = nullptr;
    }
    (void)DeleteLightSession(reqId, osAccountId);
    (void)DeleteLightSession(nonMatchReqId, osAccountId);
    DestroyLightSessionManager();
}

/* Exercise the max-session-number limit branch; FUZZ_LIGHT_SESSION_MAX_NUM
   mirrors MAX_SESSION_NUM_LIGHT_AUTH in mini_session_manager.c. requestId
   uses the loop index (0..30, no overflow) and osAccountId is fuzzed; the
   random/serviceId are fixed-valid so every add succeeds to reach the count
   limit. */
static void LightSessionAddLimitTest001(FuzzedDataProvider &fdp)
{
    if (InitLightSessionManager() != HC_SUCCESS) {
        return;
    }
    int32_t osAccountId = fdp.ConsumeIntegral<int32_t>();
    LightSessionInitParams params;
    DeviceAuthCallback callback;
    (void)memset_s(&params, sizeof(params), 0, sizeof(params));
    (void)memset_s(&callback, sizeof(callback), 0, sizeof(callback));
    params.osAccountId = osAccountId;
    params.randomBuff.data = g_lightSessionRandom;
    params.randomBuff.length = FUZZ_LIGHT_SESSION_RANDOM_MAX_LEN;
    params.serviceId = "fuzz_service";
    params.callback = &callback;
    uint32_t index;
    for (index = 0; index <= FUZZ_LIGHT_SESSION_MAX_NUM; ++index) {
        params.requestId = static_cast<int64_t>(index);
        (void)AddLightSession(&params);
    }
    DestroyLightSessionManager();
}

using TestFunc = void(*)(FuzzedDataProvider &);
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
    g_testFuncs[testId % TEST_FUNC_COUNT](fdp);
    return true;
}
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::FuzzDoCallback(data, size);
    return 0;
}
