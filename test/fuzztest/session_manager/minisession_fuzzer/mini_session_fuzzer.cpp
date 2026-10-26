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
#include "hilog/log.h"
#include "mini_session_manager.h"
#include "securec.h"

extern "C" void ProcessErrorCallback(int64_t reqId, int operationCode, int errorCode,
    const char *errorReturn, const DeviceAuthCallback *callback)
{
    (void)reqId;
    (void)operationCode;
    (void)errorCode;
    (void)errorReturn;
    (void)callback;
}

extern "C" int HiLogPrint(LogType type, LogLevel level, unsigned int domain,
    const char *tag, const char *fmt, ...)
{
    (void)type;
    (void)level;
    (void)domain;
    (void)tag;
    (void)fmt;
    return 0;
}

namespace OHOS {
static const uint32_t FUZZ_LIGHT_SESSION_RANDOM_MAX_LEN = 64;
static uint8_t g_lightSessionRandom[FUZZ_LIGHT_SESSION_RANDOM_MAX_LEN] = { 0 };

static void FillFuzzedLightSessionParams(LightSessionInitParams *params,
    DeviceAuthCallback *callback, FuzzedDataProvider &fdp)
{
    (void)memset_s(params, sizeof(*params), 0, sizeof(*params));
    (void)memset_s(callback, sizeof(*callback), 0, sizeof(*callback));
    params->requestId = fdp.ConsumeIntegral<int64_t>();
    params->osAccountId = fdp.ConsumeIntegral<int32_t>();
    params->opCode = fdp.ConsumeIntegral<int32_t>();
    params->serviceId = "fuzz_service";
    params->randomBuff.data = g_lightSessionRandom;
    params->randomBuff.length = FUZZ_LIGHT_SESSION_RANDOM_MAX_LEN;
    params->callback = callback;
}

/* Fdp-driven operation sequence: 0=Add, 1=Query, 2=Delete.
   Explores unordered sequences (Delete before Add, double Add, etc.). */
bool FuzzDoCallback(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return false;
    }
    FuzzedDataProvider fdp(data, size);
    if (InitLightSessionManager() != HC_SUCCESS) {
        return false;
    }
    while (fdp.remaining_bytes() > 0) {
        uint8_t op = fdp.ConsumeIntegralInRange<uint8_t>(0, 2);
        int64_t reqId = fdp.ConsumeIntegral<int64_t>();
        int32_t osAccountId = fdp.ConsumeIntegral<int32_t>();
        if (op == 0) {
            LightSessionInitParams params;
            DeviceAuthCallback callback;
            FillFuzzedLightSessionParams(&params, &callback, fdp);
            params.requestId = reqId;
            params.osAccountId = osAccountId;
            (void)AddLightSession(&params);
        } else if (op == 1) {
            uint8_t *randomVal = nullptr;
            uint32_t randomLen = 0;
            char *serviceId = nullptr;
            (void)QueryLightSession(reqId, osAccountId, &randomVal, &randomLen, &serviceId);
            if (randomVal != nullptr) {
                HcFree(randomVal);
            }
            if (serviceId != nullptr) {
                HcFree(serviceId);
            }
        } else {
            (void)DeleteLightSession(reqId, osAccountId);
        }
    }
    DestroyLightSessionManager();
    return true;
}
}  // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::FuzzDoCallback(data, size);
    return 0;
}
