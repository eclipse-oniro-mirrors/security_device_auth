/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "devauthservgetregisterinfo_fuzzer.h"
#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "hc_dev_info.h"
#include "hc_log.h"
#include "json_utils.h"

namespace OHOS {
    static void GenerateReqJson(CJson *json, const char *deviceId)
    {
        AddStringToJson(json, FIELD_VERSION, "1");
        AddStringToJson(json, FIELD_DEVICE_ID, deviceId);
        AddStringToJson(json, FIELD_USER_ID, "123");
    }

    bool FuzzDoGetRegisterInfo(const uint8_t* data, size_t size)
    {
        if (data == nullptr) {
            return false;
        }
        InitDeviceAuthService();
        CJson *reqJson = CreateJson();
        std::string deviceId(reinterpret_cast<const char *>(data), size);
        GenerateReqJson(reqJson, deviceId.c_str());
        char *reqJsonStr = PackJsonToString(reqJson);
        FreeJson(reqJson);
        const DeviceGroupManager *gmInstance = GetGmInstance();
        char *returnJsonStr = nullptr;
        LOGI("reqJsonStr: %" LOG_PUB "s", reqJsonStr);
        gmInstance->getRegisterInfo(reqJsonStr, &returnJsonStr);
        if (returnJsonStr != nullptr) {
            gmInstance->destroyInfo(&returnJsonStr);
        }
        ClearAndFreeJsonString(reqJsonStr);
        DestroyDeviceAuthService();
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoGetRegisterInfo(data, size);
    return 0;
}

