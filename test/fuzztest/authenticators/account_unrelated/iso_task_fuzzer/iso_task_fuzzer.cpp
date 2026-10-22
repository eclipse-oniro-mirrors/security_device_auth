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

#include "iso_task_fuzzer.h"

#include <cstdint>
#include <cstddef>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "common_defs.h"
#include "alg_defs.h"
#include "das_task_common.h"
#include "device_auth.h"
#include "hilog/log.h"
#include "iso_protocol_common.h"
#include "iso_task_main.h"
#include "json_utils.h"
#include "protocol_common.h"
#include "securec.h"
#include "uint8buff_utils.h"

/* Stub hilog so the fuzzer links without libhilog (env conflict). */
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

/* iso_protocol_common.c is compiled for real (InitIsoBaseParams fills
   baseParams + sets params->loader = GetLoaderInstance()). Stub
   GetLoaderInstance to return a no-op AlgLoader so process() can be
   invoked: the 9 loader functions the iso_task/protocol tree calls are
   no-ops returning HC_ERROR, exercising process parsing + error paths
   without real HUKS. */
static int32_t StubGenerateRandom(Uint8Buff *rand) { (void)rand; return HC_SUCCESS; }
static int32_t StubComputeHmac(const KeyParams *kp, const Uint8Buff *msg, Uint8Buff *out) { (void)kp; (void)msg; (void)out; return HC_SUCCESS; }
static int32_t StubComputeHmac3(const KeyParams *kp, const Uint8Buff *msg, Uint8Buff *out) { (void)kp; (void)msg; (void)out; return HC_SUCCESS; }
static int32_t StubComputeHkdf(const KeyParams *kp, const Uint8Buff *salt, const Uint8Buff *info, Uint8Buff *out) { (void)kp; (void)salt; (void)info; (void)out; return HC_SUCCESS; }
static int32_t StubImportSymKey(const KeyParams *kp, const Uint8Buff *tok, KeyPurpose pur, const ExtraInfo *ex) { (void)kp; (void)tok; (void)pur; (void)ex; return HC_SUCCESS; }
static int32_t StubDeleteKey(const Uint8Buff *alias, bool de, int32_t os) { (void)alias; (void)de; (void)os; return HC_SUCCESS; }
static int32_t StubAesGcmEnc(const KeyParams *kp, const Uint8Buff *plain, const GcmParam *gi, Uint8Buff *out) { (void)kp; (void)plain; (void)gi; (void)out; return HC_SUCCESS; }
static int32_t StubAesGcmDec(const KeyParams *kp, const Uint8Buff *cipher, const GcmParam *gi, Uint8Buff *out) { (void)kp; (void)cipher; (void)gi; (void)out; return HC_SUCCESS; }
static int32_t StubSha256(const Uint8Buff *msg, Uint8Buff *hash) { (void)msg; (void)hash; return HC_SUCCESS; }

static AlgLoader g_stubLoader = {
    .generateRandom = StubGenerateRandom,
    .computeHmac = StubComputeHmac,
    .computeHmacWithThreeStage = StubComputeHmac3,
    .computeHkdf = StubComputeHkdf,
    .importSymmetricKey = StubImportSymKey,
    .deleteKey = StubDeleteKey,
    .aesGcmEncrypt = StubAesGcmEnc,
    .aesGcmDecrypt = StubAesGcmDec,
    .sha256 = StubSha256,
};
extern "C" const AlgLoader *GetRealLoaderInstance(void) { return &g_stubLoader; }

/* Stub the iso_protocol_common.c functions (not compiled; only reached on
   process() path). InitIsoBaseParams returns HC_SUCCESS so creation always
   proceeds; the process functions return 0 so Process() in iso_client/
   server_task.c steps through them. */
extern "C" int32_t InitIsoBaseParams(const CJson *in, IsoBaseParams *params) { (void)in; (void)params; return HC_SUCCESS; }
extern "C" void DestroyIsoBaseParams(IsoBaseParams *params) { (void)params; }
extern "C" int IsoClientGenRandom(IsoBaseParams *params) { (void)params; return 0; }
extern "C" int IsoClientGenSessionKey(IsoBaseParams *p, int r, const uint8_t *h, uint32_t l) { (void)p; (void)r; (void)h; (void)l; return 0; }
extern "C" int IsoClientCheckAndGenToken(IsoBaseParams *p, const Uint8Buff *pt, Uint8Buff *st) { (void)p; (void)pt; (void)st; return 0; }
extern "C" int IsoServerGenRandomAndToken(IsoBaseParams *p, Uint8Buff *st) { (void)p; (void)st; return 0; }
extern "C" int IsoServerGenSessionKeyAndCalToken(IsoBaseParams *p, const Uint8Buff *tf, Uint8Buff *tt) { (void)p; (void)tf; (void)tt; return 0; }
extern "C" int32_t GenerateKeyAlias(const TokenManagerParams *params, Uint8Buff *outKeyAlias)
{
    (void)params;
    (void)outKeyAlias;
    return HC_ERROR;
}
extern "C" uint32_t ProtocolMessageIn(const CJson *in)
{
    (void)in;
    return 0;
}
extern "C" int32_t GetAuthIdPeerFromPayload(const CJson *in, const Uint8Buff *authIdSelf, Uint8Buff *authIdPeer)
{
    (void)in;
    (void)authIdSelf;
    (void)authIdPeer;
    return HC_ERROR;
}
extern "C" int ClientProtocolMessageOut(CJson *out, int opCode, uint32_t step)
{
    (void)out;
    (void)opCode;
    (void)step;
    return 0;
}
extern "C" void FreeAndCleanKey(Uint8Buff *key)
{
    (void)key;
}

/* das_task_common.c / key_agree_sdk symbols not compiled; stubbed for link.
   Only reached on process() paths (now invoked). */
extern "C" int ServerProtocolMessageOut(CJson *out, int opCode, uint32_t step)
{
    (void)out;
    (void)opCode;
    (void)step;
    return 0;
}
extern "C" int32_t GetAndCheckKeyLenOnServer(const CJson *in, uint32_t keyLen)
{
    (void)in;
    (void)keyLen;
    return HC_SUCCESS;
}
extern "C" int32_t GetAndCheckAuthIdPeer(const CJson *in, const Uint8Buff *authIdSelf, const Uint8Buff *authIdPeer)
{
    (void)in;
    (void)authIdSelf;
    (void)authIdPeer;
    return HC_SUCCESS;
}

namespace OHOS {
static const char *FUZZ_ISO_PKG_NAME = "fuzz_pkg";
static const char *FUZZ_ISO_SERVICE_TYPE = "fuzz_svc";
static const int32_t FUZZ_ISO_MAX_OP_CODE = 5;
static const uint32_t FUZZ_ISO_AUTH_ID_MAX_LEN = 64;

static void BuildFuzzedIsoTaskJson(FuzzedDataProvider &fdp, CJson *in)
{
    (void)AddBoolToJson(in, FIELD_IS_CLIENT, fdp.ConsumeBool());
    (void)AddIntToJson(in, FIELD_OPERATION_CODE, fdp.ConsumeIntegralInRange<int32_t>(0, FUZZ_ISO_MAX_OP_CODE));
    std::string selfAuthId = fdp.ConsumeRandomLengthString(FUZZ_ISO_AUTH_ID_MAX_LEN);
    std::string peerAuthId = fdp.ConsumeRandomLengthString(FUZZ_ISO_AUTH_ID_MAX_LEN);
    (void)AddStringToJson(in, FIELD_SELF_AUTH_ID, selfAuthId.c_str());
    (void)AddStringToJson(in, FIELD_PEER_AUTH_ID, peerAuthId.c_str());
    (void)AddStringToJson(in, FIELD_PKG_NAME, FUZZ_ISO_PKG_NAME);
    (void)AddStringToJson(in, FIELD_SERVICE_TYPE, FUZZ_ISO_SERVICE_TYPE);
    (void)AddIntToJson(in, FIELD_SELF_TYPE, fdp.ConsumeIntegral<int32_t>());
    (void)AddIntToJson(in, FIELD_PEER_USER_TYPE, fdp.ConsumeIntegral<int32_t>());
    (void)AddIntToJson(in, FIELD_KEY_LENGTH, fdp.ConsumeIntegral<int32_t>());
    std::string pinCode = fdp.ConsumeRandomLengthString(FUZZ_ISO_AUTH_ID_MAX_LEN);
    (void)AddStringToJson(in, FIELD_PIN_CODE, pinCode.c_str());
}

static void IsoTaskCreateNullTest001(FuzzedDataProvider &fdp)
{
    (void)fdp;
    (void)CreateIsoSubTask(nullptr);
    CJson *in = CreateJson();
    if (in == nullptr) {
        return;
    }
    (void)CreateIsoSubTask(in);
    FreeJson(in);
}

static void IsoTaskCreateFuzzTest001(FuzzedDataProvider &fdp)
{
    CJson *in = CreateJson();
    if (in == nullptr) {
        return;
    }
    BuildFuzzedIsoTaskJson(fdp, in);
    SubTaskBase *task = CreateIsoSubTask(in);
    if (task != nullptr) {
        (void)task->getTaskType(task);
        CJson *out = CreateJson();
        if (out != nullptr) {
            int32_t status = 0;
            (void)task->process(task, in, out, &status);
            FreeJson(out);
        }
        task->destroyTask(task);
    }
    FreeJson(in);
}

using TestFunc = void(*)(FuzzedDataProvider &);
static TestFunc g_testFuncs[] = {
    IsoTaskCreateNullTest001,
    IsoTaskCreateFuzzTest001,
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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::FuzzDoCallback(data, size);
    return 0;
}
