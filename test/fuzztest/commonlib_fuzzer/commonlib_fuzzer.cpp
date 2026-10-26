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

#include "commonlib_fuzzer.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "account_module_defines.h"
#include "clib_error.h"
#include "cred_tlv_parser.h"
#include "device_auth.h"
#include "group_data_manager.h"
#include "hc_string.h"
#include "hc_tlv_parser.h"
#include "json_utils.h"
#include "mk_agree_task.h"
#include "operation_data_manager.h"
#include "pseudonym_manager.h"
#include "securec.h"
#include "string_util.h"
#include "uint8buff_utils.h"
#include "base/security/device_auth/common_lib/impl/src/hc_parcel.c"

namespace OHOS {
static const uint32_t TEST_BUFFER_SIZE = 16;
static const uint16_t FUZZ_TLV_TAG_ROOT = 0x1000;
static const uint16_t FUZZ_TLV_TAG_M1 = 0x0001;
static const uint16_t FUZZ_TLV_TAG_M2 = 0x0002;
static const uint16_t FUZZ_TLV_TAG_UNKNOWN = 0x9999;
static const uint16_t FUZZ_TLV_TAG_BUF = 0x1234;
static const uint16_t FUZZ_TLV_UINT32_NODE_LEN =
    sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint32_t);
static const uint16_t FUZZ_TLV_STRUCT_LEN_TWO_MEMBERS = 2 * FUZZ_TLV_UINT32_NODE_LEN;
static const uint16_t FUZZ_TLV_STRUCT_LEN_THREE_NODES = 3 * FUZZ_TLV_UINT32_NODE_LEN;
static const uint32_t FUZZ_CRED_TLV_UINT32_NODE_LEN =
    sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint32_t);
static const uint32_t FUZZ_CRED_TLV_STRUCT_LEN_TWO_MEMBERS = 2 * FUZZ_CRED_TLV_UINT32_NODE_LEN;
static const uint32_t FUZZ_CRED_TLV_STRUCT_LEN_THREE_NODES = 3 * FUZZ_CRED_TLV_UINT32_NODE_LEN;
static const uint32_t FUZZ_RECORD_BUF_SIZE = 256;
static const uint32_t FUZZ_STRING_MAX_LEN = 64;

typedef struct {
    DECLARE_TLV_STRUCT(2)
    TlvUint32 member1;
    TlvUint32 member2;
} FuzzTlvStruct;

static void InitFuzzTlvStruct(FuzzTlvStruct *tlv, unsigned short checkTag)
{
    unsigned int index = 0;
    (void)memset_s(&tlv->base, sizeof(tlv->base), 0, sizeof(tlv->base));
    tlv->base.checkTag = GetTag(checkTag, FUZZ_TLV_TAG_ROOT);
    InitTlvUint32(&tlv->member1, FUZZ_TLV_TAG_M1);
    tlv->offset[index++] = offsetof(FuzzTlvStruct, member1);
    InitTlvUint32(&tlv->member2, FUZZ_TLV_TAG_M2);
    tlv->offset[index++] = offsetof(FuzzTlvStruct, member2);
    tlv->offsetCount = index;
    tlv->base.parse = ParseTlvStruct;
    tlv->base.getlen = GetLenTlvStruct;
    tlv->base.encode = EncodeTlvStruct;
    tlv->base.deinit = DeinitTlvStruct;
}

typedef struct {
    DECLARE_CRED_TLV_STRUCT(2)
    CredTlvUint32 member1;
    CredTlvUint32 member2;
} FuzzCredTlvStruct;

static void InitFuzzCredTlvStruct(FuzzCredTlvStruct *tlv, unsigned short checkTag)
{
    unsigned int index = 0;
    (void)memset_s(&tlv->base, sizeof(tlv->base), 0, sizeof(tlv->base));
    tlv->base.checkTag = GetCredTag(checkTag, FUZZ_TLV_TAG_ROOT);
    InitCredTlvUint32(&tlv->member1, FUZZ_TLV_TAG_M1);
    tlv->offset[index++] = offsetof(FuzzCredTlvStruct, member1);
    InitCredTlvUint32(&tlv->member2, FUZZ_TLV_TAG_M2);
    tlv->offset[index++] = offsetof(FuzzCredTlvStruct, member2);
    tlv->offsetCount = index;
    tlv->base.parse = ParseCredTlvStruct;
    tlv->base.getlen = GetLenCredTlvStruct;
    tlv->base.encode = EncodeCredTlvStruct;
    tlv->base.deinit = DeinitCredTlvStruct;
}

/* ===== TLV: merged struct roundtrip / strict-fail / unknown-tag ===== */
static void TlvStructFuzzTest001(FuzzedDataProvider &fdp)
{
    FuzzTlvStruct tlvStruct;
    InitFuzzTlvStruct(&tlvStruct, FUZZ_TLV_TAG_ROOT);
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE * 4, TEST_BUFFER_SIZE);
    ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_ROOT);
    uint8_t mode = fdp.ConsumeIntegralInRange<uint8_t>(0, 2);
    uint32_t valA = fdp.ConsumeIntegral<uint32_t>();
    uint32_t valB = fdp.ConsumeIntegral<uint32_t>();
    if (mode == 0) {
        ParcelWriteUint16(&parcel, FUZZ_TLV_STRUCT_LEN_TWO_MEMBERS);
        ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_M1);
        ParcelWriteUint16(&parcel, sizeof(uint32_t));
        ParcelWriteUint32(&parcel, valA);
        ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_M2);
        ParcelWriteUint16(&parcel, sizeof(uint32_t));
        ParcelWriteUint32(&parcel, valB);
        (void)ParseTlvNode((TlvBase *)&tlvStruct, &parcel, HC_TRUE);
    } else if (mode == 1) {
        ParcelWriteUint16(&parcel, FUZZ_TLV_UINT32_NODE_LEN);
        ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_M1);
        ParcelWriteUint16(&parcel, sizeof(uint32_t));
        ParcelWriteUint32(&parcel, valA);
        (void)ParseTlvNode((TlvBase *)&tlvStruct, &parcel, HC_TRUE);
    } else {
        ParcelWriteUint16(&parcel, FUZZ_TLV_STRUCT_LEN_THREE_NODES);
        ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_M1);
        ParcelWriteUint16(&parcel, sizeof(uint32_t));
        ParcelWriteUint32(&parcel, valA);
        ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_UNKNOWN);
        ParcelWriteUint16(&parcel, sizeof(uint32_t));
        ParcelWriteUint32(&parcel, valB);
        ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_M2);
        ParcelWriteUint16(&parcel, sizeof(uint32_t));
        ParcelWriteUint32(&parcel, valA);
        (void)ParseTlvNode((TlvBase *)&tlvStruct, &parcel, HC_FALSE);
    }
    DeleteParcel(&parcel);
    tlvStruct.base.deinit((TlvBase *)&tlvStruct);
}

static void TlvEncodeGetLenDeinitTest001(FuzzedDataProvider &fdp)
{
    (void)EncodeTlvStruct(nullptr, nullptr);
    (void)GetLenTlvStruct(nullptr);
    DeinitTlvStruct(nullptr);
    FuzzTlvStruct tlvStruct;
    InitFuzzTlvStruct(&tlvStruct, FUZZ_TLV_TAG_ROOT);
    tlvStruct.member1.data = fdp.ConsumeIntegral<uint32_t>();
    tlvStruct.member2.data = fdp.ConsumeIntegral<uint32_t>();
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE * 4, TEST_BUFFER_SIZE);
    (void)EncodeTlvStruct((TlvBase *)&tlvStruct, &parcel);
    (void)GetLenTlvStruct((TlvBase *)&tlvStruct);
    DeleteParcel(&parcel);
    DeinitTlvStruct((TlvBase *)&tlvStruct);
}

static void TlvMessageFuzzTest001(FuzzedDataProvider &fdp)
{
    TlvUint32 tlvUint32;
    InitTlvUint32(&tlvUint32, FUZZ_TLV_TAG_BUF);
    tlvUint32.data = fdp.ConsumeIntegral<uint32_t>();
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE * 2, TEST_BUFFER_SIZE);
    (void)EncodeTlvMessage((TlvBase *)&tlvUint32, &parcel);
    TlvUint32 tlvDst;
    InitTlvUint32(&tlvDst, FUZZ_TLV_TAG_BUF);
    (void)DecodeTlvMessage((TlvBase *)&tlvDst, &parcel, HC_FALSE);
    DeleteParcel(&parcel);
    tlvUint32.base.deinit((TlvBase *)&tlvUint32);
    tlvDst.base.deinit((TlvBase *)&tlvDst);
}

static void TlvBufferFuzzTest001(FuzzedDataProvider &fdp)
{
    InitTlvBuffer(nullptr, FUZZ_TLV_TAG_BUF);
    TlvBuffer tlvBuf;
    InitTlvBuffer(&tlvBuf, FUZZ_TLV_TAG_BUF);
    uint32_t dataLen = fdp.ConsumeIntegralInRange<uint32_t>(0, FUZZ_STRING_MAX_LEN);
    auto rawBytes = fdp.ConsumeBytes<uint8_t>(dataLen);
    ParcelWrite(&tlvBuf.data, rawBytes.data(), rawBytes.size());
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    (void)EncodeTlvBuffer((TlvBase *)&tlvBuf, &parcel);
    DeleteParcel(&parcel);
    tlvBuf.base.deinit((TlvBase *)&tlvBuf);
}

static void TlvStringFuzzTest001(FuzzedDataProvider &fdp)
{
    TlvString tlvStr;
    InitTlvString(&tlvStr, FUZZ_TLV_TAG_BUF);
    std::string str = fdp.ConsumeRandomLengthString(FUZZ_STRING_MAX_LEN);
    StringSetPointer(&tlvStr.data, str.c_str());
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    (void)EncodeTlvString((TlvBase *)&tlvStr, &parcel);
    DeleteParcel(&parcel);
    tlvStr.base.deinit((TlvBase *)&tlvStr);
}

static void TlvFixLengthTypesFuzzTest001(FuzzedDataProvider &fdp)
{
    TlvUint32 u32;
    InitTlvUint32(&u32, FUZZ_TLV_TAG_BUF);
    u32.data = fdp.ConsumeIntegral<uint32_t>();
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE * 4, TEST_BUFFER_SIZE);
    (void)EncodeTlvMessage((TlvBase *)&u32, &parcel);
    TlvUint32 u32Dst;
    InitTlvUint32(&u32Dst, FUZZ_TLV_TAG_BUF);
    (void)DecodeTlvMessage((TlvBase *)&u32Dst, &parcel, HC_FALSE);
    DeleteParcel(&parcel);
    u32.base.deinit((TlvBase *)&u32);
    u32Dst.base.deinit((TlvBase *)&u32Dst);
}

/* ===== cred_tlv: merged struct roundtrip / unknown-tag / strict-fail ===== */
static void CredTlvStructFuzzTest001(FuzzedDataProvider &fdp)
{
    FuzzCredTlvStruct tlvStruct;
    InitFuzzCredTlvStruct(&tlvStruct, FUZZ_TLV_TAG_ROOT);
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE * 4, TEST_BUFFER_SIZE);
    ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_ROOT);
    uint8_t mode = fdp.ConsumeIntegralInRange<uint8_t>(0, 2);
    uint32_t valA = fdp.ConsumeIntegral<uint32_t>();
    uint32_t valB = fdp.ConsumeIntegral<uint32_t>();
    if (mode == 0) {
        ParcelWriteUint32(&parcel, FUZZ_CRED_TLV_STRUCT_LEN_TWO_MEMBERS);
        ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_M1);
        ParcelWriteUint32(&parcel, sizeof(uint32_t));
        ParcelWriteUint32(&parcel, valA);
        ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_M2);
        ParcelWriteUint32(&parcel, sizeof(uint32_t));
        ParcelWriteUint32(&parcel, valB);
        (void)ParseCredTlvNode((CredTlvBase *)&tlvStruct, &parcel, HC_TRUE);
    } else if (mode == 1) {
        ParcelWriteUint32(&parcel, FUZZ_CRED_TLV_STRUCT_LEN_THREE_NODES);
        ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_M1);
        ParcelWriteUint32(&parcel, sizeof(uint32_t));
        ParcelWriteUint32(&parcel, valA);
        ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_UNKNOWN);
        ParcelWriteUint32(&parcel, sizeof(uint32_t));
        ParcelWriteUint32(&parcel, valB);
        ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_M2);
        ParcelWriteUint32(&parcel, sizeof(uint32_t));
        ParcelWriteUint32(&parcel, valA);
        (void)ParseCredTlvNode((CredTlvBase *)&tlvStruct, &parcel, HC_FALSE);
    } else {
        ParcelWriteUint32(&parcel, FUZZ_CRED_TLV_UINT32_NODE_LEN);
        ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_M1);
        ParcelWriteUint32(&parcel, sizeof(uint32_t));
        ParcelWriteUint32(&parcel, valA);
        (void)ParseCredTlvNode((CredTlvBase *)&tlvStruct, &parcel, HC_TRUE);
    }
    DeleteParcel(&parcel);
    tlvStruct.base.deinit((CredTlvBase *)&tlvStruct);
}

static void CredTlvBufferFuzzTest001(FuzzedDataProvider &fdp)
{
    CredTlvBuffer tlvBuf;
    InitCredTlvBuffer(&tlvBuf, FUZZ_TLV_TAG_BUF);
    uint32_t dataLen = fdp.ConsumeIntegralInRange<uint32_t>(0, FUZZ_STRING_MAX_LEN);
    auto rawBytes = fdp.ConsumeBytes<uint8_t>(dataLen);
    ParcelWrite(&tlvBuf.data, rawBytes.data(), rawBytes.size());
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    (void)EncodeCredTlvBuffer((CredTlvBase *)&tlvBuf, &parcel);
    DeleteParcel(&parcel);
    tlvBuf.base.deinit((CredTlvBase *)&tlvBuf);
}

static void CredTlvStringFuzzTest001(FuzzedDataProvider &fdp)
{
    CredTlvString tlvStr;
    InitCredTlvString(&tlvStr, FUZZ_TLV_TAG_BUF);
    std::string str = fdp.ConsumeRandomLengthString(FUZZ_STRING_MAX_LEN);
    StringSetPointer(&tlvStr.data, str.c_str());
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    (void)EncodeCredTlvString((CredTlvBase *)&tlvStr, &parcel);
    DeleteParcel(&parcel);
    tlvStr.base.deinit((CredTlvBase *)&tlvStr);
}

/* ===== data_manager ===== */
static void OperationRecordTest001(FuzzedDataProvider &fdp)
{
    (void)DeepCopyOperationRecord(nullptr);
    OperationRecord *rec = CreateOperationRecord();
    if (rec == nullptr) {
        return;
    }
    std::string caller = fdp.ConsumeRandomLengthString(FUZZ_STRING_MAX_LEN);
    std::string function = fdp.ConsumeRandomLengthString(FUZZ_STRING_MAX_LEN);
    std::string info = fdp.ConsumeRandomLengthString(128);
    CopyHcStringForcibly(&rec->caller, caller.c_str());
    CopyHcStringForcibly(&rec->function, function.c_str());
    CopyHcStringForcibly(&rec->operationInfo, info.c_str());
    rec->operationType = fdp.ConsumeIntegral<uint32_t>();
    OperationRecord *copy = DeepCopyOperationRecord(rec);
    if (copy != nullptr) {
        DestroyOperationRecord(copy);
    }
    DestroyOperationRecord(rec);
}

static void OperationDataManagerTest001(FuzzedDataProvider &fdp)
{
    (void)InitOperationDataManager();
    OperationRecord *rec = CreateOperationRecord();
    if (rec == nullptr) {
        return;
    }
    std::string caller = fdp.ConsumeRandomLengthString(FUZZ_STRING_MAX_LEN);
    std::string function = fdp.ConsumeRandomLengthString(FUZZ_STRING_MAX_LEN);
    std::string info = fdp.ConsumeRandomLengthString(128);
    CopyHcStringForcibly(&rec->caller, caller.c_str());
    CopyHcStringForcibly(&rec->function, function.c_str());
    CopyHcStringForcibly(&rec->operationInfo, info.c_str());
    rec->operationType = fdp.ConsumeIntegral<uint32_t>();
    int32_t osAccountId = fdp.ConsumeIntegral<int32_t>();
    (void)RecordOperationData(osAccountId, rec);
    char record[FUZZ_RECORD_BUF_SIZE] = { 0 };
    (void)GetOperationDataRecently(osAccountId, OPERATION_ANY, record, sizeof(record), 1);
    DestroyOperationRecord(rec);
}

static void SetAnonymousFieldTest001(FuzzedDataProvider &fdp)
{
    CJson *operationInfo = CreateJson();
    if (operationInfo == nullptr) {
        return;
    }
    std::string str = fdp.ConsumeRandomLengthString(FUZZ_STRING_MAX_LEN);
    std::string field = fdp.ConsumeRandomLengthString(32);
    SetAnonymousField(str.c_str(), field.c_str(), operationInfo);
    SetAnonymousField(nullptr, field.c_str(), operationInfo);
    SetAnonymousField(str.c_str(), nullptr, operationInfo);
    FreeJson(operationInfo);
}

/* ===== mk_agree ===== */
static void MkAgreeTaskProtocolTypeTest001(FuzzedDataProvider &fdp)
{
    CJson *in = CreateJson();
    if (in == nullptr) {
        return;
    }
    (void)AddBoolToJson(in, FIELD_IS_CLIENT, fdp.ConsumeBool());
    MkAgreeTaskBase *task = nullptr;
    int32_t proto = fdp.ConsumeIntegral<int32_t>();
    (void)CreateMkAgreeTask(proto, in, &task);
    CJson *empty = CreateJson();
    (void)CreateMkAgreeTask(proto, empty, &task);
    FreeJson(empty);
    FreeJson(in);
}

static void MkAgreeTaskPakeAttemptTest001(FuzzedDataProvider &fdp)
{
    CJson *in = CreateJson();
    if (in == nullptr) {
        return;
    }
    (void)AddBoolToJson(in, FIELD_IS_CLIENT, fdp.ConsumeBool());
    MkAgreeTaskBase *task = nullptr;
    int32_t res = CreateMkAgreeTask(TASK_TYPE_PAKE, in, &task);
    if (res == HC_SUCCESS && task != nullptr) {
        CJson *out = CreateJson();
        if (out != nullptr) {
            (void)task->process(task, in, out);
            FreeJson(out);
        }
        task->destroy(task);
    }
    FreeJson(in);
}

/* ===== pseudonym ===== */
static void PseudonymNormalQueryTest001(FuzzedDataProvider &fdp)
{
    PseudonymManager *inst = GetPseudonymInstance();
    if (inst == nullptr) {
        return;
    }
    int32_t osAccountId = fdp.ConsumeIntegral<int32_t>();
    std::string pid = fdp.ConsumeRandomLengthString(FUZZ_STRING_MAX_LEN);
    std::string key = fdp.ConsumeRandomLengthString(FUZZ_STRING_MAX_LEN);
    char *realInfo = nullptr;
    (void)inst->getRealInfo(osAccountId, pid.c_str(), &realInfo);
    if (realInfo != nullptr) {
        HcFree(realInfo);
        realInfo = nullptr;
    }
    char *pseudonymId = nullptr;
    (void)inst->getPseudonymId(osAccountId, key.c_str(), &pseudonymId);
    if (pseudonymId != nullptr) {
        HcFree(pseudonymId);
        pseudonymId = nullptr;
    }
    (void)inst->isNeedRefreshPseudonymId(osAccountId, key.c_str());
}

static void PseudonymDeleteTest001(FuzzedDataProvider &fdp)
{
    PseudonymManager *inst = GetPseudonymInstance();
    if (inst == nullptr) {
        return;
    }
    int32_t osAccountId = fdp.ConsumeIntegral<int32_t>();
    std::string dev = fdp.ConsumeRandomLengthString(FUZZ_STRING_MAX_LEN);
    std::string key = fdp.ConsumeRandomLengthString(FUZZ_STRING_MAX_LEN);
    (void)inst->deleteAllPseudonymId(osAccountId, dev.c_str());
    (void)inst->deletePseudonymId(osAccountId, key.c_str());
}

using TestFunc = void(*)(FuzzedDataProvider &);
static TestFunc g_testFuncs[] = {
    TlvStructFuzzTest001,
    TlvEncodeGetLenDeinitTest001,
    TlvMessageFuzzTest001,
    TlvBufferFuzzTest001,
    TlvStringFuzzTest001,
    TlvFixLengthTypesFuzzTest001,
    CredTlvStructFuzzTest001,
    CredTlvBufferFuzzTest001,
    CredTlvStringFuzzTest001,
    OperationRecordTest001,
    OperationDataManagerTest001,
    SetAnonymousFieldTest001,
    MkAgreeTaskProtocolTypeTest001,
    MkAgreeTaskPakeAttemptTest001,
    PseudonymNormalQueryTest001,
    PseudonymDeleteTest001,
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
