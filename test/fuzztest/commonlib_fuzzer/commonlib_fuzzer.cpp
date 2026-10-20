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

#include "commonlib_fuzzer.h"

#include "clib_error.h"
#include "hc_string.h"
#include "json_utils.h"
#include "string_util.h"
#include "hc_tlv_parser.h"
#include "cred_tlv_parser.h"
#include "group_data_manager.h"
#include "operation_data_manager.h"
#include "mk_agree_task.h"
#include "pseudonym_manager.h"
#include "device_auth.h"
#include "account_module_defines.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstddef>
#include <fuzzer/FuzzedDataProvider.h>
#include "securec.h"
#include "base/security/device_auth/common_lib/impl/src/hc_parcel.c"

namespace OHOS {
static const uint32_t TEST_BUFFER_SIZE = 16;
static const uint32_t TEST_MIN_ANONYMOUS_LEN = 6;
static const uint32_t TEST_LEN_TWO = 2;
static const uint32_t TEST_INVALID_BUFFER_SIZE = 0;
static const uint32_t TEST_LENGTH_ZERO = 0;
static const uint32_t TEST_SRC_DATA = 4;
static const uint32_t MAX_TLV_LENGTH = 32768;
static const uint32_t PARCEL_POS_0 = 0;
static const uint32_t PARCEL_POS_1 = 1;
const uint32_t PARCEL_UINT_MAX = 0xffffffffU;
static const char *TEST_JSON_STR = "{\"name\":\"test_name\", \"age\":18}";
static const char *TEST_JSON_STR_1 =
    "{\"name\":\"test_name\", \"age\":18, \"useBigIntArr\":[\"userId\"], \"userId\":\"12343215234\"}";
static const char *TEST_JSON_STR_ARR = "[{\"name\":\"Tom1\",\"age\":18},{\"name\":\"Tom2\",\"age\":19}]";
static const char *TEST_STR = "test_str";
static const char TEST_CHAR = '0';

/* ===== fuzz supplements: TLV / data_manager / mk_agree / pseudonym ===== */
static const uint32_t FUZZ_TLV_HEAD_MAX_LEN = 48 * 1024;       /* matches MAX_TLV_LENGTH in hc_tlv_parser.c */
static const uint32_t FUZZ_CRED_TLV_HEAD_MAX_LEN = 4800 * 1024; /* matches MAX_CRED_TLV_LENGTH in cred_tlv_parser.c */
static const uint16_t FUZZ_TLV_TAG_ROOT = 0x1000;
static const uint16_t FUZZ_TLV_TAG_M1 = 0x0001;
static const uint16_t FUZZ_TLV_TAG_M2 = 0x0002;
static const uint16_t FUZZ_TLV_TAG_UNKNOWN = 0x9999;
static const uint16_t FUZZ_TLV_TAG_BUF = 0x1234;
static const uint32_t FUZZ_UINT32_VAL_A = 0x11111111;
static const uint32_t FUZZ_UINT32_VAL_B = 0x22222222;
static const uint32_t FUZZ_RECORD_BUF_SIZE = 256;
static const int32_t FUZZ_OS_ACCOUNT_ID = 100;
static const uint32_t FUZZ_OPERATION_TYPE = 2;
/* TLV wire node sizes (tag + length + data); used to compute struct root lengths */
static const uint16_t FUZZ_TLV_UINT32_NODE_LEN =
    sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint32_t);     /* hc TlvUint32 = 8 */
static const uint32_t FUZZ_CRED_TLV_UINT32_NODE_LEN =
    sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint32_t);     /* cred CredTlvUint32 = 10 */
/* TlvBuffer declared length intentionally larger than the parcel data to exercise
   the insufficient-data branch of ParseTlvBuffer */
static const uint32_t FUZZ_TLV_BUFFER_DECLARED_LEN = 10;
/* mk_agree protocol type that is neither TASK_TYPE_ISO nor TASK_TYPE_PAKE,
   used to exercise the default (invalid) branch of CreateMkAgreeTask */
static const int32_t FUZZ_MK_AGREE_INVALID_PROTOCOL_TYPE = 99;

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

static void HcParcelNullPtrTest001()
{
    HcParcel *parcelNull = nullptr;
    ClearParcel(parcelNull);
    ResetParcel(parcelNull, 1, 1);
    HcParcel parcel;
    void *dstNull = nullptr;
    (void)ParcelEraseBlock(&parcel, 1, 1, dstNull);
    (void)ParcelIncrease(parcelNull, 1);
    (void)ParcelIncrease(&parcel, 0);
    ParcelRecycle(parcelNull);
    const void *srcNull = nullptr;
    (void)ParcelWrite(&parcel, srcNull, 1);
    (void)ParcelPopBack(parcelNull, 1);
    (void)ParcelPopBack(&parcel, 0);
    (void)ParcelPopFront(parcelNull, 1);
    (void)ParcelPopFront(&parcel, 0);
    DataRevert(parcelNull, 0);
    (void)ParcelCopy(&parcel, parcelNull);
    (void)ParcelReadParcel(&parcel, parcelNull, 0, HC_TRUE);
}

static void HcParcelNullPtrTest002()
{
    HcParcel *parcelNull = nullptr;
    HcParcel parcel;
    (void)GetParcelIncreaseSize(parcelNull, 1);
    parcel.allocUnit = 0;
    (void)GetParcelIncreaseSize(&parcel, 1);
}

static void HcParcelInValidDataSizeTest001()
{
    HcParcel parcel;
    parcel.beginPos = PARCEL_POS_1;
    parcel.endPos = PARCEL_POS_0;
    (void)GetParcelDataSize(&parcel);
    (void)GetParcelLastChar(&parcel);
    parcel.beginPos = PARCEL_POS_0;
    parcel.endPos = PARCEL_POS_1;
    parcel.allocUnit = 0;
    ParcelRecycle(&parcel);
}

static void HcParcelInValidDataSizeTest002()
{
    HcParcel parcel;
    uint32_t data = 1;
    (void)ParcelEraseBlock(&parcel, 1, 0, &data);
    (void)ParcelWriteRevert(&parcel, &data, 0);
    parcel.length = 1;
    (void)ParcelRealloc(&parcel, 0);
    parcel.data = nullptr;
    (void)ParcelIncrease(&parcel, 1);
}

static void HcParcelReadRevertTest001()
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    HcParcel *parcelNull = nullptr;
    int32_t int32Dst = 0;
    uint32_t uint32Dst = 0;
    int16_t int16Dst = 0;
    uint16_t uint16Dst = 0;
    uint16_t *uint16DstNull = nullptr;
    int64_t int64Dst = 0;
    uint64_t uint64Dst = 0;
    (void)ParcelReadInt32Revert(&parcel, &int32Dst);
    (void)ParcelReadUint32Revert(&parcel, &uint32Dst);
    (void)ParcelReadInt16Revert(&parcel, &int16Dst);
    (void)ParcelReadUint16Revert(&parcel, &uint16Dst);
    (void)ParcelReadUint16Revert(&parcel, uint16DstNull);
    (void)ParcelReadUint16Revert(parcelNull, &uint16Dst);
    (void)ParcelReadUint16Revert(&parcel, &uint16Dst);
    (void)ParcelReadInt64Revert(&parcel, &int64Dst);
    (void)ParcelReadUint64Revert(&parcel, &uint64Dst);
    DeleteParcel(&parcel);
}

static void HcParcelCreateTest001()
{
    HcParcel parcelNullData = CreateParcel(TEST_INVALID_BUFFER_SIZE, PARCEL_DEFAULT_ALLOC_UNIT);
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, PARCEL_DEFAULT_ALLOC_UNIT);
    ParcelWriteUint32(&parcelWithData, TEST_SRC_DATA);
    (void)GetParcelDataSize(nullptr);
    (void)GetParcelDataSize(&parcelWithData);
    (void)GetParcelData(nullptr);
    (void)GetParcelData(&parcelWithData);
    (void)GetParcelLastChar(nullptr);
    (void)GetParcelLastChar(&parcelWithData);
    ClearParcel(&parcelWithData);
    ResetParcel(&parcelWithData, TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    DeleteParcel(nullptr);
    DeleteParcel(&parcelNullData);
    DeleteParcel(&parcelWithData);
}

static void HcParcelReadTest001()
{
    uint32_t num = 0;
    uint32_t uintDataSize = sizeof(uint32_t);
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    ParcelWriteUint32(&parcelWithData, TEST_SRC_DATA);
    (void)ParcelReadWithoutPopData(&parcelWithData, &num, uintDataSize);
    (void)ParcelRead(nullptr, nullptr, uintDataSize);
    (void)ParcelRead(&parcelWithData, &num, uintDataSize);
    parcelWithData.beginPos = PARCEL_UINT_MAX - uintDataSize;
    (void)ParcelRead(&parcelWithData, &num, uintDataSize);
    parcelWithData.beginPos = 0;
    parcelWithData.endPos = 0;
    (void)ParcelRead(&parcelWithData, &num, uintDataSize);
    DeleteParcel(&parcelWithData);
}

static void HcParcelEraseBlockTest001()
{
    uint32_t start = 0;
    uint32_t num = 0;
    uint32_t uintDataSize = sizeof(uint32_t);
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    ParcelWriteUint32(&parcelWithData, TEST_SRC_DATA);
    (void)ParcelEraseBlock(nullptr, start, uintDataSize, &num);
    (void)ParcelEraseBlock(&parcelWithData, PARCEL_UINT_MAX, uintDataSize, &num);
    (void)ParcelEraseBlock(&parcelWithData, PARCEL_UINT_MAX - uintDataSize, uintDataSize, &num);
    (void)ParcelEraseBlock(&parcelWithData, start, uintDataSize, &num);
    DeleteParcel(&parcelWithData);
}

static void HcParcelRevertTest001()
{
    uint32_t num = 0;
    uint32_t uintDataSize = sizeof(uint32_t);
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    ParcelWriteUint32(&parcelWithData, TEST_SRC_DATA);
    (void)ParcelReadRevert(&parcelWithData, &num, TEST_LENGTH_ZERO);
    (void)ParcelReadRevert(&parcelWithData, &num, uintDataSize);
    (void)ParcelWriteRevert(nullptr, &num, uintDataSize);
    DeleteParcel(&parcelWithData);
}

static void HcParcelReadWrite001()
{
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    int32_t srcInt = 0;
    int32_t dstInt = 0;
    (void)ParcelWriteInt32(&parcelWithData, srcInt);
    (void)ParcelReadInt32(&parcelWithData, &dstInt);
    uint32_t srcUint32 = 0;
    uint32_t dstUint32 = 0;
    (void)ParcelWriteUint32(&parcelWithData, srcUint32);
    (void)ParcelReadUint32(&parcelWithData, &dstUint32);
    short srcInt16 = 0;
    short dstInt16 = 0;
    (void)ParcelWriteInt16(&parcelWithData, srcInt16);
    (void)ParcelReadInt16(&parcelWithData, &dstInt16);
    uint16_t srcUint16 = 0;
    uint16_t dstUint16 = 0;
    (void)ParcelWriteUint16(&parcelWithData, srcUint16);
    (void)ParcelReadUint16(&parcelWithData, &dstUint16);
    char srcInt8 = 0;
    char dstInt8 = 0;
    (void)ParcelWriteInt8(&parcelWithData, srcInt8);
    (void)ParcelReadInt8(&parcelWithData, &dstInt8);
    uint8_t srcUint8 = 0;
    uint8_t dstUint8 = 0;
    (void)ParcelWriteUint8(&parcelWithData, srcUint8);
    (void)ParcelReadUint8(&parcelWithData, &dstUint8);
    int64_t srcInt64 = 0;
    int64_t dstInt64 = 0;
    (void)ParcelWriteInt64(&parcelWithData, srcInt64);
    (void)ParcelReadInt64(&parcelWithData, &dstInt64);
    uint64_t srcUint64 = 0;
    uint64_t dstUint64 = 0;
    (void)ParcelWriteUint64(&parcelWithData, srcUint64);
    (void)ParcelReadUint64(&parcelWithData, &dstUint64);
    DeleteParcel(&parcelWithData);
}

static void HcParcelRealloc001()
{
    HcParcel parcelSrc = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    HcParcel parcelDst = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    (void)ParcelWriteInt32(&parcelSrc, TEST_SRC_DATA);
    uint32_t data01 = 0;
    uint64_t data02 = 0;
    uint32_t validLen = sizeof(data01);
    uint32_t invalidLen = sizeof(data02);
    (void)ParcelReadParcel(nullptr, nullptr, validLen, HC_FALSE);
    (void)ParcelReadParcel(&parcelSrc, &parcelDst, invalidLen, HC_FALSE);
    (void)ParcelReadParcel(&parcelSrc, &parcelDst, TEST_LENGTH_ZERO, HC_FALSE);
    (void)ParcelReadParcel(&parcelSrc, &parcelDst, validLen, HC_FALSE);
    DeleteParcel(&parcelSrc);
    DeleteParcel(&parcelDst);
}

static void HcParcelCopy001()
{
    HcParcel parcelSrc = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    HcParcel parcelDst = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    (void)ParcelCopy(nullptr, nullptr);
    (void)ParcelCopy(&parcelSrc, &parcelDst);
    (void)ParcelWriteInt32(&parcelSrc, TEST_SRC_DATA);
    (void)ParcelCopy(&parcelSrc, &parcelDst);
    DeleteParcel(&parcelSrc);
    DeleteParcel(&parcelDst);
}

static void HcParcelReadWriteRevert001()
{
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    int32_t srcInt = 0;
    int32_t dstInt = 0;
    (void)ParcelWriteInt32Revert(&parcelWithData, srcInt);
    (void)ParcelReadInt32Revert(&parcelWithData, &dstInt);
    uint32_t srcUint32 = 0;
    uint32_t dstUint32 = 0;
    (void)ParcelWriteUint32Revert(&parcelWithData, srcUint32);
    (void)ParcelReadUint32Revert(&parcelWithData, &dstUint32);
    short srcInt16 = 0;
    short dstInt16 = 0;
    (void)ParcelWriteInt16Revert(&parcelWithData, srcInt16);
    (void)ParcelReadInt16Revert(&parcelWithData, &dstInt16);
    uint16_t srcUint16 = 0;
    uint16_t dstUint16 = 0;
    (void)ParcelWriteUint16Revert(&parcelWithData, srcUint16);
    (void)ParcelReadUint16Revert(&parcelWithData, &dstUint16);
    char srcInt8 = 0;
    char dstInt8 = 0;
    (void)ParcelWriteInt8Revert(&parcelWithData, srcInt8);
    (void)ParcelReadInt8Revert(&parcelWithData, &dstInt8);
    uint8_t srcUint8 = 0;
    uint8_t dstUint8 = 0;
    (void)ParcelWriteUint8Revert(&parcelWithData, srcUint8);
    (void)ParcelReadUint8Revert(&parcelWithData, &dstUint8);
    int64_t srcInt64 = 0;
    int64_t dstInt64 = 0;
    (void)ParcelWriteInt64Revert(&parcelWithData, srcInt64);
    (void)ParcelReadInt64Revert(&parcelWithData, &dstInt64);
    uint64_t srcUint64 = 0;
    uint64_t dstUint64 = 0;
    (void)ParcelWriteUint64Revert(&parcelWithData, srcUint64);
    (void)ParcelReadUint64Revert(&parcelWithData, &dstUint64);
    DeleteParcel(&parcelWithData);
}

static void HcParcelPop001()
{
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    (void)ParcelWriteInt32(&parcelWithData, TEST_SRC_DATA);
    (void)ParcelPopBack(&parcelWithData, sizeof(uint32_t));
    (void)ParcelPopBack(&parcelWithData, sizeof(uint32_t));
    (void)ParcelWriteInt32(&parcelWithData, TEST_SRC_DATA);
    (void)ParcelPopFront(&parcelWithData, sizeof(uint32_t));
    (void)ParcelPopFront(&parcelWithData, sizeof(uint32_t));
    DeleteParcel(&parcelWithData);
}

static void HcStringTest001()
{
    HcString selfStr = CreateString();
    HcString srcStr = CreateString();
    (void)StringSetPointer(&srcStr, TEST_STR);
    (void)StringAppend(nullptr, srcStr);
    (void)StringAppend(&selfStr, srcStr);
    (void)StringAppendPointer(nullptr, TEST_STR);
    (void)StringAppendPointer(&selfStr, TEST_STR);
    (void)StringAppendChar(nullptr, TEST_CHAR);
    (void)StringAppendChar(&selfStr, TEST_CHAR);
    (void)StringSet(nullptr, srcStr);
    (void)StringSet(&selfStr, srcStr);
    (void)StringSetPointer(nullptr, TEST_STR);
    (void)StringSetPointer(&selfStr, TEST_STR);
    const char *retStr = StringGet(nullptr);
    retStr = StringGet(&selfStr);
    uint32_t retLen = StringLength(nullptr);
    retLen = StringLength(&selfStr);
    DeleteString(&selfStr);
    retLen = StringLength(&selfStr);
    DeleteString(&srcStr);
}

static void HcCreateJsonTest001()
{
    CJson *invalidJson = CreateJsonFromString(nullptr);
    CJson *validJson = CreateJsonFromString(TEST_JSON_STR);
    invalidJson = DuplicateJson(nullptr);
    FreeJson(validJson);
}

static void HcDeleteJsonTest001()
{
    CJson *validJson = CreateJsonFromString(TEST_JSON_STR);
    CJson *jsonItem = DetachItemFromJson(nullptr, "age");
    jsonItem = DetachItemFromJson(validJson, "age");
    DeleteItemFromJson(nullptr, "name");
    DeleteItemFromJson(validJson, "name");
    DeleteAllItemExceptOne(nullptr, "name");
    DeleteAllItemExceptOne(validJson, "name");
    DeleteAllItem(nullptr);
    DeleteAllItem(validJson);
    FreeJson(validJson);
}

static void HcJsonGetTest001()
{
    CJson *validJson = CreateJsonFromString(TEST_JSON_STR);
    char *jsonStr = PackJsonToString(nullptr);
    jsonStr = PackJsonToString(validJson);
    FreeJsonString(jsonStr);
    int32_t itemNum = GetItemNum(nullptr);
    itemNum = GetItemNum(validJson);
    const char *itemKey = GetItemKey(nullptr);
    itemKey = GetItemKey(validJson);
    CJson *jsonObj = GetObjFromJson(nullptr, "name");
    jsonObj = GetObjFromJson(validJson, "name");
    jsonObj = GetItemFromArray(nullptr, 0);
    jsonObj = GetItemFromArray(validJson, 0);
    FreeJson(validJson);
}

static void HcJsonGetTest002()
{
    CJson *validJson = CreateJsonFromString(TEST_JSON_STR);
    const char *strObj = GetStringFromJson(nullptr, "name");
    strObj = GetStringFromJson(validJson, "name");
    char byteData[] = "test_byte";
    (void)GetByteFromJson(nullptr, "name", nullptr, sizeof(byteData));
    (void)GetByteFromJson(validJson, "gender", reinterpret_cast<uint8_t *>(byteData), sizeof(byteData));
    (void)GetByteFromJson(validJson, "name", reinterpret_cast<uint8_t *>(byteData), TEST_LENGTH_ZERO);
    int32_t valueInt32 = 0;
    (void)GetIntFromJson(nullptr, "age", &valueInt32);
    uint32_t valueUint32 = 0;
    (void)GetUnsignedIntFromJson(nullptr, "age", &valueUint32);
    int64_t valueInt64 = 0;
    (void)GetInt64FromJson(nullptr, "age", &valueInt64);
    bool valueBool = false;
    (void)GetBoolFromJson(nullptr, "age", &valueBool);
    CJson *jsonObj = GetObjFromJson(validJson, "name");
    (void)GetStringValue(jsonObj);
    FreeJson(validJson);
}

static void HcJsonGetTest003()
{
    CJson *jsonObj = CreateJson();
    int data = 1;
    uint8_t value = 0;
    (void)AddIntToJson(jsonObj, "name", data);
    (void)GetUint8FromJson(nullptr, "name", &value);
    (void)GetUint8FromJson(jsonObj, nullptr, &value);
    (void)GetUint8FromJson(jsonObj, "name", nullptr);
    (void)GetUint8FromJson(jsonObj, "name", &value);
    DeleteItemFromJson(jsonObj, "name");
    (void)GetUint8FromJson(jsonObj, "name", &value);
    (void)GetBoolFromJson(jsonObj, nullptr, nullptr);
    (void)GetBoolFromJson(jsonObj, "name", nullptr);
    (void)GetUnsignedIntFromJson(jsonObj, nullptr, nullptr);
    (void)GetUnsignedIntFromJson(jsonObj, "name", nullptr);
    (void)GetIntFromJson(jsonObj, nullptr, nullptr);
    (void)GetIntFromJson(jsonObj, "name", nullptr);
    (void)GetByteFromJson(jsonObj, nullptr, nullptr, TEST_BUFFER_SIZE);
    (void)GetByteFromJson(jsonObj, "name", nullptr, TEST_BUFFER_SIZE);
    (void)GetStringFromJson(jsonObj, nullptr);
    FreeJsonString(nullptr);
    CJson *retJson = DetachItemFromJson(jsonObj, nullptr);
    retJson = GetObjFromJson(jsonObj, nullptr);
    DeleteAllItemExceptOne(jsonObj, nullptr);
    DeleteItemFromJson(jsonObj, nullptr);
    retJson = DuplicateJson(nullptr);
    FreeJson(jsonObj);
}

static void HcJsonGetTest004()
{
    CJson *jsonObj = CreateJson();
    uint32_t byteLen = 0;
    char byteData[] = "test_byte";
    (void)AddByteToJson(jsonObj, "name", reinterpret_cast<uint8_t *>(byteData), sizeof(byteData));
    (void)GetByteLenFromJson(nullptr, "name", &byteLen);
    (void)GetByteLenFromJson(jsonObj, nullptr, &byteLen);
    (void)GetByteLenFromJson(jsonObj, "name", nullptr);
    (void)GetByteLenFromJson(jsonObj, "name", &byteLen);
    (void)GetByteLenFromJson(jsonObj, "test", &byteLen);
    FreeJson(jsonObj);
}

static void HcJsonAddTest001()
{
    CJson *jsonArr = CreateJsonFromString(TEST_JSON_STR_ARR);
    CJson *childObj = CreateJsonFromString(TEST_JSON_STR);
    (void)AddObjToJson(nullptr, "name", nullptr);
    (void)AddObjToJson(jsonArr, "gender", childObj);
    (void)AddObjToJson(jsonArr, "name", childObj);
    (void)AddObjToArray(nullptr, childObj);
    (void)AddObjToArray(childObj, jsonArr);
    (void)AddObjToArray(jsonArr, childObj);
    (void)AddStringToArray(nullptr, TEST_STR);
    (void)AddStringToArray(childObj, TEST_STR);
    (void)AddStringToArray(jsonArr, TEST_STR);
    (void)AddStringToJson(nullptr, "name", TEST_STR);
    (void)AddStringToJson(childObj, "gender", TEST_STR);
    (void)AddStringToJson(childObj, "name", TEST_STR);
    FreeJson(jsonArr);
}

static void HcJsonAddTest002()
{
    CJson *childObj = CreateJsonFromString(TEST_JSON_STR);
    char byteData[] = "test_byte";
    (void)AddByteToJson(nullptr, "name", reinterpret_cast<uint8_t *>(byteData), sizeof(byteData));
    (void)AddByteToJson(childObj, "gender", reinterpret_cast<uint8_t *>(byteData), sizeof(byteData));
    (void)AddByteToJson(childObj, "name", reinterpret_cast<uint8_t *>(byteData), sizeof(byteData));
    (void)AddBoolToJson(nullptr, "name", false);
    (void)AddBoolToJson(childObj, "gender", false);
    (void)AddBoolToJson(childObj, "name", false);
    int32_t valueInt32 = 0;
    (void)AddIntToJson(nullptr, "name", valueInt32);
    (void)AddIntToJson(childObj, "gender", valueInt32);
    (void)AddIntToJson(childObj, "name", valueInt32);
    int64_t valueInt64 = 0;
    (void)AddInt64StringToJson(nullptr, "name", valueInt64);
    (void)AddInt64StringToJson(childObj, "name", valueInt64);
    const char *const strArr[] = {"first test data", "second test data"};
    (void)AddStringArrayToJson(nullptr, "name", strArr, sizeof(strArr) / sizeof(strArr[0]));
    (void)AddStringArrayToJson(childObj, "name", strArr, sizeof(strArr) / sizeof(strArr[0]));
}

static void HcJsonAddTest003()
{
    CJson *jsonObj = CreateJson();
    (void)AddBoolToJson(jsonObj, nullptr, false);
    (void)AddByteToJson(jsonObj, nullptr, nullptr, TEST_BUFFER_SIZE);
    (void)AddByteToJson(jsonObj, "name", nullptr, TEST_BUFFER_SIZE);
    (void)AddIntToJson(jsonObj, nullptr, 0);
    (void)AddStringArrayToJson(jsonObj, nullptr, nullptr, TEST_BUFFER_SIZE);
    (void)AddStringArrayToJson(jsonObj, "name", nullptr, TEST_BUFFER_SIZE);
    (void)AddStringToJson(jsonObj, nullptr, nullptr);
    (void)AddStringToJson(jsonObj, "name", nullptr);
    (void)AddStringToArray(jsonObj, nullptr);
    (void)AddObjToArray(jsonObj, nullptr);
    (void)AddObjToJson(jsonObj, nullptr, nullptr);
    (void)AddObjToJson(jsonObj, "name", nullptr);
    FreeJson(jsonObj);
}

static void HcClearJsonTest001()
{
    CJson *jsonObj = CreateJsonFromString(TEST_JSON_STR);
    ClearSensitiveStringInJson(nullptr, "name");
    ClearSensitiveStringInJson(jsonObj, "gender");
    ClearSensitiveStringInJson(jsonObj, "name");
    ClearSensitiveStringInJson(jsonObj, nullptr);
    FreeJson(jsonObj);
}

static void HcClearJsonTest002()
{
    CJson *jsonObj = CreateJsonFromString(TEST_JSON_STR);
    char *jsonStr = PackJsonToString(jsonObj);
    ClearAndFreeJsonString(nullptr);
    ClearAndFreeJsonString(jsonStr);
    FreeJson(jsonObj);
}

static void HcClearJsonTest003()
{
    CJson *jsonObj = CreateJsonFromString(TEST_JSON_STR_1);
    char *jsonStr = PackJsonToString(jsonObj);
    ClearAndFreeJsonString(nullptr);
    ClearAndFreeJsonString(jsonStr);
    FreeJson(jsonObj);
}

static void HcStringUtilTest001()
{
    const uint8_t byteData[] = "1234";
    const char hexData[] = "ABCD";
    const char invalidData[] = "GHJK";
    const char inValidLenData[] = "ABC";
    uint32_t byteSize = sizeof(byteData);
    char hexStr[TEST_BUFFER_SIZE] = { 0 };
    (void)ByteToHexString(nullptr, byteSize, hexStr, TEST_BUFFER_SIZE);
    (void)ByteToHexString(byteData, byteSize, nullptr, TEST_BUFFER_SIZE);
    (void)ByteToHexString(byteData, byteSize, hexStr, TEST_LENGTH_ZERO);
    (void)ByteToHexString(byteData, byteSize, hexStr, TEST_BUFFER_SIZE);
    uint8_t byteStr[TEST_BUFFER_SIZE] = { 0 };
    (void)HexStringToByte(nullptr, byteStr, TEST_BUFFER_SIZE);
    (void)HexStringToByte(hexData, nullptr, TEST_BUFFER_SIZE);
    (void)HexStringToByte(inValidLenData, byteStr, TEST_BUFFER_SIZE);
    (void)HexStringToByte(hexData, byteStr, TEST_LENGTH_ZERO);
    (void)HexStringToByte(invalidData, byteStr, TEST_BUFFER_SIZE);
    (void)HexStringToByte(hexData, byteStr, TEST_BUFFER_SIZE);
    const char intStr[] = "10";
    int64_t int64Res = StringToInt64(intStr);
    int64Res = StringToInt64(nullptr);
}

static void HcStringUtilTest002()
{
    const char oriData[] = "abcd";
    const char inValidData[] = "";
    char *desData = nullptr;
    (void)ToUpperCase(nullptr, &desData);
    (void)ToUpperCase(oriData, nullptr);
    (void)DeepCopyString(nullptr, &desData);
    (void)DeepCopyString(inValidData, &desData);
}

static void HcStringUtilTest003()
{
    const uint8_t byteData[] = "1234";
    uint32_t byteSize = sizeof(byteData);
    const char tag[] = "TEST";
    PrintBuffer(byteData, byteSize, tag);
}

static void HcStringUtilTest004()
{
    const char oriData[] = "abcd";
    char anonymousData[TEST_MIN_ANONYMOUS_LEN + TEST_LEN_TWO] = { 0 };
    (void)GetAnonymousString(oriData, nullptr, TEST_MIN_ANONYMOUS_LEN + 1, true);
    (void)GetAnonymousString(oriData, anonymousData, TEST_MIN_ANONYMOUS_LEN - 1, true);
    (void)GetAnonymousString(oriData, anonymousData, TEST_MIN_ANONYMOUS_LEN + 1, true);
    (void)GetAnonymousString(oriData, anonymousData, TEST_MIN_ANONYMOUS_LEN + TEST_LEN_TWO, true);
}

static void ParseTlvHeadTest001()
{
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    ParcelWriteUint32(&parcelWithData, TEST_SRC_DATA);
    TlvBase tlvBase = {
        .tag = 0,
        .length = 0,
        .checkTag = 1,
    };
    (void)ParseTlvHead(&tlvBase, nullptr);
    (void)ParseTlvHead(&tlvBase, &parcelWithData);
    parcelWithData.beginPos = PARCEL_UINT_MAX;
    tlvBase.checkTag = tlvBase.length;
    (void)ParseTlvHead(&tlvBase, &parcelWithData);
    parcelWithData.beginPos = 0;
    tlvBase.length = MAX_TLV_LENGTH + 1;
    (void)ParseTlvHead(&tlvBase, &parcelWithData);
    tlvBase.length = 0;
    (void)ParseTlvHead(&tlvBase, &parcelWithData);
    DeleteParcel(&parcelWithData);
}


static void ParseTlvNodeTest001()
{
    HcParcel parcelWithData = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    ParcelWriteUint32(&parcelWithData, TEST_SRC_DATA);
    TlvBase tlvBase = {
        .tag = 0,
        .length = GetParcelDataSize(&parcelWithData) + 1,
        .checkTag = 1,
    };
    (void)ParseTlvNode(nullptr, &parcelWithData, true);
    (void)ParseTlvNode(&tlvBase, &parcelWithData, true);
    DeleteParcel(&parcelWithData);
}

/* ===== gap 1: hc_tlv_parser null-guard branches (added by 1222adae) ===== */
static void TlvHeadNullGuardTest001()
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    TlvBase tlvBase = { 0 };
    tlvBase.checkTag = 1;
    (void)ParseTlvHead(nullptr, nullptr);
    (void)ParseTlvHead(nullptr, &parcel);
    (void)ParseTlvHead(&tlvBase, nullptr);
    DeleteParcel(&parcel);
}

static void TlvHeadLenOverflowTest001()
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_BUF);
    ParcelWriteUint16(&parcel, static_cast<uint16_t>(FUZZ_TLV_HEAD_MAX_LEN + 1));
    TlvBase tlvBase = { 0 };
    tlvBase.checkTag = FUZZ_TLV_TAG_BUF;
    (void)ParseTlvHead(&tlvBase, &parcel);
    DeleteParcel(&parcel);
}

static void TlvNodeGuardTest001()
{
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    TlvBase tlvBase = { 0 };
    (void)GetlenTlvNode(nullptr);
    (void)GetlenTlvNode(&tlvBase);
    (void)DeinitTlvNode(nullptr);
    (void)EncodeTlvNode(nullptr, &parcel, true);
    (void)EncodeTlvNode(&tlvBase, nullptr, true);
    (void)ParseTlvStruct(nullptr, &parcel, true);
    (void)ParseTlvStruct(nullptr, nullptr, true);
    DeleteParcel(&parcel);
}

static void TlvStructRoundtripTest001()
{
    FuzzTlvStruct tlvStruct;
    InitFuzzTlvStruct(&tlvStruct, FUZZ_TLV_TAG_ROOT);
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE * 4, TEST_BUFFER_SIZE);
    ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_ROOT);
    ParcelWriteUint16(&parcel, static_cast<uint16_t>(2 * FUZZ_TLV_UINT32_NODE_LEN));
    ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_M1);
    ParcelWriteUint16(&parcel, sizeof(uint32_t));
    ParcelWriteUint32(&parcel, FUZZ_UINT32_VAL_A);
    ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_M2);
    ParcelWriteUint16(&parcel, sizeof(uint32_t));
    ParcelWriteUint32(&parcel, FUZZ_UINT32_VAL_B);
    (void)ParseTlvNode((TlvBase *)&tlvStruct, &parcel, HC_TRUE);
    DeleteParcel(&parcel);
    tlvStruct.base.deinit((TlvBase *)&tlvStruct);
}

static void TlvStructStrictFailTest001()
{
    FuzzTlvStruct tlvStruct;
    InitFuzzTlvStruct(&tlvStruct, FUZZ_TLV_TAG_ROOT);
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE * 2, TEST_BUFFER_SIZE);
    ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_ROOT);
    ParcelWriteUint16(&parcel, FUZZ_TLV_UINT32_NODE_LEN);
    ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_M1);
    ParcelWriteUint16(&parcel, sizeof(uint32_t));
    ParcelWriteUint32(&parcel, FUZZ_UINT32_VAL_A);
    (void)ParseTlvNode((TlvBase *)&tlvStruct, &parcel, HC_TRUE);
    DeleteParcel(&parcel);
    tlvStruct.base.deinit((TlvBase *)&tlvStruct);
}

static void TlvStructUnknownTagTest001()
{
    FuzzTlvStruct tlvStruct;
    InitFuzzTlvStruct(&tlvStruct, FUZZ_TLV_TAG_ROOT);
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE * 4, TEST_BUFFER_SIZE);
    ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_ROOT);
    ParcelWriteUint16(&parcel, static_cast<uint16_t>(3 * FUZZ_TLV_UINT32_NODE_LEN));
    ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_M1);
    ParcelWriteUint16(&parcel, sizeof(uint32_t));
    ParcelWriteUint32(&parcel, FUZZ_UINT32_VAL_A);
    ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_UNKNOWN);
    ParcelWriteUint16(&parcel, sizeof(uint32_t));
    ParcelWriteUint32(&parcel, FUZZ_UINT32_VAL_B);
    ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_M2);
    ParcelWriteUint16(&parcel, sizeof(uint32_t));
    ParcelWriteUint32(&parcel, FUZZ_UINT32_VAL_A);
    (void)ParseTlvNode((TlvBase *)&tlvStruct, &parcel, HC_FALSE);
    DeleteParcel(&parcel);
    tlvStruct.base.deinit((TlvBase *)&tlvStruct);
}

static void TlvStructEncodeGetLenDeinitTest001()
{
    (void)EncodeTlvStruct(nullptr, nullptr);
    (void)GetLenTlvStruct(nullptr);
    DeinitTlvStruct(nullptr);
    FuzzTlvStruct tlvStruct;
    InitFuzzTlvStruct(&tlvStruct, FUZZ_TLV_TAG_ROOT);
    tlvStruct.member1.data = FUZZ_UINT32_VAL_A;
    tlvStruct.member2.data = FUZZ_UINT32_VAL_B;
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE * 4, TEST_BUFFER_SIZE);
    (void)EncodeTlvStruct((TlvBase *)&tlvStruct, &parcel);
    (void)GetLenTlvStruct((TlvBase *)&tlvStruct);
    DeleteParcel(&parcel);
    DeinitTlvStruct((TlvBase *)&tlvStruct);
}

static void TlvMessageEncodeDecodeTest001()
{
    (void)EncodeTlvMessage(nullptr, nullptr);
    (void)DecodeTlvMessage(nullptr, nullptr, HC_FALSE);
    TlvUint32 tlvUint32;
    InitTlvUint32(&tlvUint32, FUZZ_TLV_TAG_BUF);
    tlvUint32.data = FUZZ_UINT32_VAL_A;
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE * 2, TEST_BUFFER_SIZE);
    (void)EncodeTlvMessage((TlvBase *)&tlvUint32, &parcel);
    TlvUint32 tlvDst;
    InitTlvUint32(&tlvDst, FUZZ_TLV_TAG_BUF);
    (void)DecodeTlvMessage((TlvBase *)&tlvDst, &parcel, HC_FALSE);
    DeleteParcel(&parcel);
    tlvUint32.base.deinit((TlvBase *)&tlvUint32);
    tlvDst.base.deinit((TlvBase *)&tlvDst);
}

static void TlvMessageExtraDataTest001()
{
    TlvUint32 tlvUint32;
    InitTlvUint32(&tlvUint32, FUZZ_TLV_TAG_BUF);
    tlvUint32.data = FUZZ_UINT32_VAL_A;
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE * 2, TEST_BUFFER_SIZE);
    (void)EncodeTlvMessage((TlvBase *)&tlvUint32, &parcel);
    uint8_t extra[2] = { 0 };
    ParcelWrite(&parcel, extra, sizeof(extra));
    TlvUint32 tlvDst;
    InitTlvUint32(&tlvDst, FUZZ_TLV_TAG_BUF);
    (void)DecodeTlvMessage((TlvBase *)&tlvDst, &parcel, HC_FALSE);
    DeleteParcel(&parcel);
    tlvUint32.base.deinit((TlvBase *)&tlvUint32);
    tlvDst.base.deinit((TlvBase *)&tlvDst);
}

static void TlvBufferTest001()
{
    InitTlvBuffer(nullptr, FUZZ_TLV_TAG_BUF);
    TlvBuffer tlvBuf;
    InitTlvBuffer(&tlvBuf, FUZZ_TLV_TAG_BUF);
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_BUF);
    ParcelWriteUint16(&parcel, static_cast<uint16_t>(FUZZ_TLV_BUFFER_DECLARED_LEN));
    uint8_t data[5] = { 0 };
    ParcelWrite(&parcel, data, sizeof(data));
    TlvBase *base = (TlvBase *)&tlvBuf;
    base->length = FUZZ_TLV_BUFFER_DECLARED_LEN;
    (void)ParseTlvBuffer(base, &parcel, HC_FALSE);
    (void)ParseTlvBuffer(nullptr, &parcel, HC_FALSE);
    (void)EncodeTlvBuffer(base, nullptr);
    DeleteParcel(&parcel);
    tlvBuf.base.deinit((TlvBase *)&tlvBuf);
}

static void TlvBufferEncodeTest001()
{
    TlvBuffer tlvBuf;
    InitTlvBuffer(&tlvBuf, FUZZ_TLV_TAG_BUF);
    uint8_t data[4] = { 1, 2, 3, 4 };
    ParcelWrite(&tlvBuf.data, data, sizeof(data));
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    (void)EncodeTlvBuffer((TlvBase *)&tlvBuf, &parcel);
    DeleteParcel(&parcel);
    tlvBuf.base.deinit((TlvBase *)&tlvBuf);
    TlvBuffer emptyBuf;
    InitTlvBuffer(&emptyBuf, FUZZ_TLV_TAG_BUF);
    HcParcel parcel2 = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    (void)EncodeTlvBuffer((TlvBase *)&emptyBuf, &parcel2);
    DeleteParcel(&parcel2);
    emptyBuf.base.deinit((TlvBase *)&emptyBuf);
}

static void TlvStringTest001()
{
    InitTlvString(nullptr, FUZZ_TLV_TAG_BUF);
    TlvString tlvStr;
    InitTlvString(&tlvStr, FUZZ_TLV_TAG_BUF);
    StringSetPointer(&tlvStr.data, "test1234");
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    (void)EncodeTlvString((TlvBase *)&tlvStr, &parcel);
    (void)EncodeTlvString(nullptr, &parcel);
    DeleteParcel(&parcel);
    (void)ParseTlvString(nullptr, nullptr, HC_FALSE);
    (void)GetlenTlvString(nullptr);
    (void)DeinitTlvString(nullptr);
    tlvStr.base.deinit((TlvBase *)&tlvStr);
}

static void TlvFixLengthTypesTest001()
{
    TlvUint8 u8;
    InitTlvUint8(&u8, FUZZ_TLV_TAG_BUF);
    TlvUint16 u16;
    InitTlvUint16(&u16, FUZZ_TLV_TAG_BUF);
    TlvUint32 u32;
    InitTlvUint32(&u32, FUZZ_TLV_TAG_BUF);
    u32.data = FUZZ_UINT32_VAL_A;
    TlvUint64 u64;
    InitTlvUint64(&u64, FUZZ_TLV_TAG_BUF);
    TlvInt8 i8;
    InitTlvInt8(&i8, FUZZ_TLV_TAG_BUF);
    TlvInt16 i16;
    InitTlvInt16(&i16, FUZZ_TLV_TAG_BUF);
    TlvInt32 i32;
    InitTlvInt32(&i32, FUZZ_TLV_TAG_BUF);
    TlvInt64 i64;
    InitTlvInt64(&i64, FUZZ_TLV_TAG_BUF);
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE * 4, TEST_BUFFER_SIZE);
    (void)EncodeTlvMessage((TlvBase *)&u32, &parcel);
    TlvUint32 u32Dst;
    InitTlvUint32(&u32Dst, FUZZ_TLV_TAG_BUF);
    (void)DecodeTlvMessage((TlvBase *)&u32Dst, &parcel, HC_FALSE);
    DeleteParcel(&parcel);
    u8.base.deinit((TlvBase *)&u8);
    u16.base.deinit((TlvBase *)&u16);
    u32.base.deinit((TlvBase *)&u32);
    u64.base.deinit((TlvBase *)&u64);
    i8.base.deinit((TlvBase *)&i8);
    i16.base.deinit((TlvBase *)&i16);
    i32.base.deinit((TlvBase *)&i32);
    i64.base.deinit((TlvBase *)&i64);
    u32Dst.base.deinit((TlvBase *)&u32Dst);
}

static void TlvGetTagTest001()
{
    (void)GetTag(FUZZ_TLV_TAG_BUF, 0xFFFF);
    (void)GetTag(0xFFFF, FUZZ_TLV_TAG_BUF);
}

/* ===== gap 2a: cred_tlv_parser (only guarded funcs accept null) ===== */
static void CredTlvNullGuardTest001()
{
    (void)DeinitCredTlvNode(nullptr);
    (void)EncodeCredTlvMessage(nullptr, nullptr);
    (void)DecodeCredTlvMessage(nullptr, nullptr, HC_FALSE);
    (void)GetCredTag(FUZZ_TLV_TAG_BUF, 0xFFFF);
    (void)GetCredTag(0xFFFF, FUZZ_TLV_TAG_BUF);
}

static void CredTlvHeadLenOverflowTest001()
{
    CredTlvUint32 tlvUint32;
    InitCredTlvUint32(&tlvUint32, FUZZ_TLV_TAG_BUF);
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE * 2, TEST_BUFFER_SIZE);
    ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_BUF);
    ParcelWriteUint32(&parcel, FUZZ_CRED_TLV_HEAD_MAX_LEN + 1);
    (void)ParseCredTlvHead((CredTlvBase *)&tlvUint32, &parcel);
    DeleteParcel(&parcel);
    tlvUint32.base.deinit((CredTlvBase *)&tlvUint32);
}

static void CredTlvFixTypeRoundtripTest001()
{
    CredTlvUint32 tlvUint32;
    InitCredTlvUint32(&tlvUint32, FUZZ_TLV_TAG_BUF);
    tlvUint32.data = FUZZ_UINT32_VAL_A;
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE * 2, TEST_BUFFER_SIZE);
    (void)EncodeCredTlvMessage((CredTlvBase *)&tlvUint32, &parcel);
    CredTlvUint32 tlvDst;
    InitCredTlvUint32(&tlvDst, FUZZ_TLV_TAG_BUF);
    (void)DecodeCredTlvMessage((CredTlvBase *)&tlvDst, &parcel, HC_FALSE);
    DeleteParcel(&parcel);
    tlvUint32.base.deinit((CredTlvBase *)&tlvUint32);
    tlvDst.base.deinit((CredTlvBase *)&tlvDst);
}

static void CredTlvStructRoundtripTest001()
{
    FuzzCredTlvStruct tlvStruct;
    InitFuzzCredTlvStruct(&tlvStruct, FUZZ_TLV_TAG_ROOT);
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE * 4, TEST_BUFFER_SIZE);
    ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_ROOT);
    ParcelWriteUint32(&parcel, 2 * FUZZ_CRED_TLV_UINT32_NODE_LEN);
    ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_M1);
    ParcelWriteUint32(&parcel, sizeof(uint32_t));
    ParcelWriteUint32(&parcel, FUZZ_UINT32_VAL_A);
    ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_M2);
    ParcelWriteUint32(&parcel, sizeof(uint32_t));
    ParcelWriteUint32(&parcel, FUZZ_UINT32_VAL_B);
    (void)ParseCredTlvNode((CredTlvBase *)&tlvStruct, &parcel, HC_TRUE);
    DeleteParcel(&parcel);
    tlvStruct.base.deinit((CredTlvBase *)&tlvStruct);
}

static void CredTlvStructUnknownTagTest001()
{
    FuzzCredTlvStruct tlvStruct;
    InitFuzzCredTlvStruct(&tlvStruct, FUZZ_TLV_TAG_ROOT);
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE * 4, TEST_BUFFER_SIZE);
    ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_ROOT);
    ParcelWriteUint32(&parcel, 3 * FUZZ_CRED_TLV_UINT32_NODE_LEN);
    ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_M1);
    ParcelWriteUint32(&parcel, sizeof(uint32_t));
    ParcelWriteUint32(&parcel, FUZZ_UINT32_VAL_A);
    ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_UNKNOWN);
    ParcelWriteUint32(&parcel, sizeof(uint32_t));
    ParcelWriteUint32(&parcel, FUZZ_UINT32_VAL_B);
    ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_M2);
    ParcelWriteUint32(&parcel, sizeof(uint32_t));
    ParcelWriteUint32(&parcel, FUZZ_UINT32_VAL_A);
    (void)ParseCredTlvNode((CredTlvBase *)&tlvStruct, &parcel, HC_FALSE);
    DeleteParcel(&parcel);
    tlvStruct.base.deinit((CredTlvBase *)&tlvStruct);
}

static void CredTlvStructStrictFailTest001()
{
    FuzzCredTlvStruct tlvStruct;
    InitFuzzCredTlvStruct(&tlvStruct, FUZZ_TLV_TAG_ROOT);
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE * 2, TEST_BUFFER_SIZE);
    ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_ROOT);
    ParcelWriteUint32(&parcel, FUZZ_CRED_TLV_UINT32_NODE_LEN);
    ParcelWriteUint16(&parcel, FUZZ_TLV_TAG_M1);
    ParcelWriteUint32(&parcel, sizeof(uint32_t));
    ParcelWriteUint32(&parcel, FUZZ_UINT32_VAL_A);
    (void)ParseCredTlvNode((CredTlvBase *)&tlvStruct, &parcel, HC_TRUE);
    DeleteParcel(&parcel);
    tlvStruct.base.deinit((CredTlvBase *)&tlvStruct);
}

static void CredTlvBufferTest001()
{
    CredTlvBuffer tlvBuf;
    InitCredTlvBuffer(&tlvBuf, FUZZ_TLV_TAG_BUF);
    uint8_t data[4] = { 1, 2, 3, 4 };
    ParcelWrite(&tlvBuf.data, data, sizeof(data));
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    (void)EncodeCredTlvBuffer((CredTlvBase *)&tlvBuf, &parcel);
    DeleteParcel(&parcel);
    tlvBuf.base.deinit((CredTlvBase *)&tlvBuf);
    CredTlvBuffer emptyBuf;
    InitCredTlvBuffer(&emptyBuf, FUZZ_TLV_TAG_BUF);
    HcParcel parcel2 = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    (void)EncodeCredTlvBuffer((CredTlvBase *)&emptyBuf, &parcel2);
    DeleteParcel(&parcel2);
    emptyBuf.base.deinit((CredTlvBase *)&emptyBuf);
}

static void CredTlvStringTest001()
{
    CredTlvString tlvStr;
    InitCredTlvString(&tlvStr, FUZZ_TLV_TAG_BUF);
    StringSetPointer(&tlvStr.data, "test1234");
    HcParcel parcel = CreateParcel(TEST_BUFFER_SIZE, TEST_BUFFER_SIZE);
    (void)EncodeCredTlvString((CredTlvBase *)&tlvStr, &parcel);
    DeleteParcel(&parcel);
    tlvStr.base.deinit((CredTlvBase *)&tlvStr);
}

/* ===== gap 2b: group_data_manager / operation_data_manager ===== */
static void GroupEntryTest001()
{
    (void)GenerateGroupEntryFromEntry(nullptr, nullptr);
    (void)DeepCopyGroupEntry(nullptr);
    TrustedGroupEntry *entry = CreateGroupEntry();
    if (entry == nullptr) {
        return;
    }
    TrustedGroupEntry *copy = DeepCopyGroupEntry(entry);
    if (copy != nullptr) {
        DestroyGroupEntry(copy);
    }
    DestroyGroupEntry(entry);
    QueryGroupParams params = InitQueryGroupParams();
    (void)params.groupType;
}

static void DeviceEntryTest001()
{
    (void)DeepCopyDeviceEntry(nullptr);
    TrustedDeviceEntry *entry = CreateDeviceEntry();
    if (entry == nullptr) {
        return;
    }
    TrustedDeviceEntry *copy = DeepCopyDeviceEntry(entry);
    if (copy != nullptr) {
        DestroyDeviceEntry(copy);
    }
    DestroyDeviceEntry(entry);
    QueryDeviceParams params = InitQueryDeviceParams();
    (void)params.udid;
}

static void OperationRecordTest001()
{
    (void)DeepCopyOperationRecord(nullptr);
    OperationRecord *rec = CreateOperationRecord();
    if (rec == nullptr) {
        return;
    }
    CopyHcStringForcibly(&rec->caller, "fuzz_caller");
    CopyHcStringForcibly(&rec->function, "fuzz_func");
    CopyHcStringForcibly(&rec->operationInfo, "fuzz_info");
    rec->operationType = FUZZ_OPERATION_TYPE;
    OperationRecord *copy = DeepCopyOperationRecord(rec);
    if (copy != nullptr) {
        DestroyOperationRecord(copy);
    }
    DestroyOperationRecord(rec);
}

static void OperationDataManagerTest001()
{
    (void)InitOperationDataManager();
    OperationRecord *rec = CreateOperationRecord();
    if (rec == nullptr) {
        return;
    }
    CopyHcStringForcibly(&rec->caller, "fuzz_caller");
    CopyHcStringForcibly(&rec->function, "fuzz_func");
    CopyHcStringForcibly(&rec->operationInfo, "fuzz_info");
    rec->operationType = FUZZ_OPERATION_TYPE;
    (void)RecordOperationData(FUZZ_OS_ACCOUNT_ID, rec);
    char record[FUZZ_RECORD_BUF_SIZE] = { 0 };
    (void)GetOperationDataRecently(FUZZ_OS_ACCOUNT_ID, OPERATION_ANY, record, sizeof(record), 1);
    DestroyOperationRecord(rec);
}

static void SetAnonymousFieldTest001()
{
    CJson *operationInfo = CreateJson();
    if (operationInfo == nullptr) {
        return;
    }
    SetAnonymousField("abcdef1234567890", "udid", operationInfo);
    SetAnonymousField(nullptr, "udid", operationInfo);
    SetAnonymousField("abcdef", nullptr, operationInfo);
    FreeJson(operationInfo);
}

/* ===== gap 3a: mk_agree ===== */
static void MkAgreeTaskNullTest001()
{
    MkAgreeTaskBase *task = nullptr;
    (void)CreateMkAgreeTask(TASK_TYPE_PAKE, nullptr, &task);
    (void)CreateMkAgreeTask(TASK_TYPE_PAKE, nullptr, nullptr);
    CJson *in = CreateJson();
    if (in != nullptr) {
        (void)CreateMkAgreeTask(TASK_TYPE_PAKE, in, nullptr);
        FreeJson(in);
    }
}

static void MkAgreeTaskProtocolTypeTest001()
{
    CJson *in = CreateJson();
    if (in == nullptr) {
        return;
    }
    (void)AddBoolToJson(in, FIELD_IS_CLIENT, true);
    MkAgreeTaskBase *task = nullptr;
    (void)CreateMkAgreeTask(TASK_TYPE_ISO, in, &task);
    (void)CreateMkAgreeTask(-1, in, &task);
    (void)CreateMkAgreeTask(FUZZ_MK_AGREE_INVALID_PROTOCOL_TYPE, in, &task);
    CJson *empty = CreateJson();
    (void)CreateMkAgreeTask(TASK_TYPE_PAKE, empty, &task);
    FreeJson(empty);
    FreeJson(in);
}

static void MkAgreeTaskPakeAttemptTest001()
{
    CJson *in = CreateJson();
    if (in == nullptr) {
        return;
    }
    (void)AddBoolToJson(in, FIELD_IS_CLIENT, true);
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

/* ===== gap 3b: privacy_enhancement / pseudonym ===== */
static void PseudonymNullParamTest001()
{
    PseudonymManager *inst = GetPseudonymInstance();
    if (inst == nullptr) {
        return;
    }
    char *out = nullptr;
    (void)inst->getRealInfo(FUZZ_OS_ACCOUNT_ID, nullptr, &out);
    (void)inst->getRealInfo(FUZZ_OS_ACCOUNT_ID, "pid", nullptr);
    (void)inst->getPseudonymId(FUZZ_OS_ACCOUNT_ID, nullptr, &out);
    (void)inst->getPseudonymId(FUZZ_OS_ACCOUNT_ID, "key", nullptr);
    (void)inst->savePseudonymId(FUZZ_OS_ACCOUNT_ID, nullptr, "info", "dev", "key");
    (void)inst->deleteAllPseudonymId(FUZZ_OS_ACCOUNT_ID, nullptr);
    (void)inst->deletePseudonymId(FUZZ_OS_ACCOUNT_ID, nullptr);
    (void)inst->isNeedRefreshPseudonymId(FUZZ_OS_ACCOUNT_ID, nullptr);
}

static void PseudonymNormalQueryTest001()
{
    PseudonymManager *inst = GetPseudonymInstance();
    if (inst == nullptr) {
        return;
    }
    char *realInfo = nullptr;
    (void)inst->getRealInfo(FUZZ_OS_ACCOUNT_ID, "fuzz_pid", &realInfo);
    if (realInfo != nullptr) {
        HcFree(realInfo);
        realInfo = nullptr;
    }
    char *pseudonymId = nullptr;
    (void)inst->getPseudonymId(FUZZ_OS_ACCOUNT_ID, "fuzz_key", &pseudonymId);
    if (pseudonymId != nullptr) {
        HcFree(pseudonymId);
        pseudonymId = nullptr;
    }
    (void)inst->isNeedRefreshPseudonymId(FUZZ_OS_ACCOUNT_ID, "fuzz_key");
}

static void PseudonymDeleteTest001()
{
    PseudonymManager *inst = GetPseudonymInstance();
    if (inst == nullptr) {
        return;
    }
    (void)inst->deleteAllPseudonymId(FUZZ_OS_ACCOUNT_ID, "fuzz_dev");
    (void)inst->deletePseudonymId(FUZZ_OS_ACCOUNT_ID, "fuzz_key");
}

using TestFunc = void(*)(void);
static TestFunc g_testFuncs[] = {
    HcParcelNullPtrTest001, HcParcelNullPtrTest002,
    HcParcelInValidDataSizeTest001, HcParcelInValidDataSizeTest002,
    HcParcelReadRevertTest001, HcParcelCreateTest001, HcParcelReadTest001,
    HcParcelEraseBlockTest001, HcParcelRevertTest001, HcParcelReadWrite001,
    HcParcelRealloc001, HcParcelCopy001, HcParcelReadWriteRevert001, HcParcelPop001,
    HcStringTest001, HcCreateJsonTest001, HcDeleteJsonTest001,
    HcJsonGetTest001, HcJsonGetTest002, HcJsonGetTest003, HcJsonGetTest004,
    HcJsonAddTest001, HcJsonAddTest002, HcJsonAddTest003,
    HcClearJsonTest001, HcClearJsonTest002, HcClearJsonTest003,
    HcStringUtilTest001, HcStringUtilTest002, HcStringUtilTest003, HcStringUtilTest004,
    ParseTlvHeadTest001, ParseTlvNodeTest001,
    /* gap 1: hc_tlv_parser */
    TlvHeadNullGuardTest001, TlvHeadLenOverflowTest001, TlvNodeGuardTest001,
    TlvStructRoundtripTest001, TlvStructStrictFailTest001, TlvStructUnknownTagTest001,
    TlvStructEncodeGetLenDeinitTest001, TlvMessageEncodeDecodeTest001,
    TlvMessageExtraDataTest001, TlvBufferTest001, TlvBufferEncodeTest001,
    TlvStringTest001, TlvFixLengthTypesTest001, TlvGetTagTest001,
    /* gap 2a: cred_tlv_parser */
    CredTlvNullGuardTest001, CredTlvHeadLenOverflowTest001,
    CredTlvFixTypeRoundtripTest001, CredTlvStructRoundtripTest001,
    CredTlvStructUnknownTagTest001, CredTlvStructStrictFailTest001,
    CredTlvBufferTest001, CredTlvStringTest001,
    /* gap 2b: group/operation data_manager */
    GroupEntryTest001, DeviceEntryTest001, OperationRecordTest001,
    OperationDataManagerTest001, SetAnonymousFieldTest001,
    /* gap 3a: mk_agree */
    MkAgreeTaskNullTest001, MkAgreeTaskProtocolTypeTest001, MkAgreeTaskPakeAttemptTest001,
    /* gap 3b: pseudonym */
    PseudonymNullParamTest001, PseudonymNormalQueryTest001, PseudonymDeleteTest001,
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
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoCallback(data, size);
    return 0;
}

