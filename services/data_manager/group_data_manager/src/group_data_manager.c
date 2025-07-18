/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include "group_data_manager.h"

#include "broadcast_manager.h"
#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "hc_dev_info.h"
#include "hc_file.h"
#include "hc_log.h"
#include "hc_mutex.h"
#include "hc_string_vector.h"
#include "hc_types.h"
#include "key_manager.h"
#include "securec.h"
#include "hidump_adapter.h"
#include "os_account_adapter.h"
#include "pseudonym_manager.h"
#include "security_label_adapter.h"
#include "account_task_manager.h"

typedef struct {
    DECLARE_TLV_STRUCT(10)
    TlvString name;
    TlvString id;
    TlvUint32 type;
    TlvInt32 visibility;
    TlvInt32 expireTime;
    TlvString userId;
    TlvString sharedUserId;
    TlvBuffer managers;
    TlvBuffer friends;
    TlvUint8 upgradeFlag;
} TlvGroupElement;
DECLEAR_INIT_FUNC(TlvGroupElement)
DECLARE_TLV_VECTOR(TlvGroupVec, TlvGroupElement)

typedef struct {
    uint8_t credential;
    uint8_t devType;
    uint8_t source;
    int64_t userId;
    uint64_t lastTm;
} DevAuthFixedLenInfo;
DECLARE_TLV_FIX_LENGTH_TYPE(TlvDevAuthFixedLenInfo, DevAuthFixedLenInfo)
DECLEAR_INIT_FUNC(TlvDevAuthFixedLenInfo)

typedef struct {
    DECLARE_TLV_STRUCT(8)
    TlvString groupId;
    TlvString udid;
    TlvString authId;
    TlvString userId;
    TlvString serviceType;
    TlvBuffer ext;
    TlvDevAuthFixedLenInfo info;
    TlvUint8 upgradeFlag;
} TlvDeviceElement;
DECLEAR_INIT_FUNC(TlvDeviceElement)
DECLARE_TLV_VECTOR(TlvDeviceVec, TlvDeviceElement)

typedef struct {
    DECLARE_TLV_STRUCT(3)
    TlvInt32 version;
    TlvGroupVec groups;
    TlvDeviceVec devices;
} HCDataBaseV1;
DECLEAR_INIT_FUNC(HCDataBaseV1)

DEFINE_TLV_FIX_LENGTH_TYPE(TlvDevAuthFixedLenInfo, NO_REVERT)

BEGIN_TLV_STRUCT_DEFINE(TlvGroupElement, 0x0001)
    TLV_MEMBER(TlvString, name, 0x4001)
    TLV_MEMBER(TlvString, id, 0x4002)
    TLV_MEMBER(TlvUint32, type, 0x4003)
    TLV_MEMBER(TlvInt32, visibility, 0x4004)
    TLV_MEMBER(TlvInt32, expireTime, 0x4005)
    TLV_MEMBER(TlvString, userId, 0x4006)
    TLV_MEMBER(TlvString, sharedUserId, 0x4007)
    TLV_MEMBER(TlvBuffer, managers, 0x4008)
    TLV_MEMBER(TlvBuffer, friends, 0x4009)
    TLV_MEMBER(TlvUint8, upgradeFlag, 0x400A)
END_TLV_STRUCT_DEFINE()
IMPLEMENT_TLV_VECTOR(TlvGroupVec, TlvGroupElement, 1)

BEGIN_TLV_STRUCT_DEFINE(TlvDeviceElement, 0x0002)
    TLV_MEMBER(TlvString, groupId, 0x4101)
    TLV_MEMBER(TlvString, udid, 0x4102)
    TLV_MEMBER(TlvString, authId, 0x4103)
    TLV_MEMBER(TlvString, userId, 0x4107)
    TLV_MEMBER(TlvString, serviceType, 0x4104)
    TLV_MEMBER(TlvBuffer, ext, 0x4105)
    TLV_MEMBER(TlvDevAuthFixedLenInfo, info, 0x4106)
    TLV_MEMBER(TlvUint8, upgradeFlag, 0x4108)
END_TLV_STRUCT_DEFINE()
IMPLEMENT_TLV_VECTOR(TlvDeviceVec, TlvDeviceElement, 1)

BEGIN_TLV_STRUCT_DEFINE(HCDataBaseV1, 0x0001)
    TLV_MEMBER(TlvInt32, version, 0x6001)
    TLV_MEMBER(TlvGroupVec, groups, 0x6002)
    TLV_MEMBER(TlvDeviceVec, devices, 0x6003)
END_TLV_STRUCT_DEFINE()

IMPLEMENT_HC_VECTOR(GroupEntryVec, TrustedGroupEntry*, 1)
IMPLEMENT_HC_VECTOR(DeviceEntryVec, TrustedDeviceEntry*, 1)

typedef struct {
    int32_t osAccountId;
    GroupEntryVec groups;
    DeviceEntryVec devices;
} OsAccountTrustedInfo;

DECLARE_HC_VECTOR(DeviceAuthDb, OsAccountTrustedInfo)
IMPLEMENT_HC_VECTOR(DeviceAuthDb, OsAccountTrustedInfo, 1)

#define MAX_DB_PATH_LEN 256

static HcMutex *g_databaseMutex = NULL;
static DeviceAuthDb g_deviceauthDb;
static const int UPGRADE_OS_ACCOUNT_ID = 100;

static bool EndWithZero(HcParcel *parcel)
{
    const char *p = GetParcelLastChar(parcel);
    if (p == NULL) {
        return false;
    }
    return (*p == '\0');
}

static bool LoadStringVectorFromParcel(StringVector *vec, HcParcel *parcel)
{
    uint32_t strLen = 0;
    do {
        if (!ParcelReadUint32(parcel, &strLen)) {
            return true;
        }
        if ((strLen == 0) || (strLen > MAX_STRING_LEN)) {
            LOGE("strlen invalid.");
            return false;
        }
        HcString str = CreateString();
        ClearParcel(&str.parcel);
        if (!ParcelReadParcel(parcel, &str.parcel, strLen, false) ||
            !EndWithZero(&str.parcel)) {
            DeleteString(&str);
            return false;
        } else {
            if (vec->pushBack(vec, &str) == NULL) {
                DeleteString(&str);
                LOGE("vec pushBack failed.");
                return false;
            }
        }
    } while (1);
}

static bool SaveStringVectorToParcel(const StringVector *vec, HcParcel *parcel)
{
    uint32_t index;
    HcString *str = NULL;
    FOR_EACH_HC_VECTOR(*vec, index, str) {
        uint32_t len = StringLength(str) + sizeof(char);
        if (!ParcelWriteUint32(parcel, len)) {
            LOGE("Parcel write failed.");
            return false;
        }
        if (!ParcelWrite(parcel, GetParcelData(&str->parcel), GetParcelDataSize(&str->parcel))) {
            LOGE("Parcel write failed.");
            return false;
        }
    }
    return true;
}

static bool GetOsAccountInfoPathCe(int32_t osAccountId, char *infoPath, uint32_t pathBufferLen)
{
    const char *beginPath = GetStorageDirPathCe();
    if (beginPath == NULL) {
        LOGE("[DB]: Failed to get the storage path!");
        return false;
    }
    if (sprintf_s(infoPath, pathBufferLen, "%s/%d/deviceauth/hcgroup.dat", beginPath, osAccountId) <= 0) {
        LOGE("[DB]: Failed to generate db file path!");
        return false;
    }
    return true;
}

static bool GetOsAccountInfoPathDe(int32_t osAccountId, char *infoPath, uint32_t pathBufferLen)
{
    const char *beginPath = GetStorageDirPath();
    if (beginPath == NULL) {
        LOGE("[DB]: Failed to get the storage path dir!");
        return false;
    }
    int32_t writeByteNum;
    if (osAccountId == DEFAULT_OS_ACCOUNT) {
        writeByteNum = sprintf_s(infoPath, pathBufferLen, "%s/hcgroup.dat", beginPath);
    } else {
        writeByteNum = sprintf_s(infoPath, pathBufferLen, "%s/hcgroup%d.dat", beginPath, osAccountId);
    }
    if (writeByteNum <= 0) {
        LOGE("[DB]: sprintf_s fail!");
        return false;
    }
    return true;
}

static bool GetOsAccountInfoPath(int32_t osAccountId, char *infoPath, uint32_t pathBufferLen)
{
    if (IsOsAccountSupported())  {
        return GetOsAccountInfoPathCe(osAccountId, infoPath, pathBufferLen);
    } else {
        return GetOsAccountInfoPathDe(osAccountId, infoPath, pathBufferLen);
    }
}

bool GenerateGroupEntryFromEntry(const TrustedGroupEntry *entry, TrustedGroupEntry *returnEntry)
{
    if (HC_VECTOR_SIZE(&entry->managers) <= 0) {
        LOGE("[DB]: The group owner is lost!");
        return false;
    }
    HcString entryOwner = HC_VECTOR_GET(&entry->managers, 0);
    if (!StringSet(&returnEntry->name, entry->name)) {
        LOGE("[DB]: Failed to copy groupName!");
        return false;
    }
    if (!StringSet(&returnEntry->id, entry->id)) {
        LOGE("[DB]: Failed to copy groupId!");
        return false;
    }
    if (!StringSet(&returnEntry->userId, entry->userId)) {
        LOGE("[DB]: Failed to copy userId!");
        return false;
    }
    if (!StringSet(&returnEntry->sharedUserId, entry->sharedUserId)) {
        LOGE("[DB]: Failed to copy sharedUserId!");
        return false;
    }
    returnEntry->type = entry->type;
    returnEntry->visibility = entry->visibility;
    returnEntry->upgradeFlag = entry->upgradeFlag;
    returnEntry->expireTime = entry->expireTime;
    HcString ownerName = CreateString();
    if (!StringSet(&ownerName, entryOwner)) {
        LOGE("[DB]: Failed to copy groupOwner!");
        DeleteString(&ownerName);
        return false;
    }
    if (returnEntry->managers.pushBack(&returnEntry->managers, &ownerName) == NULL) {
        LOGE("[DB]: Failed to push groupOwner to managers!");
        DeleteString(&ownerName);
        return false;
    }
    return true;
}

bool GenerateDeviceEntryFromEntry(const TrustedDeviceEntry *entry, TrustedDeviceEntry *returnEntry)
{
    returnEntry->groupEntry = NULL;
    if (!StringSet(&returnEntry->groupId, entry->groupId)) {
        LOGE("[DB]: Failed to copy udid!");
        return false;
    }
    if (!StringSet(&returnEntry->udid, entry->udid)) {
        LOGE("[DB]: Failed to copy udid!");
        return false;
    }
    if (!StringSet(&returnEntry->authId, entry->authId)) {
        LOGE("[DB]: Failed to copy authId!");
        return false;
    }
    if (!StringSet(&returnEntry->userId, entry->userId)) {
        LOGE("[DB]: Failed to copy userId!");
        return false;
    }
    if (!StringSet(&returnEntry->serviceType, entry->serviceType)) {
        LOGE("[DB]: Failed to copy serviceType!");
        return false;
    }
    returnEntry->credential = entry->credential;
    returnEntry->devType = entry->devType;
    returnEntry->upgradeFlag = entry->upgradeFlag;
    returnEntry->source = entry->source;
    returnEntry->lastTm = entry->lastTm;
    return true;
}

static bool GenerateGroupEntryFromTlv(TlvGroupElement *group, TrustedGroupEntry *entry)
{
    if (!StringSet(&entry->name, group->name.data)) {
        LOGE("[DB]: Failed to load groupName from tlv!");
        return false;
    }
    if (!StringSet(&entry->id, group->id.data)) {
        LOGE("[DB]: Failed to load groupId from tlv!");
        return false;
    }
    if (!StringSet(&entry->userId, group->userId.data)) {
        LOGE("[DB]: Failed to load userId from tlv!");
        return false;
    }
    if (!StringSet(&entry->sharedUserId, group->sharedUserId.data)) {
        LOGE("[DB]: Failed to load sharedUserId from tlv!");
        return false;
    }
    if (!LoadStringVectorFromParcel(&entry->managers, &group->managers.data)) {
        LOGE("[DB]: Failed to load managers from tlv!");
        return false;
    }
    if (!LoadStringVectorFromParcel(&entry->friends, &group->friends.data)) {
        LOGE("[DB]: Failed to load friends from tlv!");
        return false;
    }
    entry->type = group->type.data;
    entry->visibility = group->visibility.data;
    entry->upgradeFlag = group->upgradeFlag.data;
    entry->expireTime = group->expireTime.data;
    return true;
}

static bool GenerateDeviceEntryFromTlv(TlvDeviceElement *device, TrustedDeviceEntry *deviceEntry)
{
    deviceEntry->groupEntry = NULL;
    if (!StringSet(&deviceEntry->groupId, device->groupId.data)) {
        LOGE("[DB]: Failed to load groupId from tlv!");
        return false;
    }
    if (!StringSet(&deviceEntry->udid, device->udid.data)) {
        LOGE("[DB]: Failed to load udid from tlv!");
        return false;
    }
    if (!StringSet(&deviceEntry->authId, device->authId.data)) {
        LOGE("[DB]: Failed to load authId from tlv!");
        return false;
    }
    if (!StringSet(&deviceEntry->userId, device->userId.data)) {
        LOGE("[DB]: Failed to load userId from tlv!");
        return false;
    }
    if (!StringSet(&deviceEntry->serviceType, device->serviceType.data)) {
        LOGE("[DB]: Failed to load serviceType from tlv!");
        return false;
    }
    if (!ParcelCopy(&device->ext.data, &deviceEntry->ext)) {
        LOGE("[DB]: Failed to load external data from tlv!");
        return false;
    }
    deviceEntry->credential = device->info.data.credential;
    deviceEntry->devType = device->info.data.devType;
    deviceEntry->upgradeFlag = device->upgradeFlag.data;
    deviceEntry->source = device->info.data.source;
    deviceEntry->lastTm = device->info.data.lastTm;
    return true;
}

static bool LoadGroups(HCDataBaseV1 *db, GroupEntryVec *vec)
{
    uint32_t index;
    TlvGroupElement *group = NULL;
    FOR_EACH_HC_VECTOR(db->groups.data, index, group) {
        if (group == NULL) {
            continue;
        }
        TrustedGroupEntry *entry = CreateGroupEntry();
        if (entry == NULL) {
            LOGE("[DB]: Failed to allocate entry memory!");
            ClearGroupEntryVec(vec);
            return false;
        }
        if (!GenerateGroupEntryFromTlv(group, entry)) {
            DestroyGroupEntry(entry);
            ClearGroupEntryVec(vec);
            return false;
        }
        if (vec->pushBackT(vec, entry) == NULL) {
            LOGE("[DB]: Failed to push entry to vec!");
            DestroyGroupEntry(entry);
            ClearGroupEntryVec(vec);
            return false;
        }
    }
    return true;
}

static bool LoadDevices(HCDataBaseV1 *db, DeviceEntryVec *vec)
{
    uint32_t index;
    TlvDeviceElement *device = NULL;
    FOR_EACH_HC_VECTOR(db->devices.data, index, device) {
        if (device == NULL) {
            continue;
        }
        TrustedDeviceEntry *entry = CreateDeviceEntry();
        if (entry == NULL) {
            LOGE("[DB]: Failed to allocate entry memory!");
            ClearDeviceEntryVec(vec);
            return false;
        }
        if (!GenerateDeviceEntryFromTlv(device, entry)) {
            DestroyDeviceEntry(entry);
            ClearDeviceEntryVec(vec);
            return false;
        }
        if (vec->pushBackT(vec, entry) == NULL) {
            LOGE("[DB]: Failed to push entry to vec!");
            DestroyDeviceEntry(entry);
            ClearDeviceEntryVec(vec);
            return false;
        }
    }
    return true;
}

static bool ReadInfoFromParcel(HcParcel *parcel, OsAccountTrustedInfo *info)
{
    bool ret = false;
    HCDataBaseV1 dbv1;
    TLV_INIT(HCDataBaseV1, &dbv1)
    if (DecodeTlvMessage((TlvBase *)&dbv1, parcel, false)) {
        if (!LoadGroups(&dbv1, &info->groups)) {
            TLV_DEINIT(dbv1)
            return false;
        }
        if (!LoadDevices(&dbv1, &info->devices)) {
            ClearGroupEntryVec(&info->groups);
            TLV_DEINIT(dbv1)
            return false;
        }
        ret = true;
    } else {
        LOGE("[DB]: Decode Tlv Message Failed!");
    }
    TLV_DEINIT(dbv1)
    return ret;
}

static bool ReadParcelFromFile(const char *filePath, HcParcel *parcel)
{
    FileHandle file;
    int ret = HcFileOpen(filePath, MODE_FILE_READ, &file);
    if (ret != 0) {
        LOGE("[DB]: Failed to open database file!");
        return false;
    }
    SetSecurityLabel(filePath, SECURITY_LABEL_S2);
    int fileSize = HcFileSize(file);
    if (fileSize <= 0) {
        LOGE("[DB]: The database file size is invalid!");
        HcFileClose(file);
        return false;
    }
    char *fileData = (char *)HcMalloc(fileSize, 0);
    if (fileData == NULL) {
        LOGE("[DB]: Failed to allocate fileData memory!");
        HcFileClose(file);
        return false;
    }
    if (HcFileRead(file, fileData, fileSize) != fileSize) {
        LOGE("[DB]: Read file error!");
        HcFileClose(file);
        HcFree(fileData);
        return false;
    }
    HcFileClose(file);
    if (!ParcelWrite(parcel, fileData, fileSize)) {
        HcFree(fileData);
        LOGE("[DB]: parcel write error!");
        return false;
    }
    HcFree(fileData);
    return true;
}

static bool SaveParcelToFile(const char *filePath, HcParcel *parcel)
{
    FileHandle file;
    int ret = HcFileOpen(filePath, MODE_FILE_WRITE, &file);
    if (ret != HC_SUCCESS) {
        LOGE("[DB]: Failed to open database file!");
        return false;
    }
    SetSecurityLabel(filePath, SECURITY_LABEL_S2);
    int fileSize = (int)GetParcelDataSize(parcel);
    const char *fileData = GetParcelData(parcel);
    int writeSize = HcFileWrite(file, fileData, fileSize);
    HcFileClose(file);
    if (writeSize == fileSize) {
        return true;
    } else {
        LOGE("[DB]: write file error!");
        return false;
    }
}

static void LoadOsAccountDb(int32_t osAccountId)
{
    char filePath[MAX_DB_PATH_LEN] = { 0 };
    if (!GetOsAccountInfoPath(osAccountId, filePath, MAX_DB_PATH_LEN)) {
        LOGE("[DB]: Failed to get os account info path!");
        return;
    }
    HcParcel parcel = CreateParcel(0, 0);
    if (!ReadParcelFromFile(filePath, &parcel)) {
        DeleteParcel(&parcel);
        return;
    }
    OsAccountTrustedInfo info;
    info.osAccountId = osAccountId;
    info.groups = CreateGroupEntryVec();
    info.devices = CreateDeviceEntryVec();
    if (!ReadInfoFromParcel(&parcel, &info)) {
        DestroyGroupEntryVec(&info.groups);
        DestroyDeviceEntryVec(&info.devices);
        DeleteParcel(&parcel);
        return;
    }
    DeleteParcel(&parcel);
    if (g_deviceauthDb.pushBackT(&g_deviceauthDb, info) == NULL) {
        LOGE("[DB]: Failed to push osAccountInfo to database!");
        ClearGroupEntryVec(&info.groups);
        ClearDeviceEntryVec(&info.devices);
        return;
    }
    LOGI("[DB]: Load os account db successfully! [Id]: %" LOG_PUB "d", osAccountId);
}

static void TryMoveDeDataToCe(int32_t osAccountId)
{
    char ceFilePath[MAX_DB_PATH_LEN] = { 0 };
    if (!GetOsAccountInfoPathCe(osAccountId, ceFilePath, MAX_DB_PATH_LEN)) {
        LOGE("[DB]: Failed to get ce database file path!");
        return;
    }
    HcParcel parcelCe = CreateParcel(0, 0);
    if (ReadParcelFromFile(ceFilePath, &parcelCe)) {
        LOGI("[DB]: ce data exists, no need to move.");
        DeleteParcel(&parcelCe);
        return;
    }
    DeleteParcel(&parcelCe);
    char deFilePath[MAX_DB_PATH_LEN] = { 0 };
    if (!GetOsAccountInfoPathDe(osAccountId, deFilePath, MAX_DB_PATH_LEN)) {
        LOGE("[DB]: Failed to get de database file path!");
        return;
    }
    HcParcel parcelDe = CreateParcel(0, 0);
    if (!ReadParcelFromFile(deFilePath, &parcelDe)) {
        LOGI("[DB]: no data in de file, no need to move!");
        DeleteParcel(&parcelDe);
        return;
    }
    if (!SaveParcelToFile(ceFilePath, &parcelDe)) {
        LOGE("[DB]: save de parcel to ce file failed!");
        DeleteParcel(&parcelDe);
        return;
    }
    DeleteParcel(&parcelDe);
    parcelCe = CreateParcel(0, 0);
    if (!ReadParcelFromFile(ceFilePath, &parcelCe)) {
        LOGE("[DB]: Failed to read ce file data!");
        DeleteParcel(&parcelCe);
        return;
    }
    DeleteParcel(&parcelCe);
    LOGI("[DB]: move de data to ce successfully, remove de file!");
    HcFileRemove(deFilePath);
}

static void RemoveOsAccountTrustedInfo(int32_t osAccountId)
{
    uint32_t index = 0;
    OsAccountTrustedInfo *info = NULL;
    FOR_EACH_HC_VECTOR(g_deviceauthDb, index, info) {
        if (info->osAccountId == osAccountId) {
            OsAccountTrustedInfo deleteInfo;
            HC_VECTOR_POPELEMENT(&g_deviceauthDb, &deleteInfo, index);
            ClearGroupEntryVec(&deleteInfo.groups);
            ClearDeviceEntryVec(&deleteInfo.devices);
            return;
        }
    }
}

static void LoadOsAccountDbCe(int32_t osAccountId)
{
    TryMoveDeDataToCe(osAccountId);
    RemoveOsAccountTrustedInfo(osAccountId);
    LoadOsAccountDb(osAccountId);
}

static int32_t DelGroupFromDbInner(int32_t osAccountId, const char *groupId)
{
    if (groupId == NULL) {
        LOGE("The input groupId is NULL!");
        return HC_ERR_NULL_PTR;
    }
    QueryGroupParams queryGroupParams = InitQueryGroupParams();
    QueryDeviceParams queryDeviceParams = InitQueryDeviceParams();
    queryGroupParams.groupId = groupId;
    queryDeviceParams.groupId = groupId;
    int32_t result = HC_SUCCESS;
    if (DelTrustedDevice(osAccountId, &queryDeviceParams) != HC_SUCCESS) {
        result = HC_ERR_DEL_GROUP;
    }
    if (DelGroup(osAccountId, &queryGroupParams) != HC_SUCCESS) {
        result = HC_ERR_DEL_GROUP;
    }
    if (SaveOsAccountDb(osAccountId) != HC_SUCCESS) {
        result = HC_ERR_DEL_GROUP;
    }
    return result;
}

static void CheckAndRemoveUpgradeGroupEntry(const TrustedGroupEntry *groupEntry)
{
    if (groupEntry->upgradeFlag != IS_UPGRADE) {
        LOGW("Group is not upgrade group, not need to remove!");
        return;
    }
    const char *groupId = StringGet(&(groupEntry->id));

    HcString entryManager = HC_VECTOR_GET(&groupEntry->managers, 0);
    const char *groupOwner = StringGet(&entryManager);
    if (groupId == NULL || groupOwner == NULL) {
        LOGW("groupId or groupOwner is null, not need to remove!");
        return;
    }
    CJson *upgradeJson = CreateJson();
    if (upgradeJson == NULL) {
        LOGE("Failed to create upgradeIdentity json.");
        return;
    }
    if (AddStringToJson(upgradeJson, FIELD_APP_ID, groupOwner) != HC_SUCCESS) {
        FreeJson(upgradeJson);
        LOGE("Failed to add groupOwner.");
        return;
    }
    int32_t res = ExecuteAccountAuthCmd(UPGRADE_OS_ACCOUNT_ID, CHECK_UPGRADE_DATA, upgradeJson, NULL);
    FreeJson(upgradeJson);
    if (res == HC_SUCCESS) {
        LOGI("GroupOwner is in trustedlist, not need to remove!");
        return;
    }
    if (DelGroupFromDbInner(UPGRADE_OS_ACCOUNT_ID, groupId) != HC_SUCCESS) {
        LOGW("Delete group from db failed!");
        return;
    }
    LOGI("Delete group from db successfully!");
}

static void CheckAndRemoveUpgradeData(int32_t osAccountId)
{
    if (osAccountId != UPGRADE_OS_ACCOUNT_ID) {
        LOGI("Current os accountId is %" LOG_PUB "d, no need to check and remove.", osAccountId);
        return;
    }
    QueryGroupParams queryParams = InitQueryGroupParams();
    GroupEntryVec groupEntryVec = CreateGroupEntryVec();
    int32_t ret = QueryGroups(UPGRADE_OS_ACCOUNT_ID, &queryParams, &groupEntryVec);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to query groups!");
        ClearGroupEntryVec(&groupEntryVec);
        return;
    }
    uint32_t index;
    TrustedGroupEntry **ptr = NULL;
    FOR_EACH_HC_VECTOR(groupEntryVec, index, ptr) {
        if (ptr == NULL || *ptr == NULL) {
            continue;
        }
        const TrustedGroupEntry *groupEntry = (const TrustedGroupEntry *)(*ptr);
        CheckAndRemoveUpgradeGroupEntry(groupEntry);
    }
    ClearGroupEntryVec(&groupEntryVec);
}

static void OnOsAccountUnlocked(int32_t osAccountId)
{
    (void)LockHcMutex(g_databaseMutex);
    LoadOsAccountDbCe(osAccountId);
    UnlockHcMutex(g_databaseMutex);
    CheckAndRemoveUpgradeData(osAccountId);
}

static void OnOsAccountRemoved(int32_t osAccountId)
{
    LOGI("[DB]: os account is removed, osAccountId: %" LOG_PUB "d", osAccountId);
    (void)LockHcMutex(g_databaseMutex);
    RemoveOsAccountTrustedInfo(osAccountId);
    UnlockHcMutex(g_databaseMutex);
}

static bool IsOsAccountGroupDataLoaded(int32_t osAccountId)
{
    uint32_t index = 0;
    OsAccountTrustedInfo *info = NULL;
    FOR_EACH_HC_VECTOR(g_deviceauthDb, index, info) {
        if (info->osAccountId == osAccountId) {
            return true;
        }
    }
    return false;
}

static void LoadDataIfNotLoaded(int32_t osAccountId)
{
    if (IsOsAccountGroupDataLoaded(osAccountId)) {
        return;
    }
    LOGI("[DB]: data has not been loaded, load it, osAccountId: %" LOG_PUB "d", osAccountId);
    LoadOsAccountDbCe(osAccountId);
}

static OsAccountTrustedInfo *GetTrustedInfoByOsAccountId(int32_t osAccountId)
{
    if (IsOsAccountSupported()) {
        LoadDataIfNotLoaded(osAccountId);
    }
    uint32_t index = 0;
    OsAccountTrustedInfo *info = NULL;
    FOR_EACH_HC_VECTOR(g_deviceauthDb, index, info) {
        if (info->osAccountId == osAccountId) {
            return info;
        }
    }
    LOGI("[DB]: Create a new os account database cache! [Id]: %" LOG_PUB "d", osAccountId);
    OsAccountTrustedInfo newInfo;
    newInfo.osAccountId = osAccountId;
    newInfo.groups = CreateGroupEntryVec();
    newInfo.devices = CreateDeviceEntryVec();
    OsAccountTrustedInfo *returnInfo = g_deviceauthDb.pushBackT(&g_deviceauthDb, newInfo);
    if (returnInfo == NULL) {
        LOGE("[DB]: Failed to push osAccountInfo to database!");
        DestroyGroupEntryVec(&newInfo.groups);
        DestroyDeviceEntryVec(&newInfo.devices);
    }
    return returnInfo;
}

static void LoadDeviceAuthDb(void)
{
    if (IsOsAccountSupported()) {
        return;
    }
    (void)LockHcMutex(g_databaseMutex);
    StringVector osAccountDbNameVec = CreateStrVector();
    HcFileGetSubFileName(GetStorageDirPath(), &osAccountDbNameVec);
    HcString *dbName;
    uint32_t index;
    FOR_EACH_HC_VECTOR(osAccountDbNameVec, index, dbName) {
        int32_t osAccountId;
        const char *osAccountIdStr = StringGet(dbName);
        if (osAccountIdStr == NULL) {
            LOGW("[DB]: Invalid osAccountIdStr!");
            continue;
        }
        if (strcmp(osAccountIdStr, "hcgroup.dat") == 0) {
            LoadOsAccountDb(DEFAULT_OS_ACCOUNT);
        } else if (sscanf_s(osAccountIdStr, "hcgroup%d.dat", &osAccountId) == 1) {
            LoadOsAccountDb(osAccountId);
        }
    }
    DestroyStrVector(&osAccountDbNameVec);
    UnlockHcMutex(g_databaseMutex);
}

static bool SetGroupElement(TlvGroupElement *element, TrustedGroupEntry *entry)
{
    if (!StringSet(&element->name.data, entry->name)) {
        LOGE("[DB]: Failed to copy groupName!");
        return false;
    }
    if (!StringSet(&element->id.data, entry->id)) {
        LOGE("[DB]: Failed to copy groupId!");
        return false;
    }
    if (!StringSet(&element->userId.data, entry->userId)) {
        LOGE("[DB]: Failed to copy userId!");
        return false;
    }
    if (!StringSet(&element->sharedUserId.data, entry->sharedUserId)) {
        LOGE("[DB]: Failed to copy sharedUserId!");
        return false;
    }
    element->type.data = entry->type;
    element->visibility.data = entry->visibility;
    element->upgradeFlag.data = entry->upgradeFlag;
    element->expireTime.data = entry->expireTime;
    if (!SaveStringVectorToParcel(&entry->managers, &element->managers.data)) {
        LOGE("[DB]: Failed to copy managers!");
        return false;
    }
    if (!SaveStringVectorToParcel(&entry->friends, &element->friends.data)) {
        LOGE("[DB]: Failed to copy friends!");
        return false;
    }
    return true;
}

static bool SetDeviceElement(TlvDeviceElement *element, TrustedDeviceEntry *entry)
{
    if (!StringSet(&element->groupId.data, entry->groupId)) {
        LOGE("[DB]: Failed to copy groupId!");
        return false;
    }
    if (!StringSet(&element->udid.data, entry->udid)) {
        LOGE("[DB]: Failed to copy udid!");
        return false;
    }
    if (!StringSet(&element->authId.data, entry->authId)) {
        LOGE("[DB]: Failed to copy authId!");
        return false;
    }
    if (!StringSet(&element->userId.data, entry->userId)) {
        LOGE("[DB]: Failed to copy userId!");
        return false;
    }
    if (!StringSet(&element->serviceType.data, entry->serviceType)) {
        LOGE("[DB]: Failed to copy serviceType!");
        return false;
    }
    if (!ParcelCopy(&element->ext.data, &entry->ext)) {
        LOGE("[DB]: Failed to copy external data!");
        return false;
    }
    element->info.data.credential = entry->credential;
    element->info.data.devType = entry->devType;
    element->upgradeFlag.data = entry->upgradeFlag;
    element->info.data.source = entry->source;
    element->info.data.lastTm = entry->lastTm;
    return true;
}

static bool SaveGroups(const GroupEntryVec *vec, HCDataBaseV1 *db)
{
    uint32_t index;
    TrustedGroupEntry **entry;
    FOR_EACH_HC_VECTOR(*vec, index, entry) {
        TlvGroupElement tmp;
        TlvGroupElement *element = db->groups.data.pushBack(&db->groups.data, &tmp);
        if (element == NULL) {
            return false;
        }
        TLV_INIT(TlvGroupElement, element);
        if (!SetGroupElement(element, *entry)) {
            TLV_DEINIT((*element));
            return false;
        }
    }
    return true;
}

static bool SaveDevices(const DeviceEntryVec *vec, HCDataBaseV1 *db)
{
    uint32_t index;
    TrustedDeviceEntry **entry;
    FOR_EACH_HC_VECTOR(*vec, index, entry) {
        TlvDeviceElement tmp;
        TlvDeviceElement *element = db->devices.data.pushBack(&db->devices.data, &tmp);
        if (element == NULL) {
            return false;
        }
        TLV_INIT(TlvDeviceElement, element);
        if (!SetDeviceElement(element, *entry)) {
            TLV_DEINIT((*element));
            return false;
        }
    }
    return true;
}

static bool SaveInfoToParcel(const OsAccountTrustedInfo *info, HcParcel *parcel)
{
    int32_t ret = false;
    HCDataBaseV1 dbv1;
    TLV_INIT(HCDataBaseV1, &dbv1)
    dbv1.version.data = 1;
    do {
        if (!SaveGroups(&info->groups, &dbv1)) {
            break;
        }
        if (!SaveDevices(&info->devices, &dbv1)) {
            break;
        }
        if (!EncodeTlvMessage((TlvBase *)&dbv1, parcel)) {
            LOGE("[DB]: Encode Tlv Message failed!");
            break;
        }
        ret = true;
    } while (0);
    TLV_DEINIT(dbv1)
    return ret;
}

static bool CompareQueryGroupParams(const QueryGroupParams *params, const TrustedGroupEntry *entry)
{
    if ((params->groupId != NULL) && (strcmp(params->groupId, StringGet(&entry->id)) != 0)) {
        return false;
    }
    if ((params->groupName != NULL) && (strcmp(params->groupName, StringGet(&entry->name)) != 0)) {
        return false;
    }
    if ((params->userId != NULL) && (strcmp(params->userId, StringGet(&entry->userId)) != 0)) {
        return false;
    }
    if ((params->sharedUserId != NULL) && (strcmp(params->sharedUserId, StringGet(&entry->sharedUserId)) != 0)) {
        return false;
    }
    if ((params->groupType != ALL_GROUP) && (params->groupType != entry->type)) {
        return false;
    }
    if ((params->groupVisibility != ALL_GROUP_VISIBILITY) && (params->groupVisibility != entry->visibility)) {
        return false;
    }
    if (params->ownerName != NULL) {
        HcString entryOwner = HC_VECTOR_GET(&entry->managers, 0);
        if (strcmp(params->ownerName, StringGet(&entryOwner)) != 0) {
            return false;
        }
    }
    return true;
}

static bool CompareQueryDeviceParams(const QueryDeviceParams *params, const TrustedDeviceEntry *entry)
{
    if ((params->groupId != NULL) && (strcmp(params->groupId, StringGet(&entry->groupId)) != 0)) {
        return false;
    }
    if ((params->udid != NULL) && (strcmp(params->udid, StringGet(&entry->udid)) != 0)) {
        return false;
    }
    if ((params->authId != NULL) && (strcmp(params->authId, StringGet(&entry->authId)) != 0)) {
        return false;
    }
    if ((params->userId != NULL) && (strcmp(params->userId, StringGet(&entry->userId)) != 0)) {
        return false;
    }
    return true;
}

static TrustedGroupEntry **QueryGroupEntryPtrIfMatch(const GroupEntryVec *vec, const QueryGroupParams *params)
{
    uint32_t index;
    TrustedGroupEntry **entry;
    FOR_EACH_HC_VECTOR(*vec, index, entry) {
        if (CompareQueryGroupParams(params, *entry)) {
            return entry;
        }
    }
    return NULL;
}

static TrustedDeviceEntry **QueryDeviceEntryPtrIfMatch(const DeviceEntryVec *vec, const QueryDeviceParams *params)
{
    uint32_t index;
    TrustedDeviceEntry **entry;
    FOR_EACH_HC_VECTOR(*vec, index, entry) {
        if (CompareQueryDeviceParams(params, *entry)) {
            return entry;
        }
    }
    return NULL;
}

static int32_t AddGroupNameToReturn(const TrustedGroupEntry *groupInfo, CJson *json)
{
    const char *groupName = StringGet(&groupInfo->name);
    if (groupName == NULL) {
        LOGE("Failed to get groupName from groupInfo!");
        return HC_ERR_NULL_PTR;
    }
    if (AddStringToJson(json, FIELD_GROUP_NAME, groupName) != HC_SUCCESS) {
        LOGE("Failed to add groupName to json!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddGroupIdToReturn(const TrustedGroupEntry *groupInfo, CJson *json)
{
    const char *groupId = StringGet(&groupInfo->id);
    if (groupId == NULL) {
        LOGE("Failed to get groupId from groupInfo!");
        return HC_ERR_NULL_PTR;
    }
    if (AddStringToJson(json, FIELD_GROUP_ID, groupId) != HC_SUCCESS) {
        LOGE("Failed to add groupId to json!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddGroupOwnerToReturn(const TrustedGroupEntry *groupInfo, CJson *json)
{
    HcString entryManager = HC_VECTOR_GET(&groupInfo->managers, 0);
    const char *groupOwner = StringGet(&entryManager);
    if (groupOwner == NULL) {
        LOGE("Failed to get groupOwner from groupInfo!");
        return HC_ERR_NULL_PTR;
    }
    if (AddStringToJson(json, FIELD_GROUP_OWNER, groupOwner) != HC_SUCCESS) {
        LOGE("Failed to add groupOwner to json!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddGroupTypeToReturn(const TrustedGroupEntry *groupInfo, CJson *json)
{
    int32_t groupType = groupInfo->type;
    if (AddIntToJson(json, FIELD_GROUP_TYPE, groupType) != HC_SUCCESS) {
        LOGE("Failed to add groupType to json!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddGroupVisibilityToReturn(const TrustedGroupEntry *groupInfo, CJson *json)
{
    int groupVisibility = groupInfo->visibility;
    if (AddIntToJson(json, FIELD_GROUP_VISIBILITY, groupVisibility) != HC_SUCCESS) {
        LOGE("Failed to add groupType to json!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddUserIdToReturnIfAccountGroup(const TrustedGroupEntry *groupInfo, CJson *json)
{
    if ((groupInfo->type != ACROSS_ACCOUNT_AUTHORIZE_GROUP) && (groupInfo->type != IDENTICAL_ACCOUNT_GROUP)) {
        return HC_SUCCESS;
    }
    const char *userId = StringGet(&groupInfo->userId);
    if (userId == NULL) {
        LOGE("Failed to get userId from groupInfo!");
        return HC_ERR_NULL_PTR;
    }
    if (AddStringToJson(json, FIELD_USER_ID, userId) != HC_SUCCESS) {
        LOGE("Failed to add userId to json!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddSharedUserIdToReturnIfAcrossAccountGroup(const TrustedGroupEntry *groupInfo, CJson *json)
{
    if (groupInfo->type != ACROSS_ACCOUNT_AUTHORIZE_GROUP) {
        return HC_SUCCESS;
    }
    const char *sharedUserId = StringGet(&groupInfo->sharedUserId);
    if (sharedUserId == NULL) {
        LOGE("Failed to get sharedUserId from groupInfo!");
        return HC_ERR_NULL_PTR;
    }
    if (AddStringToJson(json, FIELD_SHARED_USER_ID, sharedUserId) != HC_SUCCESS) {
        LOGE("Failed to add sharedUserId to json!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddAuthIdToReturn(const TrustedDeviceEntry *deviceInfo, CJson *json)
{
    const char *authId = StringGet(&deviceInfo->authId);
    if (authId == NULL) {
        LOGE("Failed to get authId from deviceInfo!");
        return HC_ERR_NULL_PTR;
    }
    if (AddStringToJson(json, FIELD_AUTH_ID, authId) != HC_SUCCESS) {
        LOGE("Failed to add authId to json!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddCredentialTypeToReturn(const TrustedDeviceEntry *deviceInfo, CJson *json)
{
    int credentialType = deviceInfo->credential;
    if (AddIntToJson(json, FIELD_CREDENTIAL_TYPE, credentialType) != HC_SUCCESS) {
        LOGE("Failed to add credentialType to json!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddUserTypeToReturn(const TrustedDeviceEntry *deviceInfo, CJson *json)
{
    int userType = deviceInfo->devType;
    if (AddIntToJson(json, FIELD_USER_TYPE, userType) != HC_SUCCESS) {
        LOGE("Failed to add userType to json!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t GenerateMessage(const TrustedGroupEntry *groupEntry, char **returnGroupInfo)
{
    if (groupEntry == NULL) {
        LOGE("Input param groupEntry is null!");
        return HC_ERR_NULL_PTR;
    }
    CJson *message = CreateJson();
    if (message == NULL) {
        LOGE("Failed to allocate message memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t result = GenerateReturnGroupInfo(groupEntry, message);
    if (result != HC_SUCCESS) {
        FreeJson(message);
        return result;
    }
    char *messageStr = PackJsonToString(message);
    FreeJson(message);
    if (messageStr == NULL) {
        LOGE("Failed to convert json to string!");
        return HC_ERR_JSON_FAIL;
    }
    *returnGroupInfo = messageStr;
    return HC_SUCCESS;
}

static void PostGroupCreatedMsg(const TrustedGroupEntry *groupEntry)
{
    if (!IsBroadcastSupported()) {
        return;
    }
    char *messageStr = NULL;
    if (GenerateMessage(groupEntry, &messageStr) != HC_SUCCESS) {
        return;
    }
    GetBroadcaster()->postOnGroupCreated(messageStr);
    FreeJsonString(messageStr);
}

static void PostGroupDeletedMsg(const TrustedGroupEntry *groupEntry)
{
    if (!IsBroadcastSupported()) {
        return;
    }
    char *messageStr = NULL;
    if (GenerateMessage(groupEntry, &messageStr) != HC_SUCCESS) {
        return;
    }
    GetBroadcaster()->postOnGroupDeleted(messageStr);
    FreeJsonString(messageStr);
}

static void PostDeviceBoundMsg(OsAccountTrustedInfo *info, const TrustedDeviceEntry *deviceEntry)
{
    if (!IsBroadcastSupported()) {
        return;
    }
    QueryGroupParams groupParams = InitQueryGroupParams();
    groupParams.groupId = StringGet(&deviceEntry->groupId);
    TrustedGroupEntry **groupEntryPtr = QueryGroupEntryPtrIfMatch(&info->groups, &groupParams);
    if (groupEntryPtr != NULL) {
        char *messageStr = NULL;
        if (GenerateMessage(*groupEntryPtr, &messageStr) != HC_SUCCESS) {
            return;
        }
        GetBroadcaster()->postOnDeviceBound(StringGet(&deviceEntry->udid), messageStr);
        FreeJsonString(messageStr);
    }
}

static bool IsSelfDeviceEntry(const TrustedDeviceEntry *deviceEntry)
{
    char selfUdid[INPUT_UDID_LEN] = { 0 };
    int32_t res = HcGetUdid((uint8_t *)selfUdid, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local udid! res: %" LOG_PUB "d", res);
        return false;
    }
    const char *entryUdid = StringGet(&deviceEntry->udid);
    if (entryUdid == NULL) {
        LOGE("The entryUdid is NULL!");
        return false;
    }
    return strcmp(selfUdid, entryUdid) == 0;
}

static int32_t GenerateMessageWithOsAccount(const TrustedGroupEntry *groupEntry, int32_t osAccountId,
    char **returnMessageStr)
{
    if (groupEntry == NULL) {
        LOGE("groupEntry is null!");
        return HC_ERR_NULL_PTR;
    }
    CJson *message = CreateJson();
    if (message == NULL) {
        LOGE("Failed to create message json!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t result = GenerateReturnGroupInfo(groupEntry, message);
    if (result != HC_SUCCESS) {
        FreeJson(message);
        return result;
    }
    if (AddIntToJson(message, FIELD_OS_ACCOUNT_ID, osAccountId) != HC_SUCCESS) {
        FreeJson(message);
        return HC_ERR_JSON_ADD;
    }
    char *messageStr = PackJsonToString(message);
    FreeJson(message);
    if (messageStr == NULL) {
        LOGE("Failed to convert json to string!");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    *returnMessageStr = messageStr;
    return HC_SUCCESS;
}

static void PostDeviceUnBoundMsg(OsAccountTrustedInfo *info, const TrustedDeviceEntry *deviceEntry)
{
    if (!IsBroadcastSupported()) {
        return;
    }
    const char *groupId = StringGet(&deviceEntry->groupId);
    const char *udid = StringGet(&deviceEntry->udid);
    QueryGroupParams groupParams = InitQueryGroupParams();
    groupParams.groupId = groupId;
    TrustedGroupEntry **groupEntryPtr = QueryGroupEntryPtrIfMatch(&info->groups, &groupParams);
    if (groupEntryPtr != NULL) {
        char *messageStr = NULL;
        if (GenerateMessageWithOsAccount(*groupEntryPtr, info->osAccountId, &messageStr) != HC_SUCCESS) {
            return;
        }
        GetBroadcaster()->postOnDeviceUnBound(udid, messageStr);
        FreeJsonString(messageStr);
    }
    QueryDeviceParams deviceParams = InitQueryDeviceParams();
    deviceParams.udid = udid;
    if (QueryDeviceEntryPtrIfMatch(&info->devices, &deviceParams) == NULL) {
        GetBroadcaster()->postOnDeviceNotTrusted(udid);
        if (!IsSelfDeviceEntry(deviceEntry)) {
            (void)DeleteMk(info->osAccountId, udid);
            (void)DeletePseudonymPsk(info->osAccountId, udid);
        }
    }
}

static void DeletePdidByDeviceEntry(int32_t osAccountId, const TrustedDeviceEntry *deviceEntry)
{
    if (IsSelfDeviceEntry(deviceEntry)) {
        return;
    }
    const char *userId = StringGet(&deviceEntry->userId);
    if (userId == NULL) {
        LOGW("userId is null!");
        return;
    }
    if (deviceEntry->credential != ASYMMETRIC_CRED) {
        LOGW("credential type is not asymmetric!");
        return;
    }
    PseudonymManager *manager = GetPseudonymInstance();
    if (manager == NULL) {
        LOGE("Pseudonym manager is null!");
        return;
    }
    int32_t res = manager->deletePseudonymId(osAccountId, userId);
    if (res != HC_SUCCESS) {
        LOGE("Failed to delete pdid!");
    } else {
        LOGI("Delete pdid successfully!");
    }
}

QueryGroupParams InitQueryGroupParams(void)
{
    QueryGroupParams params = {
        .groupId = NULL,
        .groupName = NULL,
        .ownerName = NULL,
        .userId = NULL,
        .groupType = ALL_GROUP,
        .groupVisibility = ALL_GROUP_VISIBILITY
    };
    return params;
}

QueryDeviceParams InitQueryDeviceParams(void)
{
    QueryDeviceParams params = {
        .groupId = NULL,
        .udid = NULL,
        .authId = NULL,
        .userId = NULL
    };
    return params;
}

TrustedGroupEntry *CreateGroupEntry(void)
{
    TrustedGroupEntry *ptr = (TrustedGroupEntry *)HcMalloc(sizeof(TrustedGroupEntry), 0);
    if (ptr == NULL) {
        LOGE("[DB]: Failed to allocate groupEntry memory!");
        return NULL;
    }
    ptr->name = CreateString();
    ptr->id = CreateString();
    ptr->userId = CreateString();
    ptr->sharedUserId = CreateString();
    ptr->managers = CreateStrVector();
    ptr->friends = CreateStrVector();
    return ptr;
}

void DestroyGroupEntry(TrustedGroupEntry *groupEntry)
{
    if (groupEntry == NULL) {
        return;
    }
    DeleteString(&groupEntry->name);
    DeleteString(&groupEntry->id);
    DeleteString(&groupEntry->userId);
    DeleteString(&groupEntry->sharedUserId);
    DestroyStrVector(&groupEntry->managers);
    DestroyStrVector(&groupEntry->friends);
    HcFree(groupEntry);
}

TrustedGroupEntry *DeepCopyGroupEntry(const TrustedGroupEntry *entry)
{
    TrustedGroupEntry *returnEntry = CreateGroupEntry();
    if (returnEntry == NULL) {
        return NULL;
    }
    if (!GenerateGroupEntryFromEntry(entry, returnEntry)) {
        DestroyGroupEntry(returnEntry);
        return NULL;
    }
    return returnEntry;
}

TrustedDeviceEntry *CreateDeviceEntry(void)
{
    TrustedDeviceEntry *ptr = (TrustedDeviceEntry *)HcMalloc(sizeof(TrustedDeviceEntry), 0);
    if (ptr == NULL) {
        LOGE("[DB]: Failed to allocate deviceEntry memory!");
        return NULL;
    }
    ptr->groupId = CreateString();
    ptr->udid = CreateString();
    ptr->authId = CreateString();
    ptr->userId = CreateString();
    ptr->serviceType = CreateString();
    ptr->ext = CreateParcel(0, 0);
    return ptr;
}

void DestroyDeviceEntry(TrustedDeviceEntry *deviceEntry)
{
    if (deviceEntry == NULL) {
        return;
    }
    DeleteString(&deviceEntry->groupId);
    DeleteString(&deviceEntry->udid);
    DeleteString(&deviceEntry->authId);
    DeleteString(&deviceEntry->userId);
    DeleteString(&deviceEntry->serviceType);
    DeleteParcel(&deviceEntry->ext);
    HcFree(deviceEntry);
}

TrustedDeviceEntry *DeepCopyDeviceEntry(const TrustedDeviceEntry *entry)
{
    if (entry == NULL) {
        return NULL;
    }
    TrustedDeviceEntry *returnEntry = CreateDeviceEntry();
    if (returnEntry == NULL) {
        return NULL;
    }
    if (!GenerateDeviceEntryFromEntry(entry, returnEntry)) {
        DestroyDeviceEntry(returnEntry);
        return NULL;
    }
    return returnEntry;
}

void ClearGroupEntryVec(GroupEntryVec *vec)
{
    uint32_t index;
    TrustedGroupEntry **entry;
    FOR_EACH_HC_VECTOR(*vec, index, entry) {
        DestroyGroupEntry(*entry);
    }
    DESTROY_HC_VECTOR(GroupEntryVec, vec);
}

void ClearDeviceEntryVec(DeviceEntryVec *vec)
{
    uint32_t index;
    TrustedDeviceEntry **entry;
    FOR_EACH_HC_VECTOR(*vec, index, entry) {
        DestroyDeviceEntry(*entry);
    }
    DESTROY_HC_VECTOR(DeviceEntryVec, vec);
}

int32_t GenerateReturnGroupInfo(const TrustedGroupEntry *groupEntry, CJson *returnJson)
{
    int32_t result;
    if (((result = AddGroupNameToReturn(groupEntry, returnJson)) != HC_SUCCESS) ||
        ((result = AddGroupIdToReturn(groupEntry, returnJson)) != HC_SUCCESS) ||
        ((result = AddGroupOwnerToReturn(groupEntry, returnJson)) != HC_SUCCESS) ||
        ((result = AddGroupTypeToReturn(groupEntry, returnJson)) != HC_SUCCESS) ||
        ((result = AddGroupVisibilityToReturn(groupEntry, returnJson)) != HC_SUCCESS) ||
        ((result = AddUserIdToReturnIfAccountGroup(groupEntry, returnJson)) != HC_SUCCESS) ||
        ((result = AddSharedUserIdToReturnIfAcrossAccountGroup(groupEntry, returnJson)) != HC_SUCCESS)) {
        return result;
    }
    return HC_SUCCESS;
}

int32_t GenerateReturnDevInfo(const TrustedDeviceEntry *deviceEntry, CJson *returnJson)
{
    int32_t result;
    if (((result = AddAuthIdToReturn(deviceEntry, returnJson)) != HC_SUCCESS) ||
        ((result = AddCredentialTypeToReturn(deviceEntry, returnJson)) != HC_SUCCESS) ||
        ((result = AddUserTypeToReturn(deviceEntry, returnJson)) != HC_SUCCESS)) {
        return result;
    }
    return HC_SUCCESS;
}

int32_t AddGroup(int32_t osAccountId, const TrustedGroupEntry *groupEntry)
{
    LOGI("[DB]: Start to add a group to database! [OsAccountId]: %" LOG_PUB "d", osAccountId);
    if (groupEntry == NULL) {
        LOGE("[DB]: The input groupEntry is NULL!");
        return HC_ERR_NULL_PTR;
    }
    (void)LockHcMutex(g_databaseMutex);
    OsAccountTrustedInfo *info = GetTrustedInfoByOsAccountId(osAccountId);
    if (info == NULL) {
        UnlockHcMutex(g_databaseMutex);
        return HC_ERR_INVALID_PARAMS;
    }
    TrustedGroupEntry *newEntry = DeepCopyGroupEntry(groupEntry);
    if (newEntry == NULL) {
        UnlockHcMutex(g_databaseMutex);
        return HC_ERR_MEMORY_COPY;
    }
    QueryGroupParams params = InitQueryGroupParams();
    params.groupId = StringGet(&groupEntry->id);
    TrustedGroupEntry **oldEntryPtr = QueryGroupEntryPtrIfMatch(&info->groups, &params);
    if (oldEntryPtr != NULL) {
        DestroyGroupEntry(*oldEntryPtr);
        *oldEntryPtr = newEntry;
        PostGroupCreatedMsg(newEntry);
        UnlockHcMutex(g_databaseMutex);
        LOGI("[DB]: Replace an old group successfully! [GroupType]: %" LOG_PUB "u", groupEntry->type);
        return HC_SUCCESS;
    }
    if (info->groups.pushBackT(&info->groups, newEntry) == NULL) {
        DestroyGroupEntry(newEntry);
        UnlockHcMutex(g_databaseMutex);
        LOGE("[DB]: Failed to push groupEntry to vec!");
        return HC_ERR_MEMORY_COPY;
    }
    PostGroupCreatedMsg(newEntry);
    UnlockHcMutex(g_databaseMutex);
    LOGI("[DB]: Add a group to database successfully! [GroupType]: %" LOG_PUB "u", groupEntry->type);
    return HC_SUCCESS;
}

int32_t AddTrustedDevice(int32_t osAccountId, const TrustedDeviceEntry *deviceEntry)
{
    LOGI("[DB]: Start to add a trusted device to database! [OsAccountId]: %" LOG_PUB "d", osAccountId);
    if (deviceEntry == NULL) {
        LOGE("[DB]: The input deviceEntry is NULL!");
        return HC_ERR_NULL_PTR;
    }
    (void)LockHcMutex(g_databaseMutex);
    OsAccountTrustedInfo *info = GetTrustedInfoByOsAccountId(osAccountId);
    if (info == NULL) {
        UnlockHcMutex(g_databaseMutex);
        return HC_ERR_INVALID_PARAMS;
    }
    TrustedDeviceEntry *newEntry = DeepCopyDeviceEntry(deviceEntry);
    if (newEntry == NULL) {
        UnlockHcMutex(g_databaseMutex);
        return HC_ERR_MEMORY_COPY;
    }
    QueryDeviceParams params = InitQueryDeviceParams();
    params.udid = StringGet(&deviceEntry->udid);
    params.groupId = StringGet(&deviceEntry->groupId);
    TrustedDeviceEntry **oldEntryPtr = QueryDeviceEntryPtrIfMatch(&info->devices, &params);
    if (oldEntryPtr != NULL) {
        DestroyDeviceEntry(*oldEntryPtr);
        *oldEntryPtr = newEntry;
        PostDeviceBoundMsg(info, newEntry);
        UnlockHcMutex(g_databaseMutex);
        LOGI("[DB]: Replace an old trusted device successfully!");
        return HC_SUCCESS;
    }
    if (info->devices.pushBackT(&info->devices, newEntry) == NULL) {
        DestroyDeviceEntry(newEntry);
        UnlockHcMutex(g_databaseMutex);
        LOGE("[DB]: Failed to push deviceEntry to vec!");
        return HC_ERR_MEMORY_COPY;
    }
    PostDeviceBoundMsg(info, newEntry);
    UnlockHcMutex(g_databaseMutex);
    LOGI("[DB]: Add a trusted device to database successfully!");
    return HC_SUCCESS;
}

int32_t DelGroup(int32_t osAccountId, const QueryGroupParams *params)
{
    LOGI("[DB]: Start to delete groups from database! [OsAccountId]: %" LOG_PUB "d", osAccountId);
    if (params == NULL) {
        LOGE("[DB]: The input params is NULL!");
        return HC_ERR_NULL_PTR;
    }
    (void)LockHcMutex(g_databaseMutex);
    OsAccountTrustedInfo *info = GetTrustedInfoByOsAccountId(osAccountId);
    if (info == NULL) {
        UnlockHcMutex(g_databaseMutex);
        LOGE("[DB]: GetTrustedInfoByOsAccountId occurred error!");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t count = 0;
    uint32_t index = 0;
    TrustedGroupEntry **entry = NULL;
    while (index < HC_VECTOR_SIZE(&info->groups)) {
        entry = info->groups.getp(&info->groups, index);
        if ((entry == NULL) || (*entry == NULL) || (!CompareQueryGroupParams(params, *entry))) {
            index++;
            continue;
        }
        TrustedGroupEntry *popEntry;
        HC_VECTOR_POPELEMENT(&info->groups, &popEntry, index);
        PostGroupDeletedMsg(popEntry);
        LOGI("[DB]: Delete a group from database successfully! [GroupType]: %" LOG_PUB "u", popEntry->type);
        DestroyGroupEntry(popEntry);
        count++;
    }
    UnlockHcMutex(g_databaseMutex);
    LOGI("[DB]: Number of groups deleted: %" LOG_PUB "d", count);
    return HC_SUCCESS;
}

int32_t DelTrustedDevice(int32_t osAccountId, const QueryDeviceParams *params)
{
    LOGI("[DB]: Start to delete devices from database! [OsAccountId]: %" LOG_PUB "d", osAccountId);
    if (params == NULL) {
        LOGE("[DB]: The input params is NULL!");
        return HC_ERR_NULL_PTR;
    }
    (void)LockHcMutex(g_databaseMutex);
    OsAccountTrustedInfo *info = GetTrustedInfoByOsAccountId(osAccountId);
    if (info == NULL) {
        UnlockHcMutex(g_databaseMutex);
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t count = 0;
    uint32_t index = 0;
    TrustedDeviceEntry **entry = NULL;
    while (index < HC_VECTOR_SIZE(&info->devices)) {
        entry = info->devices.getp(&info->devices, index);
        if ((entry == NULL) || (*entry == NULL) || (!CompareQueryDeviceParams(params, *entry))) {
            index++;
            continue;
        }
        TrustedDeviceEntry *popEntry;
        HC_VECTOR_POPELEMENT(&info->devices, &popEntry, index);
        PostDeviceUnBoundMsg(info, popEntry);
        DeletePdidByDeviceEntry(osAccountId, popEntry);
        LOGI("[DB]: Delete a trusted device from database successfully!");
        DestroyDeviceEntry(popEntry);
        count++;
    }
    UnlockHcMutex(g_databaseMutex);
    LOGI("[DB]: Number of trusted devices deleted: %" LOG_PUB "d", count);
    return HC_SUCCESS;
}

int32_t QueryGroups(int32_t osAccountId, const QueryGroupParams *params, GroupEntryVec *vec)
{
    if ((params == NULL) || (vec == NULL)) {
        LOGE("[DB]: Error occurs, the input params or vec is NULL!");
        return HC_ERR_NULL_PTR;
    }
    (void)LockHcMutex(g_databaseMutex);
    OsAccountTrustedInfo *info = GetTrustedInfoByOsAccountId(osAccountId);
    if (info == NULL) {
        UnlockHcMutex(g_databaseMutex);
        return HC_ERR_INVALID_PARAMS;
    }
    uint32_t index;
    TrustedGroupEntry **entry;
    FOR_EACH_HC_VECTOR(info->groups, index, entry) {
        if (!CompareQueryGroupParams(params, *entry)) {
            continue;
        }
        TrustedGroupEntry *newEntry = DeepCopyGroupEntry(*entry);
        if (newEntry == NULL) {
            continue;
        }
        if (vec->pushBackT(vec, newEntry) == NULL) {
            LOGE("[DB]: Failed to push entry to vec!");
            DestroyGroupEntry(newEntry);
        }
    }
    UnlockHcMutex(g_databaseMutex);
    return HC_SUCCESS;
}

int32_t QueryDevices(int32_t osAccountId, const QueryDeviceParams *params, DeviceEntryVec *vec)
{
    if ((params == NULL) || (vec == NULL)) {
        LOGE("[DB]: The input query devices params or vec is NULL!");
        return HC_ERR_NULL_PTR;
    }
    (void)LockHcMutex(g_databaseMutex);
    OsAccountTrustedInfo *info = GetTrustedInfoByOsAccountId(osAccountId);
    if (info == NULL) {
        UnlockHcMutex(g_databaseMutex);
        return HC_ERR_INVALID_PARAMS;
    }
    uint32_t index;
    TrustedDeviceEntry **entry;
    FOR_EACH_HC_VECTOR(info->devices, index, entry) {
        if (!CompareQueryDeviceParams(params, *entry)) {
            continue;
        }
        TrustedDeviceEntry *newEntry = DeepCopyDeviceEntry(*entry);
        if (newEntry == NULL) {
            continue;
        }
        if (vec->pushBackT(vec, newEntry) == NULL) {
            LOGE("[DB]: Failed to push entry to vec!");
            DestroyDeviceEntry(newEntry);
        }
    }
    UnlockHcMutex(g_databaseMutex);
    return HC_SUCCESS;
}

int32_t SaveOsAccountDb(int32_t osAccountId)
{
    (void)LockHcMutex(g_databaseMutex);
    OsAccountTrustedInfo *info = GetTrustedInfoByOsAccountId(osAccountId);
    if (info == NULL) {
        UnlockHcMutex(g_databaseMutex);
        return HC_ERR_INVALID_PARAMS;
    }
    HcParcel parcel = CreateParcel(0, 0);
    if (!SaveInfoToParcel(info, &parcel)) {
        DeleteParcel(&parcel);
        UnlockHcMutex(g_databaseMutex);
        return HC_ERR_MEMORY_COPY;
    }
    char filePath[MAX_DB_PATH_LEN] = { 0 };
    if (!GetOsAccountInfoPath(osAccountId, filePath, MAX_DB_PATH_LEN)) {
        DeleteParcel(&parcel);
        UnlockHcMutex(g_databaseMutex);
        return HC_ERROR;
    }
    if (!SaveParcelToFile(filePath, &parcel)) {
        DeleteParcel(&parcel);
        UnlockHcMutex(g_databaseMutex);
        return HC_ERR_MEMORY_COPY;
    }
    DeleteParcel(&parcel);
    UnlockHcMutex(g_databaseMutex);
    LOGI("[DB]: Save an os account database successfully! [Id]: %" LOG_PUB "d", osAccountId);
    return HC_SUCCESS;
}

void ReloadOsAccountDb(int32_t osAccountId)
{
    if (g_databaseMutex == NULL) {
        LOGE("[DB]: not initialized!");
        return;
    }
    (void)LockHcMutex(g_databaseMutex);
    LoadOsAccountDbCe(osAccountId);
    UnlockHcMutex(g_databaseMutex);
}

#ifdef DEV_AUTH_HIVIEW_ENABLE
static void DumpGroup(int fd, const TrustedGroupEntry *group)
{
    dprintf(fd, "||----------------------------Group----------------------------|                   |\n");
    dprintf(fd, "||%-12s = %-46.8s|                   |\n", "name", StringGet(&group->name));
    dprintf(fd, "||%-12s = %-46.8s|                   |\n", "id", StringGet(&group->id));
    dprintf(fd, "||%-12s = %-46d|                   |\n", "type", group->type);
    dprintf(fd, "||%-12s = %-46d|                   |\n", "visibility", group->visibility);
    dprintf(fd, "||%-12s = %-46d|                   |\n", "upgradeFlag", group->upgradeFlag);
    dprintf(fd, "||%-12s = %-46d|                   |\n", "expireTime", group->expireTime);
    HcString entryOwner = HC_VECTOR_GET(&group->managers, 0);
    dprintf(fd, "||%-12s = %-46.8s|                   |\n", "ownerName", StringGet(&entryOwner));
    dprintf(fd, "||%-12s = %-46.8s|                   |\n", "userId", StringGet(&group->userId));
    dprintf(fd, "||%-12s = %-46.8s|                   |\n", "sharedUserId", StringGet(&group->sharedUserId));
    dprintf(fd, "||----------------------------Group----------------------------|                   |\n");
}

static void DumpDevice(int fd, const TrustedDeviceEntry *device)
{
    dprintf(fd, "|||--------------------DEV--------------------|                                    |\n");
    dprintf(fd, "|||%-12s = %-28.8s|                                    |\n", "groupId", StringGet(&device->groupId));
    dprintf(fd, "|||%-12s = %-28.8s|                                    |\n", "udid", StringGet(&device->udid));
    dprintf(fd, "|||%-12s = %-28.8s|                                    |\n", "authId", StringGet(&device->authId));
    dprintf(fd, "|||%-12s = %-28.8s|                                    |\n", "userId", StringGet(&device->userId));
    dprintf(fd, "|||%-12s = %-28.8s|                                    |\n", "serviceType",
        StringGet(&device->serviceType));
    dprintf(fd, "|||%-12s = %-28d|                                    |\n", "credential", device->credential);
    dprintf(fd, "|||%-12s = %-28d|                                    |\n", "devType", device->devType);
    dprintf(fd, "|||%-12s = %-28d|                                    |\n", "upgradeFlag", device->upgradeFlag);
    dprintf(fd, "|||%-12s = %-28d|                                    |\n", "credSource", device->source);
    dprintf(fd, "|||--------------------DEV--------------------|                                    |\n");
}

static void DumpDb(int fd, const OsAccountTrustedInfo *db)
{
    const GroupEntryVec *groups = &db->groups;
    const DeviceEntryVec *devices = &db->devices;
    dprintf(fd, "|-------------------------------------DataBase-------------------------------------|\n");
    dprintf(fd, "|%-12s = %-67d|\n", "osAccountId", db->osAccountId);
    dprintf(fd, "|%-12s = %-67d|\n", "groupNum", groups->size(groups));
    dprintf(fd, "|%-12s = %-67d|\n", "deviceNum", devices->size(devices));
    uint32_t index;
    TrustedGroupEntry **groupEntry;
    FOR_EACH_HC_VECTOR(*groups, index, groupEntry) {
        DumpGroup(fd, *groupEntry);
    }
    TrustedDeviceEntry **deviceEntry;
    FOR_EACH_HC_VECTOR(*devices, index, deviceEntry) {
        DumpDevice(fd, *deviceEntry);
    }
    dprintf(fd, "|-------------------------------------DataBase-------------------------------------|\n");
}

static void LoadAllAccountsData(void)
{
    int32_t *accountIds = NULL;
    uint32_t size = 0;
    int32_t ret = GetAllOsAccountIds(&accountIds, &size);
    if (ret != HC_SUCCESS) {
        LOGE("[DB]: Failed to get all os account ids, [res]: %" LOG_PUB "d", ret);
        return;
    }
    for (uint32_t index = 0; index < size; index++) {
        LoadDataIfNotLoaded(accountIds[index]);
    }
    HcFree(accountIds);
}

static void DevAuthDataBaseDump(int fd)
{
    if (g_databaseMutex == NULL) {
        LOGE("[DB]: Init mutex failed");
        return;
    }
    (void)LockHcMutex(g_databaseMutex);
    if (IsOsAccountSupported()) {
        LoadAllAccountsData();
    }
    uint32_t index;
    OsAccountTrustedInfo *info;
    FOR_EACH_HC_VECTOR(g_deviceauthDb, index, info) {
        DumpDb(fd, info);
    }
    UnlockHcMutex(g_databaseMutex);
}
#endif

int32_t InitDatabase(void)
{
    if (g_databaseMutex == NULL) {
        g_databaseMutex = (HcMutex *)HcMalloc(sizeof(HcMutex), 0);
        if (g_databaseMutex == NULL) {
            LOGE("[DB]: Alloc databaseMutex failed");
            return HC_ERR_ALLOC_MEMORY;
        }
        if (InitHcMutex(g_databaseMutex, false) != HC_SUCCESS) {
            LOGE("[DB]: Init mutex failed");
            HcFree(g_databaseMutex);
            g_databaseMutex = NULL;
            return HC_ERROR;
        }
    }
    g_deviceauthDb = CREATE_HC_VECTOR(DeviceAuthDb);
    AddOsAccountEventCallback(GROUP_DATA_CALLBACK, OnOsAccountUnlocked, OnOsAccountRemoved);
    LoadDeviceAuthDb();
    DEV_AUTH_REG_DUMP_FUNC(DevAuthDataBaseDump);
    return HC_SUCCESS;
}

void DestroyDatabase(void)
{
    RemoveOsAccountEventCallback(GROUP_DATA_CALLBACK);
    (void)LockHcMutex(g_databaseMutex);
    uint32_t index;
    OsAccountTrustedInfo *info;
    FOR_EACH_HC_VECTOR(g_deviceauthDb, index, info) {
        ClearGroupEntryVec(&info->groups);
        ClearDeviceEntryVec(&info->devices);
    }
    DESTROY_HC_VECTOR(DeviceAuthDb, &g_deviceauthDb);
    UnlockHcMutex(g_databaseMutex);
    DestroyHcMutex(g_databaseMutex);
    HcFree(g_databaseMutex);
    g_databaseMutex = NULL;
}