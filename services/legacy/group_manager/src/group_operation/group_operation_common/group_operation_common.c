/*
 * Copyright (C) 2021-2025 Huawei Device Co., Ltd.
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

#include "group_operation_common.h"

#include "alg_loader.h"
#include "string_util.h"
#include "group_data_manager.h"
#include "dev_auth_module_manager.h"
#include "device_auth_defines.h"
#include "hal_error.h"
#include "hc_dev_info.h"
#include "hc_log.h"
#include "account_task_manager.h"

static const char *IDENTITY_FROM_DB = "identityFromDB";

int32_t CheckUpgradeIdentity(uint8_t upgradeFlag, const char *appId, const char *identityFromDB)
{
    if (upgradeFlag != IS_UPGRADE) {
        LOGW("Failed to check upgrade indentity, not upgrade situation.");
        return HC_ERROR;
    }
    CJson *upgradeJson = CreateJson();
    if (upgradeJson == NULL) {
        LOGE("Failed to create upgradeIdentity json.");
        return HC_ERR_JSON_CREATE;
    }
    if (AddStringToJson(upgradeJson, FIELD_APP_ID, appId) != HC_SUCCESS) {
        FreeJson(upgradeJson);
        LOGE("Failed to add appId.");
        return HC_ERR_JSON_ADD;
    }
    if (identityFromDB != NULL && AddStringToJson(upgradeJson, IDENTITY_FROM_DB, identityFromDB) != HC_SUCCESS) {
        FreeJson(upgradeJson);
        LOGE("Failed to add identityFromDB.");
        return HC_ERR_JSON_ADD;
    }
    int32_t res = ExecuteAccountAuthCmd(0, CHECK_UPGRADE_IDENTITY, upgradeJson, NULL);
    FreeJson(upgradeJson);
    if (res != HC_SUCCESS) {
        LOGW("Check upgradeIdentity failed, appId or identity may be incorrect.");
        return res;
    }
    LOGI("Check upgradeIdentity successfully.");
    return res;
}

static bool IsGroupManager(const char *appId, const TrustedGroupEntry *entry)
{
    uint32_t index;
    HcString *manager = NULL;
    FOR_EACH_HC_VECTOR(entry->managers, index, manager) {
        if ((strcmp(StringGet(manager), appId) == 0) ||
            CheckUpgradeIdentity(entry->upgradeFlag, appId, StringGet(manager)) == HC_SUCCESS) {
            return true;
        }
    }
    return false;
}

static bool IsGroupFriend(const char *appId, const TrustedGroupEntry *entry)
{
    uint32_t index;
    HcString *trustedFriend = NULL;
    FOR_EACH_HC_VECTOR(entry->friends, index, trustedFriend) {
        if ((strcmp(StringGet(trustedFriend), appId) == 0) ||
            CheckUpgradeIdentity(entry->upgradeFlag, appId, StringGet(trustedFriend)) == HC_SUCCESS) {
            return true;
        }
    }
    return false;
}

static uint32_t GetGroupNumByOwner(int32_t osAccountId, const char *ownerName)
{
    if (ownerName == NULL) {
        LOGE("The input ownerName is NULL!");
        return 0;
    }
    uint32_t count = 0;
    QueryGroupParams queryParams = InitQueryGroupParams();
    queryParams.ownerName = ownerName;
    GroupEntryVec groupEntryVec = CreateGroupEntryVec();
    int32_t result = QueryGroups(osAccountId, &queryParams, &groupEntryVec);
    if (result != HC_SUCCESS) {
        LOGE("Failed to query groups!");
        ClearGroupEntryVec(&groupEntryVec);
        return count;
    }
    count = HC_VECTOR_SIZE(&groupEntryVec);
    ClearGroupEntryVec(&groupEntryVec);
    return count;
}

TrustedDeviceEntry *GetTrustedDeviceEntryById(int32_t osAccountId, const char *deviceId, bool isUdid,
    const char *groupId)
{
    QueryDeviceParams params = InitQueryDeviceParams();
    DeviceEntryVec deviceEntryVec = CreateDeviceEntryVec();
    params.groupId = groupId;
    if (isUdid) {
        params.udid = deviceId;
    } else {
        params.authId = deviceId;
    }
    if (QueryDevices(osAccountId, &params, &deviceEntryVec) != HC_SUCCESS) {
        ClearDeviceEntryVec(&deviceEntryVec);
        LOGE("Query trusted devices failed!");
        return NULL;
    }
    uint32_t index;
    TrustedDeviceEntry **deviceEntry;
    FOR_EACH_HC_VECTOR(deviceEntryVec, index, deviceEntry) {
        TrustedDeviceEntry *returnEntry = DeepCopyDeviceEntry(*deviceEntry);
        ClearDeviceEntryVec(&deviceEntryVec);
        return returnEntry;
    }
    ClearDeviceEntryVec(&deviceEntryVec);
    return NULL;
}

TrustedGroupEntry *GetGroupEntryById(int32_t osAccountId, const char *groupId)
{
    if (groupId == NULL) {
        LOGE("The input groupId is NULL!");
        return NULL;
    }
    uint32_t index;
    TrustedGroupEntry **entry = NULL;
    GroupEntryVec groupEntryVec = CreateGroupEntryVec();
    QueryGroupParams params = InitQueryGroupParams();
    params.groupId = groupId;
    if (QueryGroups(osAccountId, &params, &groupEntryVec) != HC_SUCCESS) {
        LOGE("Failed to query groups!");
        ClearGroupEntryVec(&groupEntryVec);
        return NULL;
    }
    FOR_EACH_HC_VECTOR(groupEntryVec, index, entry) {
        TrustedGroupEntry *returnEntry = DeepCopyGroupEntry(*entry);
        ClearGroupEntryVec(&groupEntryVec);
        return returnEntry;
    }
    ClearGroupEntryVec(&groupEntryVec);
    return NULL;
}

bool IsTrustedDeviceInGroup(int32_t osAccountId, const char *groupId, const char *deviceId, bool isUdid)
{
    if ((groupId == NULL) || (deviceId == NULL)) {
        LOGE("The input groupId or deviceId is NULL!");
        return false;
    }
    TrustedDeviceEntry *entry = GetTrustedDeviceEntryById(osAccountId, deviceId, isUdid, groupId);
    if (entry == NULL) {
        return false;
    }
    DestroyDeviceEntry(entry);
    return true;
}

int32_t CheckGroupNumLimit(int32_t osAccountId, int32_t groupType, const char *appId)
{
    /* Currently, only peer to peer group is supported. */
    (void)groupType;
    if (GetGroupNumByOwner(osAccountId, appId) >= HC_TRUST_GROUP_ENTRY_MAX_NUM) {
        LOGE("The number of groups created by the service exceeds the maximum!");
        return HC_ERR_BEYOND_LIMIT;
    }
    return HC_SUCCESS;
}

bool IsLocalDevice(const char *udid)
{
    if (udid == NULL) {
        LOGE("The input udid is NULL!");
        return true;
    }
    char localUdid[INPUT_UDID_LEN] = { 0 };
    int32_t res = HcGetUdid((uint8_t *)localUdid, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local udid! res: %" LOG_PUB "d", res);
        return true;
    }
    return (strcmp(localUdid, udid) == 0);
}

bool IsGroupOwner(int32_t osAccountId, const char *groupId, const char *appId)
{
    if ((groupId == NULL) || (appId == NULL)) {
        LOGE("The input groupId or appId is NULL!");
        return false;
    }
    TrustedGroupEntry *entry = GetGroupEntryById(osAccountId, groupId);
    if (entry == NULL) {
        LOGE("The group cannot be found!");
        return false;
    }
    HcString entryManager = HC_VECTOR_GET(&entry->managers, 0);
    const char *groupOwner = StringGet(&entryManager);
    if (groupOwner == NULL) {
        LOGE("The groupOwner is NULL!");
        DestroyGroupEntry(entry);
        return false;
    }
    if ((strcmp(groupOwner, appId) == 0) ||
        CheckUpgradeIdentity(entry->upgradeFlag, appId, groupOwner) == HC_SUCCESS) {
        DestroyGroupEntry(entry);
        return true;
    }
    DestroyGroupEntry(entry);
    return false;
}

bool IsGroupExistByGroupId(int32_t osAccountId, const char *groupId)
{
    if (groupId == NULL) {
        LOGE("The input groupId is NULL!");
        return false;
    }
    TrustedGroupEntry *entry = GetGroupEntryById(osAccountId, groupId);
    if (entry == NULL) {
        return false;
    }
    DestroyGroupEntry(entry);
    return true;
}

int32_t CheckGroupAccessible(int32_t osAccountId, const char *groupId, const char *appId)
{
    if ((groupId == NULL) || (appId == NULL)) {
        LOGE("GroupId or appId is NULL!");
        return HC_ERR_NULL_PTR;
    }
    TrustedGroupEntry *entry = GetGroupEntryById(osAccountId, groupId);
    if (entry == NULL) {
        LOGE("Group not exist!");
        return HC_ERR_GROUP_NOT_EXIST;
    }
    if ((entry->visibility != GROUP_VISIBILITY_PUBLIC) &&
        (!IsGroupManager(appId, entry)) &&
        (!IsGroupFriend(appId, entry))) {
        DestroyGroupEntry(entry);
        return HC_ERR_ACCESS_DENIED;
    }
    DestroyGroupEntry(entry);
    return HC_SUCCESS;
}

int32_t CheckGroupEditAllowed(int32_t osAccountId, const char *groupId, const char *appId)
{
    if ((groupId == NULL) || (appId == NULL)) {
        LOGE("The input groupId or appId is NULL!");
        return HC_ERR_NULL_PTR;
    }
    TrustedGroupEntry *entry = GetGroupEntryById(osAccountId, groupId);
    if (entry == NULL) {
        LOGE("The group cannot be found!");
        return HC_ERR_GROUP_NOT_EXIST;
    }
    if (!IsGroupManager(appId, entry)) {
        DestroyGroupEntry(entry);
        return HC_ERR_ACCESS_DENIED;
    }
    DestroyGroupEntry(entry);
    return HC_SUCCESS;
}

int32_t GetGroupInfo(int32_t osAccountId, const QueryGroupParams *params, GroupEntryVec *returnGroupEntryVec)
{
    /* Fuzzy query interfaces, so some parameters can be NULL. */
    if (returnGroupEntryVec == NULL) {
        LOGE("The input returnGroupEntryVec is NULL!");
        return HC_ERR_INVALID_PARAMS;
    }
    return QueryGroups(osAccountId, params, returnGroupEntryVec);
}

int32_t GetJoinedGroups(int32_t osAccountId, int groupType, GroupEntryVec *returnGroupEntryVec)
{
    QueryGroupParams params = InitQueryGroupParams();
    params.groupType = (uint32_t)groupType;
    return QueryGroups(osAccountId, &params, returnGroupEntryVec);
}

int32_t GetRelatedGroups(int32_t osAccountId, const char *peerDeviceId, bool isUdid, GroupEntryVec *returnGroupEntryVec)
{
    uint32_t index;
    TrustedDeviceEntry **entry = NULL;
    DeviceEntryVec deviceEntryVec = CreateDeviceEntryVec();
    QueryDeviceParams params = InitQueryDeviceParams();
    params.groupId = NULL;
    if (isUdid) {
        params.udid = peerDeviceId;
    } else {
        params.authId = peerDeviceId;
    }
    int32_t result = QueryDevices(osAccountId, &params, &deviceEntryVec);
    if (result != HC_SUCCESS) {
        LOGE("Failed to query trusted devices!");
        ClearDeviceEntryVec(&deviceEntryVec);
        return result;
    }
    FOR_EACH_HC_VECTOR(deviceEntryVec, index, entry) {
        TrustedGroupEntry *groupEntry = GetGroupEntryById(osAccountId, StringGet(&(*entry)->groupId));
        if (groupEntry == NULL) {
            LOGE("Failed to get group entry by id!");
            ClearDeviceEntryVec(&deviceEntryVec);
            return HC_ERR_GROUP_NOT_EXIST;
        }
        if (returnGroupEntryVec->pushBackT(returnGroupEntryVec, groupEntry) == NULL) {
            DestroyGroupEntry(groupEntry);
            ClearDeviceEntryVec(&deviceEntryVec);
            return HC_ERR_MEMORY_COPY;
        }
    }
    ClearDeviceEntryVec(&deviceEntryVec);
    return HC_SUCCESS;
}

int32_t GetTrustedDevInfoById(int32_t osAccountId, const char *deviceId, bool isUdid, const char *groupId,
    TrustedDeviceEntry *returnDeviceEntry)
{
    if ((deviceId == NULL) || (groupId == NULL) || (returnDeviceEntry == NULL)) {
        LOGE("The input parameters contain NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    TrustedDeviceEntry *deviceEntry = GetTrustedDeviceEntryById(osAccountId, deviceId, isUdid, groupId);
    if (deviceEntry == NULL) {
        LOGE("The trusted device is not found!");
        return HC_ERR_DEVICE_NOT_EXIST;
    }
    int32_t result = GenerateDeviceEntryFromEntry(deviceEntry, returnDeviceEntry) ? HC_SUCCESS : HC_ERR_MEMORY_COPY;
    DestroyDeviceEntry(deviceEntry);
    return result;
}

int32_t GetTrustedDevices(int32_t osAccountId, const char *groupId, DeviceEntryVec *returnDeviceEntryVec)
{
    QueryDeviceParams params = InitQueryDeviceParams();
    params.groupId = groupId;
    return QueryDevices(osAccountId, &params, returnDeviceEntryVec);
}

bool IsAccountRelatedGroup(int groupType)
{
    return ((groupType == IDENTICAL_ACCOUNT_GROUP) || (groupType == ACROSS_ACCOUNT_AUTHORIZE_GROUP));
}

int32_t GetHashMessage(const Uint8Buff *first, const Uint8Buff *second, uint8_t **hashMessage, uint32_t *messageSize)
{
    if ((first == NULL) || (second == NULL) || (hashMessage == NULL) || (messageSize == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_NULL_PTR;
    }
    const char *separator = "|";
    uint32_t firstSize = first->length;
    uint32_t secondSize = second->length;
    uint32_t separatorSize = HcStrlen(separator);
    uint32_t totalSize = firstSize + secondSize + separatorSize;
    *hashMessage = (uint8_t *)HcMalloc(totalSize, 0);
    if (*hashMessage == NULL) {
        LOGE("Failed to allocate hashMessage memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t result = HC_SUCCESS;
    do {
        if (memcpy_s((*hashMessage), totalSize, first->val, firstSize) != HC_SUCCESS) {
            LOGE("Failed to copy first!");
            result = HC_ERR_MEMORY_COPY;
            break;
        }
        if (memcpy_s((*hashMessage) + firstSize, totalSize - firstSize, separator, separatorSize) != HC_SUCCESS) {
            LOGE("Failed to copy separator!");
            result = HC_ERR_MEMORY_COPY;
            break;
        }
        if (memcpy_s((*hashMessage) + firstSize + separatorSize, secondSize, second->val, secondSize) != HC_SUCCESS) {
            LOGE("Failed to copy second!");
            result = HC_ERR_MEMORY_COPY;
        }
    } while (0);
    if (result != HC_SUCCESS) {
        HcFree(*hashMessage);
        *hashMessage = NULL;
        return result;
    }
    *messageSize = totalSize;
    return HC_SUCCESS;
}

uint32_t GetCurDeviceNumByGroupId(int32_t osAccountId, const char *groupId)
{
    if (groupId == NULL) {
        LOGE("The input groupId is NULL!");
        return 0;
    }
    uint32_t count = 0;
    QueryDeviceParams queryDeviceParams = InitQueryDeviceParams();
    queryDeviceParams.groupId = groupId;
    DeviceEntryVec deviceEntryVec = CreateDeviceEntryVec();
    int32_t result = QueryDevices(osAccountId, &queryDeviceParams, &deviceEntryVec);
    if (result != HC_SUCCESS) {
        LOGE("Failed to query trusted devices!");
        ClearDeviceEntryVec(&deviceEntryVec);
        return result;
    }
    count = HC_VECTOR_SIZE(&deviceEntryVec);
    ClearDeviceEntryVec(&deviceEntryVec);
    return count;
}

int32_t CheckDeviceNumLimit(int32_t osAccountId, const char *groupId, const char *peerUdid)
{
    /*
     * If the peer device does not exist in the group and needs to be added,
     * check whether the number of trusted devices exceeds the upper limit.
     */

    if ((peerUdid != NULL) && (IsTrustedDeviceInGroup(osAccountId, groupId, peerUdid, true))) {
        return HC_SUCCESS;
    }
    if (GetCurDeviceNumByGroupId(osAccountId, groupId) >= HC_TRUST_DEV_ENTRY_MAX_NUM) {
        LOGE("The number of devices in the group has reached the upper limit!");
        return HC_ERR_BEYOND_LIMIT;
    }
    return HC_SUCCESS;
}

bool IsUserTypeValid(int userType)
{
    if ((userType == DEVICE_TYPE_ACCESSORY) ||
        (userType == DEVICE_TYPE_CONTROLLER) ||
        (userType == DEVICE_TYPE_PROXY)) {
        return true;
    }
    return false;
}

bool IsExpireTimeValid(int expireTime)
{
    if ((expireTime < -1) || (expireTime == 0) || (expireTime > MAX_EXPIRE_TIME)) {
        return false;
    }
    return true;
}

bool IsGroupVisibilityValid(int groupVisibility)
{
    /* Currently, only the public group and private group can be created. */
    if ((groupVisibility == GROUP_VISIBILITY_PUBLIC) ||
        ((groupVisibility == GROUP_VISIBILITY_PRIVATE))) {
        return true;
    }
    return false;
}

int32_t CheckUserTypeIfExist(const CJson *jsonParams)
{
    int32_t userType = DEVICE_TYPE_ACCESSORY;
    (void)GetIntFromJson(jsonParams, FIELD_USER_TYPE, &userType);
    if (!IsUserTypeValid(userType)) {
        LOGE("The input userType is invalid! [UserType]: %" LOG_PUB "d", userType);
        return HC_ERR_INVALID_PARAMS;
    }
    return HC_SUCCESS;
}

int32_t CheckGroupVisibilityIfExist(const CJson *jsonParams)
{
    int32_t groupVisibility = GROUP_VISIBILITY_PUBLIC;
    (void)GetIntFromJson(jsonParams, FIELD_GROUP_VISIBILITY, &groupVisibility);
    if (!IsGroupVisibilityValid(groupVisibility)) {
        LOGE("The input groupVisibility is invalid! [GroupVisibility]: %" LOG_PUB "d", groupVisibility);
        return HC_ERR_INVALID_PARAMS;
    }
    return HC_SUCCESS;
}

int32_t CheckExpireTimeIfExist(const CJson *jsonParams)
{
    int32_t expireTime = DEFAULT_EXPIRE_TIME;
    (void)GetIntFromJson(jsonParams, FIELD_EXPIRE_TIME, &expireTime);
    if (!IsExpireTimeValid(expireTime)) {
        LOGE("Invalid group expire time! [ExpireTime]: %" LOG_PUB "d", expireTime);
        return HC_ERR_INVALID_PARAMS;
    }
    return HC_SUCCESS;
}

int32_t AddGroupNameToParams(const char *groupName, TrustedGroupEntry *groupParams)
{
    if (!StringSetPointer(&groupParams->name, groupName)) {
        LOGE("Failed to copy groupName!");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

int32_t AddGroupIdToParams(const char *groupId, TrustedGroupEntry *groupParams)
{
    if (!StringSetPointer(&groupParams->id, groupId)) {
        LOGE("Failed to copy groupId!");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

int32_t AddGroupOwnerToParams(const char *owner, TrustedGroupEntry *groupParams)
{
    HcString ownerName = CreateString();
    if (!StringSetPointer(&ownerName, owner)) {
        LOGE("Failed to copy groupOwner to ownerName!");
        DeleteString(&ownerName);
        return HC_ERR_MEMORY_COPY;
    }
    if (groupParams->managers.pushBackT(&groupParams->managers, ownerName) == NULL) {
        LOGE("Failed to push ownerName to managers vec!");
        DeleteString(&ownerName);
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

int32_t AddGroupTypeToParams(uint32_t groupType, TrustedGroupEntry *groupParams)
{
    groupParams->type = groupType;
    return HC_SUCCESS;
}

int32_t AddGroupVisibilityOrDefault(const CJson *jsonParams, TrustedGroupEntry *groupParams)
{
    /* Currently, only the public group and private group can be created. */
    int32_t groupVisibility = GROUP_VISIBILITY_PUBLIC;
    (void)GetIntFromJson(jsonParams, FIELD_GROUP_VISIBILITY, &groupVisibility);
    groupParams->visibility = groupVisibility;
    return HC_SUCCESS;
}

int32_t AddExpireTimeOrDefault(const CJson *jsonParams, TrustedGroupEntry *groupParams)
{
    int32_t expireTime = DEFAULT_EXPIRE_TIME;
    (void)GetIntFromJson(jsonParams, FIELD_EXPIRE_TIME, &expireTime);
    groupParams->expireTime = expireTime;
    return HC_SUCCESS;
}

int32_t AddUserIdToGroupParams(const CJson *jsonParams, TrustedGroupEntry *groupParams)
{
    char *userId = NULL;
    int32_t result = GetUserIdFromJson(jsonParams, &userId);
    if (result != HC_SUCCESS) {
        return result;
    }
    if (!StringSetPointer(&groupParams->userId, userId)) {
        LOGE("Failed to copy userId!");
        HcFree(userId);
        return HC_ERR_MEMORY_COPY;
    }
    HcFree(userId);
    return HC_SUCCESS;
}

int32_t AddSharedUserIdToGroupParams(const CJson *jsonParams, TrustedGroupEntry *groupParams)
{
    char *sharedUserId = NULL;
    int32_t result = GetSharedUserIdFromJson(jsonParams, &sharedUserId);
    if (result != HC_SUCCESS) {
        return result;
    }
    if (!StringSetPointer(&groupParams->sharedUserId, sharedUserId)) {
        LOGE("Failed to copy sharedUserId!");
        HcFree(sharedUserId);
        return HC_ERR_MEMORY_COPY;
    }
    HcFree(sharedUserId);
    return HC_SUCCESS;
}

int32_t AddSelfUdidToParams(TrustedDeviceEntry *devParams)
{
    char udid[INPUT_UDID_LEN] = { 0 };
    int32_t res = HcGetUdid((uint8_t *)udid, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local udid! res: %" LOG_PUB "d", res);
        return HC_ERR_DB;
    }
    if (!StringSetPointer(&devParams->udid, udid)) {
        LOGE("Failed to copy udid!");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

int32_t AddUdidToParams(const CJson *jsonParams, TrustedDeviceEntry *devParams)
{
    const char *udid = GetStringFromJson(jsonParams, FIELD_UDID);
    if (udid == NULL) {
        LOGE("Failed to get udid from json!");
        return HC_ERR_JSON_GET;
    }
    if (!StringSetPointer(&devParams->udid, udid)) {
        LOGE("Failed to copy udid!");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

int32_t AddAuthIdToParamsOrDefault(const CJson *jsonParams, TrustedDeviceEntry *devParams)
{
    const char *authId = GetStringFromJson(jsonParams, FIELD_DEVICE_ID);
    char udid[INPUT_UDID_LEN] = { 0 };
    if (authId == NULL) {
        LOGD("No authId is found. The default value is udid!");
        int32_t res = HcGetUdid((uint8_t *)udid, INPUT_UDID_LEN);
        if (res != HC_SUCCESS) {
            LOGE("Failed to get local Udid! res: %" LOG_PUB "d", res);
            return HC_ERR_DB;
        }
        authId = udid;
    }
    if (!StringSetPointer(&devParams->authId, authId)) {
        LOGE("Failed to copy authId!");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

int32_t AddAuthIdToParams(const CJson *jsonParams, TrustedDeviceEntry *devParams)
{
    const char *authId = GetStringFromJson(jsonParams, FIELD_DEVICE_ID);
    if (authId == NULL) {
        LOGE("Failed to get authId from json!");
        return HC_ERR_JSON_GET;
    }
    if (!StringSetPointer(&devParams->authId, authId)) {
        LOGE("Failed to copy authId!");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

int32_t AddSourceToParams(RelationShipSource source, TrustedDeviceEntry *devParams)
{
    devParams->source = source;
    return HC_SUCCESS;
}

int32_t AddCredTypeToParams(const CJson *jsonParams, TrustedDeviceEntry *devParams)
{
    int32_t credType = INVALID_CRED;
    if (GetIntFromJson(jsonParams, FIELD_CREDENTIAL_TYPE, &credType) != HC_SUCCESS) {
        LOGE("Failed to get credentialType from json!");
        return HC_ERR_JSON_GET;
    }
    devParams->credential = (uint8_t)credType;
    return HC_SUCCESS;
}

int32_t AddUserTypeToParamsOrDefault(const CJson *jsonParams, TrustedDeviceEntry *devParams)
{
    int32_t userType = DEVICE_TYPE_ACCESSORY;
    (void)GetIntFromJson(jsonParams, FIELD_USER_TYPE, &userType);
    devParams->devType = userType;
    return HC_SUCCESS;
}

int32_t AddServiceTypeToParams(const char *groupId, TrustedDeviceEntry *devParams)
{
    if (!StringSetPointer(&devParams->serviceType, groupId)) {
        LOGE("Failed to copy serviceType!");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

int32_t AddGroupIdToDevParams(const char *groupId, TrustedDeviceEntry *devParams)
{
    if (!StringSetPointer(&devParams->groupId, groupId)) {
        LOGE("Failed to copy groupId!");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

int32_t AddUserIdToDevParams(const CJson *jsonParams, TrustedDeviceEntry *devParams)
{
    char *userId = NULL;
    int32_t result = GetUserIdFromJson(jsonParams, &userId);
    if (result != HC_SUCCESS) {
        return result;
    }
    if (!StringSetPointer(&devParams->userId, userId)) {
        LOGE("Failed to copy userId!");
        HcFree(userId);
        return HC_ERR_MEMORY_COPY;
    }
    HcFree(userId);
    return HC_SUCCESS;
}

int32_t AssertUserIdExist(const CJson *jsonParams)
{
    const char *userId = GetStringFromJson(jsonParams, FIELD_USER_ID);
    if (userId == NULL) {
        LOGE("Failed to get userId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    return HC_SUCCESS;
}

int32_t AssertSameGroupNotExist(int32_t osAccountId, const char *groupId)
{
    if (IsGroupExistByGroupId(osAccountId, groupId)) {
        LOGE("The group has been created!");
        return HC_ERR_GROUP_DUPLICATE;
    }
    return HC_SUCCESS;
}

int32_t AssertPeerDeviceNotSelf(const char *peerUdid)
{
    if (peerUdid == NULL) {
        LOGE("The input peerUdid is NULL!");
        return HC_ERR_NULL_PTR;
    }
    char udid[INPUT_UDID_LEN] = { 0 };
    int32_t res = HcGetUdid((uint8_t *)udid, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local udid! res: %" LOG_PUB "d", res);
        return HC_ERR_DB;
    }
    if (strcmp(peerUdid, udid) == 0) {
        LOGE("You are not allowed to delete yourself!");
        return HC_ERR_INVALID_PARAMS;
    }
    return HC_SUCCESS;
}

int32_t CheckGroupExist(int32_t osAccountId, const char *groupId)
{
    if (groupId == NULL) {
        LOGE("The input groupId is NULL!");
        return HC_ERR_NULL_PTR;
    }
    if (!IsGroupExistByGroupId(osAccountId, groupId)) {
        LOGE("The group does not exist! [GroupId]: %" LOG_PUB "s", groupId);
        return HC_ERR_GROUP_NOT_EXIST;
    }
    return HC_SUCCESS;
}

int32_t AddGroupToDatabaseByJson(int32_t osAccountId, int32_t (*generateGroupParams)(const CJson*, const char *,
    TrustedGroupEntry*), const CJson *jsonParams, const char *groupId)
{
    if ((generateGroupParams == NULL) || (jsonParams == NULL) || (groupId == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    TrustedGroupEntry *groupParams = CreateGroupEntry();
    if (groupParams == NULL) {
        LOGE("Failed to allocate groupParams memory!");
        return HC_ERR_ALLOC_MEMORY;
    }

    int32_t result = (*generateGroupParams)(jsonParams, groupId, groupParams);
    if (result != HC_SUCCESS) {
        DestroyGroupEntry(groupParams);
        return result;
    }

    result = AddGroup(osAccountId, groupParams);
    DestroyGroupEntry(groupParams);
    if (result != HC_SUCCESS) {
        LOGE("Failed to add the group to the database!");
    }
    return result;
}

int32_t AddDeviceToDatabaseByJson(int32_t osAccountId, int32_t (*generateDevParams)(const CJson*, const char*,
    TrustedDeviceEntry*), const CJson *jsonParams, const char *groupId)
{
    if ((generateDevParams == NULL) || (jsonParams == NULL) || (groupId == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    TrustedDeviceEntry *devParams = CreateDeviceEntry();
    if (devParams == NULL) {
        LOGE("Failed to allocate devParams memory!");
        return HC_ERR_ALLOC_MEMORY;
    }

    int32_t result = (*generateDevParams)(jsonParams, groupId, devParams);
    if (result != HC_SUCCESS) {
        DestroyDeviceEntry(devParams);
        return result;
    }

    result = AddTrustedDevice(osAccountId, devParams);
    DestroyDeviceEntry(devParams);
    if (result != HC_SUCCESS) {
        LOGE("Failed to add the trust device to the database!");
    }
    return result;
}

int32_t DelGroupFromDb(int32_t osAccountId, const char *groupId)
{
    if (groupId == NULL) {
        LOGE("The input groupId is NULL!");
        return HC_ERR_NULL_PTR;
    }
    QueryGroupParams queryGroupParams = InitQueryGroupParams();
    queryGroupParams.groupId = groupId;
    QueryDeviceParams queryDeviceParams = InitQueryDeviceParams();
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

int32_t DelDeviceFromDb(int32_t osAccountId, const char *groupId, const TrustedDeviceEntry *deviceEntry)
{
    if (groupId == NULL || deviceEntry == NULL) {
        LOGE("The input groupId or deviceEntry is NULL!");
        return HC_ERR_NULL_PTR;
    }
    const char *udid = StringGet(&deviceEntry->udid);
    if (udid == NULL) {
        LOGE("The input udid is NULL!");
        return HC_ERR_NULL_PTR;
    }
    QueryDeviceParams queryDeviceParams = InitQueryDeviceParams();
    queryDeviceParams.groupId = groupId;
    queryDeviceParams.udid = udid;
    int32_t result = DelTrustedDevice(osAccountId, &queryDeviceParams);
    if (result != HC_SUCCESS) {
        LOGW("delete device failed, result:%" LOG_PUB "d", result);
        return result;
    }
    return SaveOsAccountDb(osAccountId);
}

int32_t ConvertGroupIdToJsonStr(const char *groupId, char **returnJsonStr)
{
    if ((groupId == NULL) || (returnJsonStr == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    CJson *json = CreateJson();
    if (json == NULL) {
        LOGE("Failed to allocate json memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (AddStringToJson(json, FIELD_GROUP_ID, groupId) != HC_SUCCESS) {
        LOGE("Failed to add groupId to json!");
        FreeJson(json);
        return HC_ERR_JSON_FAIL;
    }
    *returnJsonStr = PackJsonToString(json);
    FreeJson(json);
    if (*returnJsonStr == NULL) {
        LOGE("Failed to convert json to string!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

int32_t GenerateBindSuccessData(const char *peerAuthId, const char *peerUdid,
    const char *groupId, char **returnDataStr)
{
    if ((peerAuthId == NULL) || (peerUdid == NULL) || (groupId == NULL) || (returnDataStr == NULL)) {
        LOGE("The input params contains NULL value!");
        return HC_ERR_NULL_PTR;
    }
    PRINT_SENSITIVE_DATA("GroupId", groupId);
    PRINT_SENSITIVE_DATA("PeerAuthId", peerAuthId);
    PRINT_SENSITIVE_DATA("PeerUdid", peerUdid);
    CJson *jsonData = CreateJson();
    if (jsonData == NULL) {
        LOGE("Allocate json data memory failed!");
        return HC_ERR_JSON_FAIL;
    }
    if (AddStringToJson(jsonData, FIELD_GROUP_ID, groupId) != HC_SUCCESS) {
        LOGE("Add groupId to json data failed!");
        FreeJson(jsonData);
        return HC_ERR_JSON_FAIL;
    }
    if (AddStringToJson(jsonData, FIELD_ADD_ID, peerAuthId) != HC_SUCCESS) {
        LOGE("Add addId to json data failed!");
        FreeJson(jsonData);
        return HC_ERR_JSON_FAIL;
    }
    char *jsonDataStr = PackJsonToString(jsonData);
    FreeJson(jsonData);
    if (jsonDataStr == NULL) {
        LOGE("Error occurred when converting JSON data to String data!");
        return HC_ERR_JSON_FAIL;
    }
    *returnDataStr = jsonDataStr;
    return HC_SUCCESS;
}

int32_t GenerateUnbindSuccessData(const char *peerAuthId, const char *groupId, char **returnDataStr)
{
    if ((peerAuthId == NULL) || (groupId == NULL) || (returnDataStr == NULL)) {
        LOGE("The input params contains NULL value!");
        return HC_ERR_NULL_PTR;
    }
    PRINT_SENSITIVE_DATA("GroupId", groupId);
    PRINT_SENSITIVE_DATA("PeerAuthId", peerAuthId);
    CJson *jsonData = CreateJson();
    if (jsonData == NULL) {
        LOGE("Failed to allocate jsonData memory!");
        return HC_ERR_JSON_FAIL;
    }
    if (AddStringToJson(jsonData, FIELD_GROUP_ID, groupId) != HC_SUCCESS) {
        LOGE("Failed to add groupId to jsonData!");
        FreeJson(jsonData);
        return HC_ERR_JSON_FAIL;
    }
    if (AddStringToJson(jsonData, FIELD_DELETE_ID, peerAuthId) != HC_SUCCESS) {
        LOGE("Failed to add deleteId to jsonData!");
        FreeJson(jsonData);
        return HC_ERR_JSON_FAIL;
    }
    char *jsonDataStr = PackJsonToString(jsonData);
    FreeJson(jsonData);
    if (jsonDataStr == NULL) {
        LOGE("Error occurred, convert JSON data to String data failed!");
        return HC_ERR_JSON_FAIL;
    }
    *returnDataStr = jsonDataStr;
    return HC_SUCCESS;
}

int32_t ProcessKeyPair(int32_t osAccountId, int action, const CJson *jsonParams, const char *groupId)
{
    if ((jsonParams == NULL) || (groupId == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    /* Use the DeviceGroupManager package name. */
    const char *appId = GROUP_MANAGER_PACKAGE_NAME;
    const char *authId = GetStringFromJson(jsonParams, FIELD_DEVICE_ID);
    char udid[INPUT_UDID_LEN] = { 0 };
    if (authId == NULL) {
        LOGD("No authId is found. The default value is udid!");
        int32_t res = HcGetUdid((uint8_t *)udid, INPUT_UDID_LEN);
        if (res != HC_SUCCESS) {
            LOGE("Failed to get local udid! res: %" LOG_PUB "d!", res);
            return HC_ERR_DB;
        }
        authId = udid;
    }
    int32_t userType = DEVICE_TYPE_ACCESSORY;
    (void)GetIntFromJson(jsonParams, FIELD_USER_TYPE, &userType);
    Uint8Buff authIdBuff = { 0, 0 };
    authIdBuff.length = HcStrlen(authId);
    if (authIdBuff.length > MAX_DATA_BUFFER_SIZE) {
        LOGE("The length of authId is too long!");
        return HC_ERR_INVALID_PARAMS;
    }
    authIdBuff.val = (uint8_t *)HcMalloc(authIdBuff.length, 0);
    if (authIdBuff.val == NULL) {
        LOGE("Allocate authIdBuff memory failed!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (memcpy_s(authIdBuff.val, authIdBuff.length, authId, authIdBuff.length) != EOK) {
        LOGE("Copy authId to buff failed!");
        HcFree(authIdBuff.val);
        return HC_ERR_MEMORY_COPY;
    }
    AuthModuleParams params = { osAccountId, appId, groupId, &authIdBuff, userType };
    int32_t result;
    if (action == CREATE_KEY_PAIR) {
        result = RegisterLocalIdentity(&params, DAS_MODULE);
    } else {
        result = UnregisterLocalIdentity(&params, DAS_MODULE);
    }
    HcFree(authIdBuff.val);
    return result;
}

int32_t GetGroupTypeFromDb(int32_t osAccountId, const char *groupId, uint32_t *returnGroupType)
{
    if ((groupId == NULL) || (returnGroupType == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    TrustedGroupEntry *groupEntry = GetGroupEntryById(osAccountId, groupId);
    if (groupEntry == NULL) {
        LOGE("Failed to get groupEntry from db!");
        return HC_ERR_DB;
    }
    *returnGroupType = groupEntry->type;
    DestroyGroupEntry(groupEntry);
    return HC_SUCCESS;
}

int32_t GetUserIdFromJson(const CJson *jsonParams, char **userId)
{
    if ((jsonParams == NULL) || (userId == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    const char *oriUserId = GetStringFromJson(jsonParams, FIELD_USER_ID);
    if (oriUserId == NULL) {
        LOGE("Failed to get userId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    return ToUpperCase(oriUserId, userId);
}

int32_t GetSharedUserIdFromJson(const CJson *jsonParams, char **sharedUserId)
{
    if ((jsonParams == NULL) || (sharedUserId == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    const char *oriUserId = GetStringFromJson(jsonParams, FIELD_PEER_USER_ID);
    if (oriUserId == NULL) {
        LOGE("Failed to get sharedUserId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    return ToUpperCase(oriUserId, sharedUserId);
}

int32_t GetGroupIdFromJson(const CJson *jsonParams, const char **groupId)
{
    if ((jsonParams == NULL) || (groupId == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    *groupId = GetStringFromJson(jsonParams, FIELD_GROUP_ID);
    if (*groupId == NULL) {
        LOGE("Failed to get groupId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    return HC_SUCCESS;
}

int32_t GetAppIdFromJson(const CJson *jsonParams, const char **appId)
{
    if ((jsonParams == NULL) || (appId == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HC_ERR_INVALID_PARAMS;
    }
    *appId = GetStringFromJson(jsonParams, FIELD_APP_ID);
    if (*appId == NULL) {
        LOGE("Failed to get appId from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    return HC_SUCCESS;
}

int32_t AssertGroupTypeMatch(int32_t inputType, int32_t targetType)
{
    if (inputType != targetType) {
        LOGE("Invalid group type! [InputType]: %" LOG_PUB "d, [TargetType]: %" LOG_PUB "d", inputType, targetType);
        return HC_ERR_INVALID_PARAMS;
    }
    return HC_SUCCESS;
}

int32_t CheckPermForGroup(int32_t osAccountId, int actionType, const char *callerPkgName, const char *groupId)
{
    if (((actionType == GROUP_DISBAND) && (IsGroupOwner(osAccountId, groupId, callerPkgName))) ||
        ((actionType == MEMBER_INVITE) && (CheckGroupEditAllowed(osAccountId, groupId, callerPkgName) == HC_SUCCESS)) ||
        ((actionType == MEMBER_DELETE) && (CheckGroupEditAllowed(osAccountId, groupId, callerPkgName) == HC_SUCCESS))) {
        return HC_SUCCESS;
    }
    LOGE("You do not have the right to execute the command!");
    return HC_ERR_ACCESS_DENIED;
}

int32_t GetHashResult(const uint8_t *info, uint32_t infoLen, char *hash, uint32_t hashLen)
{
    if ((info == NULL) || (hash == NULL)) {
        LOGE("The input parameters contains NULL value!");
        return HAL_ERR_NULL_PTR;
    }
    Uint8Buff infoHash = { NULL, SHA256_LEN };
    Uint8Buff message = { NULL, infoLen };
    infoHash.val = (uint8_t *)HcMalloc(SHA256_LEN, 0);
    if (infoHash.val == NULL) {
        LOGE("Failed to allocate infoHash.val memory!");
        return HAL_ERR_BAD_ALLOC;
    }
    message.val = (uint8_t *)HcMalloc(infoLen, 0);
    if (message.val == NULL) {
        LOGE("Failed to allocate message.val memory!");
        HcFree(infoHash.val);
        return HAL_ERR_BAD_ALLOC;
    }
    if (memcpy_s(message.val, infoLen, info, infoLen) != EOK) {
        LOGE("Failed to copy info!");
        HcFree(infoHash.val);
        HcFree(message.val);
        return HAL_ERR_MEMORY_COPY;
    }
    int32_t result = GetLoaderInstance()->sha256(&message, &infoHash);
    if (result == HAL_SUCCESS) {
        if (ByteToHexString(infoHash.val, infoHash.length, hash, hashLen) != HAL_SUCCESS) {
            LOGE("Failed to convert bytes to string!");
            result = HAL_ERR_BUILD_PARAM_SET_FAILED;
        }
    }
    HcFree(infoHash.val);
    HcFree(message.val);
    return result;
}

int32_t AddGroupInfoToContextByDb(const char *groupId, CJson *context)
{
    int32_t osAccountId;
    if (GetIntFromJson(context, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("get osAccountId from json fail.");
        return HC_ERR_JSON_GET;
    }
    TrustedGroupEntry *entry = GetGroupEntryById(osAccountId, groupId);
    if (entry == NULL) {
        LOGE("Failed to get groupEntry from db!");
        return HC_ERR_DB;
    }
    if (AddStringToJson(context, FIELD_GROUP_ID, StringGet(&entry->id)) != HC_SUCCESS) {
        LOGE("Failed to add groupId to json!");
        DestroyGroupEntry(entry);
        return HC_ERR_JSON_FAIL;
    }
    if (AddIntToJson(context, FIELD_GROUP_TYPE, entry->type) != HC_SUCCESS) {
        LOGE("Failed to add groupType to json!");
        DestroyGroupEntry(entry);
        return HC_ERR_JSON_FAIL;
    }
    if (AddStringToJson(context, FIELD_GROUP_NAME, StringGet(&entry->name)) != HC_SUCCESS) {
        LOGE("Failed to add groupName to json!");
        DestroyGroupEntry(entry);
        return HC_ERR_JSON_FAIL;
    }
    DestroyGroupEntry(entry);
    return HC_SUCCESS;
}

int32_t AddDevInfoToContextByDb(const char *groupId, CJson *context)
{
    int32_t osAccountId;
    if (GetIntFromJson(context, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("get osAccountId from json fail.");
        return HC_ERR_JSON_GET;
    }
    char udid[INPUT_UDID_LEN] = { 0 };
    int32_t res = HcGetUdid((uint8_t *)udid, INPUT_UDID_LEN);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get local udid! res: %" LOG_PUB "d", res);
        return HC_ERR_DB;
    }
    TrustedDeviceEntry *devAuthParams = CreateDeviceEntry();
    if (devAuthParams == NULL) {
        LOGE("Failed to allocate devEntry memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if (GetTrustedDevInfoById(osAccountId, udid, true, groupId, devAuthParams) != HC_SUCCESS) {
        LOGE("Failed to obtain the local device information from the database!");
        DestroyDeviceEntry(devAuthParams);
        return HC_ERR_DB;
    }
    if (AddStringToJson(context, FIELD_AUTH_ID, StringGet(&devAuthParams->authId)) != HC_SUCCESS) {
        LOGE("Failed to add authId to params!");
        DestroyDeviceEntry(devAuthParams);
        return HC_ERR_JSON_FAIL;
    }
    if (AddIntToJson(context, FIELD_USER_TYPE, devAuthParams->devType) != HC_SUCCESS) {
        LOGE("Failed to add userType to params!");
        DestroyDeviceEntry(devAuthParams);
        return HC_ERR_JSON_FAIL;
    }
    DestroyDeviceEntry(devAuthParams);
    return HC_SUCCESS;
}

int32_t AddGroupInfoToContextByInput(const CJson *receivedMsg, CJson *context)
{
    const char *groupId = GetStringFromJson(receivedMsg, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("get groupId from json fail.");
        return HC_ERR_JSON_GET;
    }
    const char *groupName = GetStringFromJson(receivedMsg, FIELD_GROUP_NAME);
    if (groupName == NULL) {
        LOGE("Failed to get groupName from jsonParams!");
        return HC_ERR_JSON_GET;
    }
    if (AddStringToJson(context, FIELD_GROUP_ID, groupId) != HC_SUCCESS) {
        LOGE("Failed to add groupId to json!");
        return HC_ERR_JSON_FAIL;
    }
    if (AddIntToJson(context, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP) != HC_SUCCESS) {
        LOGE("Failed to add groupType to json!");
        return HC_ERR_JSON_FAIL;
    }
    if (AddStringToJson(context, FIELD_GROUP_NAME, groupName) != HC_SUCCESS) {
        LOGE("Failed to add groupName to json!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

int32_t AddDevInfoToContextByInput(CJson *context)
{
    int32_t userType = DEVICE_TYPE_ACCESSORY;
    (void)GetIntFromJson(context, FIELD_USER_TYPE, &userType);
    const char *authId = GetStringFromJson(context, FIELD_DEVICE_ID);
    char udid[INPUT_UDID_LEN] = { 0 };
    if (authId == NULL) {
        LOGD("The authId is not found. The default value is udid!");
        int32_t res = HcGetUdid((uint8_t *)udid, INPUT_UDID_LEN);
        if (res != HC_SUCCESS) {
            LOGE("Error occurs, failed to get local udid! res: %" LOG_PUB "d", res);
            return HC_ERR_DB;
        }
        authId = udid;
    }
    if (AddStringToJson(context, FIELD_AUTH_ID, authId) != HC_SUCCESS) {
        LOGE("Failed to add authId to params!");
        return HC_ERR_JSON_FAIL;
    }
    if (AddIntToJson(context, FIELD_USER_TYPE, userType) != HC_SUCCESS) {
        LOGE("Failed to add userType to params!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t IsDeviceIdHashMatch(const char *udid, const char *subUdidHash)
{
    Uint8Buff udidBuf = { (uint8_t *)udid, (uint32_t)HcStrlen(udid) };
    uint8_t udidHashByte[SHA256_LEN] = { 0 };
    Uint8Buff udidHashBuf = { udidHashByte, sizeof(udidHashByte) };
    int32_t ret = GetLoaderInstance()->sha256(&udidBuf, &udidHashBuf);
    if (ret != HC_SUCCESS) {
        LOGE("sha256 failed, ret:%" LOG_PUB "d", ret);
        return ret;
    }
    uint32_t udidHashLen = SHA256_LEN * BYTE_TO_HEX_OPER_LENGTH + 1;
    char *udidHash = (char *)HcMalloc(udidHashLen, 0);
    if (udidHash == NULL) {
        LOGE("malloc udidHash string failed");
        return HC_ERR_ALLOC_MEMORY;
    }
    ret = ByteToHexString(udidHashByte, SHA256_LEN, udidHash, udidHashLen);
    if (ret != HC_SUCCESS) {
        LOGE("Byte to hexString failed, ret:%" LOG_PUB "d", ret);
        HcFree(udidHash);
        return ret;
    }
    char *subUdidHashUpper = NULL;
    ret = ToUpperCase(subUdidHash, &subUdidHashUpper);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to convert the input sub udid hash to upper case!");
        HcFree(udidHash);
        return ret;
    }
    if (strstr((const char *)udidHash, subUdidHashUpper) != NULL) {
        LOGI("udid hash is match!");
        HcFree(udidHash);
        HcFree(subUdidHashUpper);
        return HC_SUCCESS;
    }
    HcFree(udidHash);
    HcFree(subUdidHashUpper);
    return HC_ERROR;
}

static const char *GetUdidByGroup(int32_t osAccountId, const char *groupId, const char *deviceIdHash)
{
    uint32_t index;
    TrustedDeviceEntry **deviceEntry = NULL;
    DeviceEntryVec deviceEntryVec = CREATE_HC_VECTOR(DeviceEntryVec);
    QueryDeviceParams params = InitQueryDeviceParams();
    params.groupId = groupId;
    if (QueryDevices(osAccountId, &params, &deviceEntryVec) != HC_SUCCESS) {
        LOGE("query trusted devices failed!");
        ClearDeviceEntryVec(&deviceEntryVec);
        return NULL;
    }
    FOR_EACH_HC_VECTOR(deviceEntryVec, index, deviceEntry) {
        const char *udid = StringGet(&(*deviceEntry)->udid);
        if (IsDeviceIdHashMatch(udid, deviceIdHash) == HC_SUCCESS) {
            ClearDeviceEntryVec(&deviceEntryVec);
            return udid;
        }
        continue;
    }
    ClearDeviceEntryVec(&deviceEntryVec);
    return NULL;
}

static const char *GetDeviceIdByUdidHash(int32_t osAccountId, const char *deviceIdHash)
{
    if (deviceIdHash == NULL) {
        LOGE("deviceIdHash is null");
        return NULL;
    }
    QueryGroupParams queryParams = InitQueryGroupParams();
    GroupEntryVec groupEntryVec = CreateGroupEntryVec();
    int32_t ret = QueryGroups(osAccountId, &queryParams, &groupEntryVec);
    if (ret != HC_SUCCESS) {
        LOGE("Failed to query groups!");
        ClearGroupEntryVec(&groupEntryVec);
        return NULL;
    }
    uint32_t index;
    TrustedGroupEntry **ptr = NULL;
    FOR_EACH_HC_VECTOR(groupEntryVec, index, ptr) {
        const TrustedGroupEntry *groupEntry = (const TrustedGroupEntry *)(*ptr);
        const char *groupId = StringGet(&(groupEntry->id));
        if (groupId == NULL) {
            continue;
        }
        const char *udid = GetUdidByGroup(osAccountId, groupId, deviceIdHash);
        if (udid != NULL) {
            ClearGroupEntryVec(&groupEntryVec);
            return udid;
        }
    }
    ClearGroupEntryVec(&groupEntryVec);
    return NULL;
}

const char *GetPeerUdidFromJson(int32_t osAccountId, const CJson *in)
{
    const char *peerConnDeviceId = GetStringFromJson(in, FIELD_PEER_CONN_DEVICE_ID);
    if (peerConnDeviceId == NULL) {
        LOGI("get peerConnDeviceId from json fail.");
        return NULL;
    }
    bool isUdidHash = false;
    (void)GetBoolFromJson(in, FIELD_IS_UDID_HASH, &isUdidHash);
    if (isUdidHash) {
        const char *deviceId = GetDeviceIdByUdidHash(osAccountId, peerConnDeviceId);
        return (deviceId == NULL ? peerConnDeviceId : deviceId);
    }
    return peerConnDeviceId;
}
