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

/* Auto-generated controllable mock of group_operation_common.
 * All signatures match group_operation_common.h exactly. */

#include "group_operation_common.h"
#include "securec.h"
#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "hc_types.h"
#include "json_utils.h"

/* ===== controllable return values ===== */
static int32_t g_checkGroupExistRet = HC_SUCCESS;
static int32_t g_checkPermForGroupRet = HC_SUCCESS;
static int32_t g_checkDeviceNumLimitRet = HC_SUCCESS;
static int32_t g_processKeyPairRet = HC_SUCCESS;
static int32_t g_getTrustedDevInfoByIdRet = HC_SUCCESS;
static int32_t g_getGroupTypeFromDbRet = HC_SUCCESS;
static int32_t g_assertGroupTypeMatchRet = HC_SUCCESS;
static bool g_isGroupExistByGroupId = false;
static bool g_isUserTypeValid = true;
static bool g_isGroupVisibilityValid = true;
static bool g_isExpireTimeValid = true;

void SetCheckGroupExistResult(int32_t ret) { g_checkGroupExistRet = ret; }
void SetCheckPermForGroupResult(int32_t ret) { g_checkPermForGroupRet = ret; }
void SetCheckDeviceNumLimitResult(int32_t ret) { g_checkDeviceNumLimitRet = ret; }
void SetProcessKeyPairResult(int32_t ret) { g_processKeyPairRet = ret; }
void SetGetTrustedDevInfoByIdResult(int32_t ret) { g_getTrustedDevInfoByIdRet = ret; }
void SetGetGroupTypeFromDbResult(int32_t ret) { g_getGroupTypeFromDbRet = ret; }
void SetAssertGroupTypeMatchResult(int32_t ret) { g_assertGroupTypeMatchRet = ret; }
void SetIsGroupExistByGroupId(bool exist) { g_isGroupExistByGroupId = exist; }
void SetIsUserTypeValid(bool valid) { g_isUserTypeValid = valid; }
void SetIsGroupVisibilityValid(bool valid) { g_isGroupVisibilityValid = valid; }
void SetIsExpireTimeValid(bool valid) { g_isExpireTimeValid = valid; }
void ResetGroupOpMock(void)
{
    g_checkGroupExistRet = HC_SUCCESS;
    g_checkPermForGroupRet = HC_SUCCESS;
    g_checkDeviceNumLimitRet = HC_SUCCESS;
    g_processKeyPairRet = HC_SUCCESS;
    g_getTrustedDevInfoByIdRet = HC_SUCCESS;
    g_getGroupTypeFromDbRet = HC_SUCCESS;
    g_assertGroupTypeMatchRet = HC_SUCCESS;
    g_isGroupExistByGroupId = false;
    g_isUserTypeValid = true;
    g_isGroupVisibilityValid = true;
    g_isExpireTimeValid = true;
}

/* ===== controllable functions ===== */
bool IsUserTypeValid(int userType) { (void)userType; return g_isUserTypeValid; }
bool IsExpireTimeValid(int expireTime) { (void)expireTime; return g_isExpireTimeValid; }
bool IsGroupVisibilityValid(int groupVisibility) { (void)groupVisibility; return g_isGroupVisibilityValid; }
int32_t ProcessKeyPair(int32_t osAccountId, int action, const CJson *jsonParams, const char *groupId)
    { (void)osAccountId; (void)action; (void)jsonParams; (void)groupId; return g_processKeyPairRet; }
int32_t AssertGroupTypeMatch(int32_t inputType, int32_t targetType)
    { (void)inputType; (void)targetType; return g_assertGroupTypeMatchRet; }
int32_t CheckGroupExist(int32_t osAccountId, const CJson *jsonParams, const char *groupId)
    { (void)osAccountId; (void)jsonParams; (void)groupId; return g_checkGroupExistRet; }
bool IsGroupExistByGroupId(int32_t osAccountId, const CJson *jsonParams, const char *groupId)
    { (void)osAccountId; (void)jsonParams; (void)groupId; return g_isGroupExistByGroupId; }
int32_t CheckPermForGroup(int32_t osAccountId, const CJson *jsonParams,
    int actionType, const char *callerPkgName, const char *groupId)
 
{
    (void)osAccountId;
    (void)jsonParams;
    (void)actionType;
    (void)callerPkgName;
    (void)groupId;
    return g_checkPermForGroupRet;
}
int32_t CheckDeviceNumLimit(int32_t osAccountId, const char *groupId, const char *peerUdid)
    { (void)osAccountId; (void)groupId; (void)peerUdid; return g_checkDeviceNumLimitRet; }
int32_t GetGroupTypeFromDb(int32_t osAccountId, const CJson *jsonParams, const char *groupId, uint32_t *returnGroupType)
 
{
    (void)osAccountId;
    (void)jsonParams;
    (void)groupId;
    if (returnGroupType) *returnGroupType = PEER_TO_PEER_GROUP;
    return g_getGroupTypeFromDbRet;
}
int32_t GetTrustedDevInfoById(int32_t osAccountId, const char *deviceId,
    bool isUdid, const char *groupId, TrustedDeviceEntry *devInfo)
 
{
    (void)osAccountId;
    (void)deviceId;
    (void)isUdid;
    (void)groupId;
    if (devInfo == NULL) return HC_ERR_INVALID_PARAMS;
    return g_getTrustedDevInfoByIdRet;
}
int32_t DelDeviceFromDb(int32_t osAccountId, const char *groupId, const TrustedDeviceEntry *deviceEntry)
    { (void)osAccountId; (void)groupId; (void)deviceEntry; return HC_SUCCESS; }
TrustedGroupEntry *GetGroupEntryById(int32_t osAccountId, const CJson *jsonParams, const char *groupId)
{
    (void)osAccountId;
    (void)jsonParams;
    (void)groupId;
    TrustedGroupEntry *entry = CreateGroupEntry();
    if (entry != NULL) {
        StringSetPointer(&entry->id, "MockGroupId");
        StringSetPointer(&entry->name, "MockGroupName");
        entry->type = PEER_TO_PEER_GROUP;
        entry->visibility = GROUP_VISIBILITY_PUBLIC;
    }
    return entry;
}
TrustedDeviceEntry *GetTrustedDeviceEntryById(int32_t osAccountId,
    const char *deviceId, bool isUdid, const char *groupId)
    { (void)osAccountId; (void)deviceId; (void)isUdid; (void)groupId; return NULL; }
int32_t GenerateBindSuccessData(const char *peerAuthId, const char *peerUdid, const char *groupId, char **returnDataStr)
 
{
    (void)peerAuthId;
    (void)peerUdid;
    (void)groupId;
    if (returnDataStr) { *returnDataStr = (char *)HcMalloc(3, 0);
    if (*returnDataStr) { (*returnDataStr)[0]='{';
    (*returnDataStr)[1]='}';
    } } return HC_SUCCESS;
}

/* ===== stubs (return success/null/false) ===== */
bool IsAccountRelatedGroup(int groupType) { (void)groupType; return false; }
int32_t CheckUpgradeIdentity(uint8_t upgradeFlag, const char *appId, const char *identityFromDB)
{
    (void)upgradeFlag;
    (void)appId;
    (void)identityFromDB;
    return HC_SUCCESS;
}
int32_t GetHashMessage(const Uint8Buff *first, const Uint8Buff *second, uint8_t **hashMessage, uint32_t *messageSize)
{
    (void)first;
    (void)second;
    (void)hashMessage;
    (void)messageSize;
    return HC_ERR_NOT_SUPPORT;
}
int32_t AssertUserIdExist(const CJson *jsonParams) { (void)jsonParams; return HC_SUCCESS; }
int32_t AssertSameGroupNotExist(int32_t osAccountId, const CJson *jsonParams, const char *groupId)
{
    (void)osAccountId;
    (void)jsonParams;
    (void)groupId;
    return HC_SUCCESS;
}
int32_t AssertPeerDeviceNotSelf(const char *peerUdid) { (void)peerUdid; return HC_SUCCESS; }
int32_t CheckGroupNumLimit(int32_t osAccountId, const CJson *jsonParams, int32_t groupType, const char *appId)
{
    (void)osAccountId;
    (void)jsonParams;
    (void)groupType;
    (void)appId;
    return HC_SUCCESS;
}
int32_t CheckUserTypeIfExist(const CJson *jsonParams) { (void)jsonParams; return HC_SUCCESS; }
int32_t CheckGroupVisibilityIfExist(const CJson *jsonParams) { (void)jsonParams; return HC_SUCCESS; }
int32_t CheckExpireTimeIfExist(const CJson *jsonParams) { (void)jsonParams; return HC_SUCCESS; }
int32_t AddGroupNameToParams(const char *groupName, TrustedGroupEntry *groupParams)
{
    (void)groupName;
    (void)groupParams;
    return HC_SUCCESS;
}
int32_t AddGroupIdToParams(const char *groupId, TrustedGroupEntry *groupParams)
{
    (void)groupId;
    (void)groupParams;
    return HC_SUCCESS;
}
int32_t AddGroupOwnerToParams(const char *owner, TrustedGroupEntry *groupParams)
{
    (void)owner;
    (void)groupParams;
    return HC_SUCCESS;
}
int32_t AddGroupTypeToParams(uint32_t groupType, TrustedGroupEntry *groupParams)
{
    (void)groupType;
    (void)groupParams;
    return HC_SUCCESS;
}
int32_t AddGroupVisibilityOrDefault(const CJson *jsonParams, TrustedGroupEntry *groupParams)
{
    (void)jsonParams;
    (void)groupParams;
    return HC_SUCCESS;
}
int32_t AddExpireTimeOrDefault(const CJson *jsonParams, TrustedGroupEntry *groupParams)
{
    (void)jsonParams;
    (void)groupParams;
    return HC_SUCCESS;
}
int32_t AddUserIdToGroupParams(const CJson *jsonParams, TrustedGroupEntry *groupParams)
{
    (void)jsonParams;
    (void)groupParams;
    return HC_SUCCESS;
}
int32_t AddSharedUserIdToGroupParams(const CJson *jsonParams, TrustedGroupEntry *groupParams)
{
    (void)jsonParams;
    (void)groupParams;
    return HC_SUCCESS;
}
int32_t AddSelfUdidToParams(TrustedDeviceEntry *devParams) { (void)devParams; return HC_SUCCESS; }
int32_t AddUdidToParams(const CJson *jsonParams, TrustedDeviceEntry *devParams)
{
    (void)jsonParams;
    (void)devParams;
    return HC_SUCCESS;
}
int32_t AddAuthIdToParams(const CJson *jsonParams, TrustedDeviceEntry *devParams)
{
    (void)jsonParams;
    (void)devParams;
    return HC_SUCCESS;
}
int32_t AddAuthIdToParamsOrDefault(const CJson *jsonParams, TrustedDeviceEntry *devParams)
{
    (void)jsonParams;
    (void)devParams;
    return HC_SUCCESS;
}
int32_t AddUserTypeToParamsOrDefault(const CJson *jsonParams, TrustedDeviceEntry *devParams)
{
    (void)jsonParams;
    (void)devParams;
    return HC_SUCCESS;
}
int32_t AddSourceToParams(RelationShipSource source, TrustedDeviceEntry *devParams)
{
    (void)source;
    (void)devParams;
    return HC_SUCCESS;
}
int32_t AddCredTypeToParams(const CJson *jsonParams, TrustedDeviceEntry *devParams)
{
    (void)jsonParams;
    (void)devParams;
    return HC_SUCCESS;
}
int32_t AddServiceTypeToParams(const char *groupId, TrustedDeviceEntry *devParams)
{
    (void)groupId;
    (void)devParams;
    return HC_SUCCESS;
}
int32_t AddGroupIdToDevParams(const char *groupId, TrustedDeviceEntry *devParams)
{
    (void)groupId;
    (void)devParams;
    return HC_SUCCESS;
}
int32_t AddUserIdToDevParams(const CJson *jsonParams, TrustedDeviceEntry *devParams)
{
    (void)jsonParams;
    (void)devParams;
    return HC_SUCCESS;
}
int32_t AddGroupToDatabaseByJson(int32_t osAccountId,
    int32_t (*generateGroupParams)(const CJson*, const char *, TrustedGroupEntry*),
    const CJson *jsonParams, const char *groupId)
{
    (void)osAccountId;
    (void)generateGroupParams;
    (void)jsonParams;
    (void)groupId;
    return HC_SUCCESS;
}
int32_t AddDeviceToDatabaseByJson(int32_t osAccountId,
    int32_t (*generateDevParams)(const CJson*, const char*, TrustedDeviceEntry*),
    const CJson *jsonParams, const char *groupId)
{
    (void)osAccountId;
    (void)generateDevParams;
    (void)jsonParams;
    (void)groupId;
    return HC_SUCCESS;
}
int32_t DelGroupFromDb(int32_t osAccountId, const CJson *jsonParams, const char *groupId)
{
    (void)osAccountId;
    (void)jsonParams;
    (void)groupId;
    return HC_SUCCESS;
}
int32_t ConvertGroupIdToJsonStr(const char *groupId, char **returnJsonStr)
{
    (void)groupId;
    if (returnJsonStr != NULL) {
        *returnJsonStr = NULL;
    }
    return HC_ERR_NOT_SUPPORT;
}
int32_t GenerateUnbindSuccessData(const char *peerAuthId, const char *groupId, char **returnDataStr)
{
    (void)peerAuthId;
    (void)groupId;
    if (returnDataStr != NULL) {
        *returnDataStr = (char *)HcMalloc(3, 0);
        if (*returnDataStr != NULL) {
            (*returnDataStr)[0] = '{';
            (*returnDataStr)[1] = '}';
        }
    }
    return HC_SUCCESS;
}
uint32_t GetCurDeviceNumByGroupId(int32_t osAccountId, const char *groupId)
{
    (void)osAccountId;
    (void)groupId;
    return 0;
}
int32_t GetUserIdFromJson(const CJson *jsonParams, char **userId)
{
    (void)jsonParams;
    (void)userId;
    return HC_ERR_NOT_SUPPORT;
}
int32_t GetSharedUserIdFromJson(const CJson *jsonParams, char **sharedUserId)
{
    (void)jsonParams;
    (void)sharedUserId;
    return HC_ERR_NOT_SUPPORT;
}
int32_t GetGroupIdFromJson(const CJson *jsonParams, const char **groupId)
{
    (void)jsonParams;
    (void)groupId;
    return HC_ERR_NOT_SUPPORT;
}
int32_t GetAppIdFromJson(const CJson *jsonParams, const char **appId)
{
    (void)jsonParams;
    (void)appId;
    return HC_ERR_NOT_SUPPORT;
}
int32_t GetHashResult(const uint8_t *info, uint32_t infoLen, char *hash, uint32_t hashLen)
{
    (void)info;
    (void)infoLen;
    (void)hash;
    (void)hashLen;
    return HC_ERR_NOT_SUPPORT;
}
bool IsLocalDevice(const char *udid) { (void)udid; return false; }
bool IsGroupOwner(int32_t osAccountId, const CJson *jsonParams, const char *groupId, const char *appId)
{
    (void)osAccountId;
    (void)jsonParams;
    (void)groupId;
    (void)appId;
    return true;
}
bool IsTrustedDeviceInGroup(int32_t osAccountId, const char *groupId, const char *deviceId, bool isUdid)
{
    (void)osAccountId;
    (void)groupId;
    (void)deviceId;
    (void)isUdid;
    return false;
}
int32_t CheckGroupAccessible(int32_t osAccountId, const CJson *jsonParams, const char *groupId, const char *appId)
{
    (void)osAccountId;
    (void)jsonParams;
    (void)groupId;
    (void)appId;
    return HC_SUCCESS;
}
int32_t CheckGroupEditAllowed(int32_t osAccountId, const CJson *jsonParams, const char *groupId, const char *appId)
{
    (void)osAccountId;
    (void)jsonParams;
    (void)groupId;
    (void)appId;
    return HC_SUCCESS;
}
int32_t GetGroupInfo(int32_t osAccountId, const CJson *jsonParams,
    const QueryGroupParams *params, GroupEntryVec *returnGroupEntryVec)
{
    (void)osAccountId;
    (void)jsonParams;
    (void)params;
    return HC_ERR_DB;
}
int32_t GetJoinedGroups(int32_t osAccountId, int groupType, GroupEntryVec *returnGroupEntryVec)
{
    (void)osAccountId;
    (void)groupType;
    (void)returnGroupEntryVec;
    return HC_ERR_NOT_SUPPORT;
}
int32_t GetRelatedGroups(int32_t osAccountId, const char *peerDeviceId, bool isUdid, GroupEntryVec *returnGroupEntryVec)
{
    (void)osAccountId;
    (void)peerDeviceId;
    (void)isUdid;
    (void)returnGroupEntryVec;
    return HC_ERR_NOT_SUPPORT;
}
int32_t GetTrustedDevices(int32_t osAccountId, const CJson *jsonParams,
    const char *groupId, DeviceEntryVec *returnDevEntryVec)
{
    (void)osAccountId;
    (void)jsonParams;
    (void)groupId;
    (void)returnDevEntryVec;
    return HC_ERR_NOT_SUPPORT;
}
int32_t AddGroupInfoToContextByDb(const char *groupId, CJson *context)
{
    (void)groupId;
    (void)context;
    return HC_SUCCESS;
}
int32_t AddDevInfoToContextByDb(const char *groupId, CJson *context)
{
    (void)groupId;
    (void)context;
    return HC_SUCCESS;
}
int32_t AddGroupInfoToContextByInput(const CJson *receivedMsg, CJson *context)
{
    (void)receivedMsg;
    (void)context;
    return HC_SUCCESS;
}
int32_t AddDevInfoToContextByInput(CJson *context) { (void)context; return HC_SUCCESS; }
char *GetPeerUdidFromJson(int32_t osAccountId, const CJson *in) { (void)osAccountId; (void)in; return NULL; }
