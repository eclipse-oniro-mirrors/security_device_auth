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

#ifndef GROUP_OPERATION_COMMON_H
#define GROUP_OPERATION_COMMON_H

#include "common_defs.h"
#include "string_util.h"
#include "group_data_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

bool IsAccountRelatedGroup(int groupType);

bool IsUserTypeValid(int userType);
bool IsExpireTimeValid(int expireTime);
bool IsGroupVisibilityValid(int groupVisibility);

int32_t CheckUpgradeIdentity(uint8_t upgradeFlag, const char *appId, const char *identityFromDB);
int32_t ProcessKeyPair(int32_t osAccountId, int action, const CJson *jsonParams, const char *groupId);
int32_t GetHashMessage(const Uint8Buff *first, const Uint8Buff *second, uint8_t **hashMessage, uint32_t *messageSize);

int32_t AssertUserIdExist(const CJson *jsonParams);
int32_t AssertGroupTypeMatch(int32_t inputType, int32_t targetType);
int32_t AssertSameGroupNotExist(int32_t osAccountId, const char *groupId);
int32_t AssertPeerDeviceNotSelf(const char *peerUdid);
int32_t CheckGroupExist(int32_t osAccountId, const char *groupId);
int32_t CheckGroupNumLimit(int32_t osAccountId, int32_t groupType, const char *appId);
int32_t CheckDeviceNumLimit(int32_t osAccountId, const char *groupId, const char *peerUdid);
int32_t CheckUserTypeIfExist(const CJson *jsonParams);
int32_t CheckGroupVisibilityIfExist(const CJson *jsonParams);
int32_t CheckExpireTimeIfExist(const CJson *jsonParams);
int32_t CheckPermForGroup(int32_t osAccountId, int actionType, const char *callerPkgName, const char *groupId);

int32_t AddGroupNameToParams(const char *groupName, TrustedGroupEntry *groupParams);
int32_t AddGroupIdToParams(const char *groupId, TrustedGroupEntry *groupParams);
int32_t AddGroupOwnerToParams(const char *owner, TrustedGroupEntry *groupParams);
int32_t AddGroupTypeToParams(uint32_t groupType, TrustedGroupEntry *groupParams);
int32_t AddGroupVisibilityOrDefault(const CJson *jsonParams, TrustedGroupEntry *groupParams);
int32_t AddExpireTimeOrDefault(const CJson *jsonParams, TrustedGroupEntry *groupParams);
int32_t AddUserIdToGroupParams(const CJson *jsonParams, TrustedGroupEntry *groupParams);
int32_t AddSharedUserIdToGroupParams(const CJson *jsonParams, TrustedGroupEntry *groupParams);

int32_t AddSelfUdidToParams(TrustedDeviceEntry *devParams);
int32_t AddUdidToParams(const CJson *jsonParams, TrustedDeviceEntry *devParams);
int32_t AddAuthIdToParams(const CJson *jsonParams, TrustedDeviceEntry *devParams);
int32_t AddAuthIdToParamsOrDefault(const CJson *jsonParams, TrustedDeviceEntry *devParams);
int32_t AddUserTypeToParamsOrDefault(const CJson *jsonParams, TrustedDeviceEntry *devParams);
int32_t AddSourceToParams(RelationShipSource source, TrustedDeviceEntry *devParams);
int32_t AddCredTypeToParams(const CJson *jsonParams, TrustedDeviceEntry *devParams);
int32_t AddServiceTypeToParams(const char *groupId, TrustedDeviceEntry *devParams);
int32_t AddGroupIdToDevParams(const char *groupId, TrustedDeviceEntry *devParams);
int32_t AddUserIdToDevParams(const CJson *jsonParams, TrustedDeviceEntry *devParams);

int32_t AddGroupToDatabaseByJson(int32_t osAccountId, int32_t (*generateGroupParams)(const CJson*,
    const char *, TrustedGroupEntry*), const CJson *jsonParams, const char *groupId);
int32_t AddDeviceToDatabaseByJson(int32_t osAccountId, int32_t (*generateDevParams)(const CJson*, const char*,
    TrustedDeviceEntry*), const CJson *jsonParams, const char *groupId);
int32_t DelGroupFromDb(int32_t osAccountId, const char *groupId);
int32_t DelDeviceFromDb(int32_t osAccountId, const char *groupId, const TrustedDeviceEntry *deviceEntry);

int32_t ConvertGroupIdToJsonStr(const char *groupId, char **returnJsonStr);
int32_t GenerateBindSuccessData(const char *peerAuthId, const char *peerUdid, const char *groupId,
    char **returnDataStr);
int32_t GenerateUnbindSuccessData(const char *peerAuthId, const char *groupId, char **returnDataStr);

uint32_t GetCurDeviceNumByGroupId(int32_t osAccountId, const char *groupId);
int32_t GetGroupTypeFromDb(int32_t osAccountId, const char *groupId, uint32_t *returnGroupType);
int32_t GetUserIdFromJson(const CJson *jsonParams, char **userId);
int32_t GetSharedUserIdFromJson(const CJson *jsonParams, char **sharedUserId);
int32_t GetGroupIdFromJson(const CJson *jsonParams, const char **groupId);
int32_t GetAppIdFromJson(const CJson *jsonParams, const char **appId);

int32_t GetHashResult(const uint8_t *info, uint32_t infoLen, char *hash, uint32_t hashLen);

bool IsLocalDevice(const char *udid);
bool IsGroupExistByGroupId(int32_t osAccountId, const char *groupId);
bool IsGroupOwner(int32_t osAccountId, const char *groupId, const char *appId);
bool IsTrustedDeviceInGroup(int32_t osAccountId, const char *groupId, const char *deviceId, bool isUdid);
int32_t CheckGroupAccessible(int32_t osAccountId, const char *groupId, const char *appId);
int32_t CheckGroupEditAllowed(int32_t osAccountId, const char *groupId, const char *appId);
int32_t GetGroupInfo(int32_t osAccountId, const QueryGroupParams *params, GroupEntryVec *returnGroupEntryVec);
int32_t GetJoinedGroups(int32_t osAccountId, int groupType, GroupEntryVec *returnGroupEntryVec);
int32_t GetRelatedGroups(int32_t osAccountId, const char *peerDeviceId, bool isUdid,
    GroupEntryVec *returnGroupEntryVec);
int32_t GetTrustedDevInfoById(int32_t osAccountId, const char *deviceId, bool isUdid, const char *groupId,
    TrustedDeviceEntry *returnDeviceEntry);
int32_t GetTrustedDevices(int32_t osAccountId, const char *groupId, DeviceEntryVec *returnDeviceEntryVec);

TrustedGroupEntry *GetGroupEntryById(int32_t osAccountId, const char *groupId);
TrustedDeviceEntry *GetTrustedDeviceEntryById(int32_t osAccountId, const char *deviceId, bool isUdid,
    const char *groupId);

int32_t AddGroupInfoToContextByDb(const char *groupId, CJson *context);
int32_t AddDevInfoToContextByDb(const char *groupId, CJson *context);

int32_t AddGroupInfoToContextByInput(const CJson *receivedMsg, CJson *context);
int32_t AddDevInfoToContextByInput(CJson *context);
const char *GetPeerUdidFromJson(int32_t osAccountId, const CJson *in);

#ifdef __cplusplus
}
#endif
#endif
