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

#include "account_related_group_auth.h"
#include "common_defs.h"
#include "device_auth_defines.h"
#include "group_auth_data_operation.h"
#include "hc_dev_info.h"
#include "hc_log.h"
#include "hc_time.h"
#include "hc_types.h"
#include "json_utils.h"
#include "performance_dumper.h"
#include "string_util.h"
#include "alg_loader.h"
#include "hisysevent_adapter.h"
#include "account_task_manager.h"

#define UID_HEX_STRING_LEN_MAX 64
#define UID_HEX_STRING_LEN_MIN 10
#define MAX_SERVICE_PEER_DATA_LENGTH 2048
#define PLACE_HOLDER_LENGTH 4
#define COMMA_SEPARATOR ","
#define COLON_SEPARATOR ":"
#define JSON_KEY_FORMAT "\"%s\":"

static void OnAccountFinish(int64_t requestId, const CJson *authParam, const CJson *out,
    const DeviceAuthCallback *callback);
static int32_t FillAccountAuthInfo(int32_t osAccountId, const TrustedGroupEntry *entry,
    const TrustedDeviceEntry *localAuthInfo, CJson *paramsData);
static void GetAccountCandidateGroup(int32_t osAccountId, const CJson *param,
    QueryGroupParams *queryParams, GroupEntryVec *vec);
static int32_t GetAuthParamsVecForServer(const CJson *dataFromClient, ParamsVecForAuth *authParamsVec);
static int32_t CombineAccountServerConfirms(const CJson *confirmationJson, CJson *dataFromClient);

static AccountRelatedGroupAuth g_accountRelatedGroupAuth = {
    .base.onFinish = OnAccountFinish,
    .base.fillDeviceAuthInfo = FillAccountAuthInfo,
    .base.getAuthParamsVecForServer = GetAuthParamsVecForServer,
    .base.combineServerConfirmParams = CombineAccountServerConfirms,
    .base.authType = ACCOUNT_RELATED_GROUP_AUTH_TYPE,
    .getAccountCandidateGroup = GetAccountCandidateGroup,
};

static int32_t ReturnSessionKey(int64_t requestId, const CJson *out, const DeviceAuthCallback *callback)
{
    const char *returnSessionKeyStr = GetStringFromJson(out, FIELD_SESSION_KEY);
    if (returnSessionKeyStr == NULL) {
        LOGE("Failed to get session key from json!");
        return HC_ERR_JSON_GET;
    }
    uint32_t keyLen = (HcStrlen(returnSessionKeyStr) / BYTE_TO_HEX_OPER_LENGTH);
    uint8_t *sessionKey = (uint8_t *)HcMalloc(keyLen, 0);
    if (sessionKey == NULL) {
        LOGE("HcMalloc failed.");
        return HC_ERR_ALLOC_MEMORY;
    }

    int32_t res = HC_SUCCESS;
    do {
        if (GetByteFromJson(out, FIELD_SESSION_KEY, sessionKey, keyLen) != HC_SUCCESS) {
            LOGE("Failed to get session key from json!");
            res = HC_ERR_JSON_GET;
            break;
        }
        if ((callback == NULL) || (callback->onSessionKeyReturned == NULL)) {
            LOGE("The callback or callback onSessionKeyReturned is NULL!");
            res = HC_ERR_INVALID_PARAMS;
            break;
        }
        LOGI("Begin execute onSessionKeyReturned!");
        UPDATE_PERFORM_DATA_BY_INPUT_INDEX(requestId, ON_SESSION_KEY_RETURN_TIME, HcGetCurTimeInMillis());
        callback->onSessionKeyReturned(requestId, sessionKey, keyLen);
        LOGI("End execute onSessionKeyReturned, res = %" LOG_PUB "d.", res);
    } while (0);
    (void)memset_s(sessionKey, keyLen, 0, keyLen);
    HcFree(sessionKey);
    sessionKey = NULL;
    return res;
}

static int32_t GetSessionKeyForAccount(const CJson *sendToSelf, CJson *returnToSelf)
{
    int32_t keyLen = DEFAULT_RETURN_KEY_LENGTH;
    uint8_t *sessionKey = (uint8_t *)HcMalloc(keyLen, 0);
    if (sessionKey == NULL) {
        LOGE("Failed to malloc memory for sessionKey!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = HC_SUCCESS;
    do {
        if (GetByteFromJson(sendToSelf, FIELD_SESSION_KEY, sessionKey, keyLen) != HC_SUCCESS) {
            LOGE("Get session key from sendToSelf failed!");
            res = HC_ERR_JSON_GET;
            break;
        }
        if (AddByteToJson(returnToSelf, FIELD_SESSION_KEY, (const uint8_t *)sessionKey, keyLen) != HC_SUCCESS) {
            LOGE("Add session key for onFinish from json failed!");
            res = HC_ERR_JSON_FAIL;
            break;
        }
    } while (0);
    (void)memset_s(sessionKey, keyLen, 0, keyLen);
    HcFree(sessionKey);
    sessionKey = NULL;
    return res;
}

static int32_t GetUserIdForAccount(const CJson *sendToSelf, CJson *returnToSelf)
{
    const char *peerUserId = GetStringFromJson(sendToSelf, FIELD_USER_ID);
    if (peerUserId == NULL) {
        LOGE("Failed to get peer uid!");
        return HC_ERR_JSON_GET;
    }
    if (AddStringToJson(returnToSelf, FIELD_USER_ID, peerUserId) != HC_SUCCESS) {
        LOGE("Failed to add peer uid!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static bool IsPeerUidLenValid(uint32_t peerUserIdLen)
{
    if ((peerUserIdLen < UID_HEX_STRING_LEN_MIN) || (peerUserIdLen > UID_HEX_STRING_LEN_MAX)) {
        LOGE("The input userId len is invalid, input userId in hex string len = %" LOG_PUB "d", peerUserIdLen);
        return false;
    }
    return true;
}

static bool IsUserIdEqual(const char *userIdInDb, const char *peerUserIdInDb)
{
    char *peerUidToUpper = NULL;
    if (ToUpperCase(peerUserIdInDb, &peerUidToUpper) != HC_SUCCESS) {
        LOGE("Failed to convert the input userId to upper case!");
        return false;
    }
    uint32_t userIdInDbLen = HcStrlen(userIdInDb);
    uint32_t peerUserIdLen = HcStrlen(peerUserIdInDb);
    if (!IsPeerUidLenValid(peerUserIdLen)) {
        HcFree(peerUidToUpper);
        peerUidToUpper = NULL;
        return false;
    }
    uint32_t cmpLen = (userIdInDbLen > peerUserIdLen) ? peerUserIdLen : userIdInDbLen;
    if (memcmp(userIdInDb, peerUidToUpper, cmpLen) == EOK) {
        HcFree(peerUidToUpper);
        peerUidToUpper = NULL;
        return true;
    }
    HcFree(peerUidToUpper);
    peerUidToUpper = NULL;
    return false;
}

static bool IsPeerInAccountRelatedGroup(const TrustedGroupEntry *groupEntry, const char *peerUserId, GroupType type)
{
    const char *userIdInDb =
        ((type == IDENTICAL_ACCOUNT_GROUP) ? StringGet(&(groupEntry->userId)) : StringGet(&(groupEntry->sharedUserId)));
    if (userIdInDb == NULL) {
        LOGD("Failed to get peer userId from db!");
        return false;
    }
    if (IsUserIdEqual(userIdInDb, peerUserId)) {
        LOGI("[Account auth]: The input peer-userId is in one account group, add account-group auth!");
        return true;
    }
    return false;
}

static bool IsPeerInIdenticalGroup(int32_t osAccountId, const char *peerUserId)
{
    bool isGroupExist = false;
    GroupEntryVec accountVec = CreateGroupEntryVec();
    QueryGroupParams queryParams = InitQueryGroupParams();
    queryParams.groupType = IDENTICAL_ACCOUNT_GROUP;
    do {
        if (QueryGroups(osAccountId, &queryParams, &accountVec) != HC_SUCCESS) {
            LOGD("No identical-account group in dataBase, no identical-account auth!");
            break;
        }
        uint32_t index = 0;
        TrustedGroupEntry **ptr = NULL;
        while (index < accountVec.size(&accountVec)) {
            ptr = accountVec.getp(&accountVec, index);
            if ((ptr == NULL) || (*ptr == NULL)) {
                index++;
                continue;
            }
            if (IsPeerInAccountRelatedGroup(*ptr, peerUserId, IDENTICAL_ACCOUNT_GROUP)) {
                isGroupExist = true;
                break;
            }
            index++;
        }
    } while (0);
    ClearGroupEntryVec(&accountVec);
    return isGroupExist;
}

static void GaGetAccountGroup(int32_t osAccountId, GroupType type, const char *peerUserId,
    QueryGroupParams *queryParams, GroupEntryVec *vec)
{
    LOGI("Try to get account group info, groupType: %" LOG_PUB "d.", type);
    queryParams->groupType = type;
    if (QueryGroups(osAccountId, queryParams, vec) != HC_SUCCESS) {
        LOGD("Database don't have local device's across-account group info!");
        return;
    }

    uint32_t index = 0;
    TrustedGroupEntry **ptr = NULL;
    while (index < vec->size(vec)) {
        ptr = vec->getp(vec, index);
        if ((ptr == NULL) || (*ptr == NULL)) {
            index++;
            continue;
        }
        if ((peerUserId == NULL) || IsPeerInAccountRelatedGroup(*ptr, peerUserId, type)) {
            index++;
            continue;
        }
        TrustedGroupEntry *tempEntry = NULL;
        HC_VECTOR_POPELEMENT(vec, &tempEntry, index);
        DestroyGroupEntry((TrustedGroupEntry *)tempEntry);
    }
    LOGI("The candidate account group size is: %" LOG_PUB "u", vec->size(vec));
}

static void GetAccountCandidateGroup(int32_t osAccountId, const CJson *param,
    QueryGroupParams *queryParams, GroupEntryVec *vec)
{
    /* Compare userId with local uid in DB. */
    bool identicalFlag = false;
    bool acrossAccountFlag = false;
    const char *peerUserId = GetStringFromJson(param, FIELD_USER_ID);
    if (peerUserId != NULL) {
        acrossAccountFlag = true;
        identicalFlag = IsPeerInIdenticalGroup(osAccountId, peerUserId);
    } else {
        LOGD("userId is null in authParam.");
        identicalFlag = true;
    }

    if (identicalFlag) {
        GaGetAccountGroup(osAccountId, IDENTICAL_ACCOUNT_GROUP, peerUserId, queryParams, vec);
    } else if (acrossAccountFlag) {
        GaGetAccountGroup(osAccountId, ACROSS_ACCOUNT_AUTHORIZE_GROUP, peerUserId, queryParams, vec);
    }
}

static int32_t FillAccountCredentialInfo(int32_t osAccountId, const char *peerUdid, const char *groupId,
    const TrustedDeviceEntry *localAuthInfo, CJson *paramsData)
{
    TrustedDeviceEntry *peerDevInfo = CreateDeviceEntry();
    if (peerDevInfo == NULL) {
        LOGE("Failed to alloc memory for peerDevInfo!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t localDevType = DEVICE_TYPE_CONTROLLER;
    int32_t authCredential = localAuthInfo->credential;
    int32_t res = GaGetTrustedDeviceEntryById(osAccountId, peerUdid, true, groupId, peerDevInfo);
    if ((res != HC_SUCCESS) || (peerDevInfo->source == SELF_CREATED)) {
        LOGI("Peer device's query result = %" LOG_PUB "d, pass local device info to account authenticator.", res);
        localDevType = DEVICE_TYPE_ACCESSORY; /* Controller has peer device info, which is added by caller. */
    }
    if ((res == HC_SUCCESS) && (peerDevInfo->source == IMPORTED_FROM_CLOUD)) {
        LOGI("Peer trusted device is imported by cloud, invoke sym account auth.");
        authCredential = peerDevInfo->credential;
    }
    DestroyDeviceEntry(peerDevInfo);
    if (AddIntToJson(paramsData, FIELD_LOCAL_DEVICE_TYPE, localDevType) != HC_SUCCESS) {
        LOGE("Failed to add self device type to json!");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(paramsData, FIELD_CREDENTIAL_TYPE, authCredential) != HC_SUCCESS) {
        LOGE("Failed to add self credential type to json!");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t FillAccountAuthInfo(int32_t osAccountId, const TrustedGroupEntry *entry,
    const TrustedDeviceEntry *localAuthInfo, CJson *paramsData)
{
    const char *peerUdid = GetStringFromJson(paramsData, FIELD_PEER_CONN_DEVICE_ID);
    if (peerUdid == NULL) {
        LOGE("Failed to get peer udid in the input data for account auth!");
        return HC_ERR_INVALID_PARAMS;
    }
    const char *selfUserId = StringGet(&entry->userId);
    const char *groupId = StringGet(&entry->id);
    const char *selfDeviceId = StringGet(&(localAuthInfo->udid));
    const char *selfDevId = StringGet(&(localAuthInfo->authId));
    if ((selfUserId == NULL) || (groupId == NULL) || (selfDeviceId == NULL) || (selfDevId == NULL)) {
        LOGE("Failed to get self account info for client in account-related auth!");
        return HC_ERR_JSON_GET;
    }
    if (AddStringToJson(paramsData, FIELD_SELF_USER_ID, selfUserId) != HC_SUCCESS) {
        LOGE("Failed to add self userId for client in account-related auth!");
        return HC_ERR_JSON_FAIL;
    }
    if (AddStringToJson(paramsData, FIELD_SELF_DEVICE_ID, selfDeviceId) != HC_SUCCESS) {
        LOGE("Failed to add self deviceId for client in account-related auth!");
        return HC_ERR_JSON_FAIL;
    }
    if (AddStringToJson(paramsData, FIELD_SELF_DEV_ID, selfDevId) != HC_SUCCESS) {
        LOGE("Failed to add self devId for client in account-related auth!");
        return HC_ERR_JSON_FAIL;
    }
    return FillAccountCredentialInfo(osAccountId, peerUdid, groupId, localAuthInfo, paramsData);
}

static bool IsDeviceImportedByCloud(int32_t osAccountId,  const char *peerUdid, const char *groupId)
{
    TrustedDeviceEntry *peerDeviceInfo = CreateDeviceEntry();
    if (peerDeviceInfo == NULL) {
        LOGE("Failed to alloc memory for peerDeviceInfo!");
        return true;
    }
    if (GaGetTrustedDeviceEntryById(osAccountId, peerUdid, true, groupId, peerDeviceInfo) != HC_SUCCESS) {
        LOGI("Peer trusted device is not in database.");
        DestroyDeviceEntry(peerDeviceInfo);
        return false;
    }
    uint8_t source = peerDeviceInfo->source;
    DestroyDeviceEntry(peerDeviceInfo);
    if (source == IMPORTED_FROM_CLOUD) {
        LOGI("Peer trusted device is imported by cloud.");
        return true;
    }
    return false;
}

static int32_t CombineAccountServerConfirms(const CJson *confirmationJson, CJson *dataFromClient)
{
    bool isClient = false;
    if (AddBoolToJson(dataFromClient, FIELD_IS_CLIENT, isClient) != HC_SUCCESS) {
        LOGE("Failed to combine server param for isClient!");
        return HC_ERR_JSON_FAIL;
    }
    const char *peerUdid = GetStringFromJson(confirmationJson, FIELD_PEER_CONN_DEVICE_ID);
    if (peerUdid == NULL) {
        LOGE("Failed to get peer udid from server confirm params!");
        return HC_ERR_JSON_GET;
    }
    if (AddStringToJson(dataFromClient, FIELD_PEER_CONN_DEVICE_ID, peerUdid) != HC_SUCCESS) {
        LOGE("Failed to combine server param for peerUdid!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t QueryAuthGroupForServer(int32_t osAccountId, GroupEntryVec *accountVec, CJson *data)
{
    const char *peerUserId = GetStringFromJson(data, FIELD_USER_ID);
    if (peerUserId == NULL) {
        LOGE("Failed to get peerUserId.");
        return HC_ERR_JSON_GET;
    }
    int32_t authForm = AUTH_FORM_INVALID_TYPE;
    if (GetIntFromJson(data, FIELD_AUTH_FORM, &authForm) != HC_SUCCESS) {
        LOGE("Failed to get auth form for server!");
        return HC_ERR_JSON_GET;
    }
    int32_t groupType = AuthFormToGroupType(authForm);
    if (groupType == GROUP_TYPE_INVALID) {
        LOGE("Invalid authForm, authForm = %" LOG_PUB "d.", authForm);
        return HC_ERR_INVALID_PARAMS;
    }
    QueryGroupParams queryParams = InitQueryGroupParams();
    queryParams.groupType = (uint32_t)groupType;
    if (queryParams.groupType == IDENTICAL_ACCOUNT_GROUP) {
        queryParams.userId = peerUserId;
    } else {
        queryParams.sharedUserId = peerUserId;
    }
    int32_t res = QueryGroups(osAccountId, &queryParams, accountVec);
    if (res != HC_SUCCESS) {
        LOGE("Failed to query local device's account group info for server!");
        return res;
    }
    if (accountVec->size(accountVec) == 0) {
        LOGE("Database don't have local device's account group info for server!");
        return HC_ERR_NO_CANDIDATE_GROUP;
    }
    return HC_SUCCESS;
}

static char *GetValueFromJsonStr(char *jsonStr, const char *key)
{
    if (HcStrlen(jsonStr) > MAX_SERVICE_PEER_DATA_LENGTH) {
        LOGE("Invalid peer data length!");
        return NULL;
    }
    uint32_t keyLen = HcStrlen(key);
    char *keyStr = (char *)HcMalloc(keyLen + PLACE_HOLDER_LENGTH, 0);
    if (keyStr == NULL) {
        LOGE("Failed to alloc memory for keyStr!");
        return NULL;
    }
    if (sprintf_s(keyStr, keyLen + PLACE_HOLDER_LENGTH, JSON_KEY_FORMAT, key) <= 0) {
        LOGE("Failed to convert key to string!");
        HcFree(keyStr);
        return NULL;
    }
    char *nextPtr = NULL;
    char *value = NULL;
    char *subVal = strtok_s(jsonStr, COMMA_SEPARATOR, &nextPtr);
    while (subVal != NULL) {
        if (strstr(subVal, keyStr) != NULL) {
            value = strstr(subVal, COLON_SEPARATOR);
            if (value != NULL) {
                value++;
            }
            break;
        }
        subVal = strtok_s(NULL, COMMA_SEPARATOR, &nextPtr);
    }
    HcFree(keyStr);
    return value;
}

static int32_t GetPeerUserIdFromReceivedData(const CJson *data, char **peerUserId)
{
    const char *peerData = GetStringFromJson(data, FIELD_PLUGIN_EXT_DATA);
    if (peerData == NULL) {
        LOGE("Failed to get peerData from data!");
        return HC_ERR_JSON_GET;
    }
    char *copyPeerData = NULL;
    int32_t res = DeepCopyString(peerData, &copyPeerData);
    if (res != HC_SUCCESS) {
        LOGE("Failed to deep copy peerData!");
        return res;
    }
    char *userId = GetValueFromJsonStr(copyPeerData, FIELD_USER_ID);
    if (userId == NULL) {
        LOGE("Failed to get userId from peer data!");
        HcFree(copyPeerData);
        return HC_ERR_JSON_GET;
    }
    uint8_t userIdHash[SHA256_LEN] = { 0 };
    Uint8Buff hashBuff = { userIdHash, sizeof(userIdHash) };
    Uint8Buff hashMsgBuff = { (uint8_t *)userId, HcStrlen(userId) };
    res = GetLoaderInstance()->sha256(&hashMsgBuff, &hashBuff);
    HcFree(copyPeerData);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get hash for userId!");
        return res;
    }
    uint32_t hexLen = hashBuff.length * BYTE_TO_HEX_OPER_LENGTH + 1;
    *peerUserId = (char *)HcMalloc(hexLen, 0);
    if (*peerUserId == NULL) {
        LOGE("Failed to alloc memory for peer userId!");
        return HC_ERR_ALLOC_MEMORY;
    }
    res = ByteToHexString(hashBuff.val, hashBuff.length, *peerUserId, hexLen);
    if (res != HC_SUCCESS) {
        LOGE("Failed to convert hash to hex string!");
        HcFree(*peerUserId);
        *peerUserId = NULL;
        return res;
    }
    return HC_SUCCESS;
}

static int32_t QueryGroupForAccountPlugin(int32_t osAccountId, GroupEntryVec *accountVec, CJson *data)
{
    char *peerUserId = NULL;
    int32_t res = GetPeerUserIdFromReceivedData(data, &peerUserId);
    if (res != HC_SUCCESS) {
        return res;
    }
    do {
        int32_t authForm = AUTH_FORM_INVALID_TYPE;
        if (GetIntFromJson(data, FIELD_AUTH_FORM, &authForm) != HC_SUCCESS) {
            LOGE("Failed to get auth form for server!");
            res = HC_ERR_JSON_GET;
            break;
        }
        int32_t groupType = AuthFormToGroupType(authForm);
        if (groupType == GROUP_TYPE_INVALID) {
            LOGE("Invalid authForm: %" LOG_PUB "d.", authForm);
            res = HC_ERR_INVALID_PARAMS;
            break;
        }
        QueryGroupParams queryParams = InitQueryGroupParams();
        queryParams.groupType = (uint32_t)groupType;
        if (queryParams.groupType == IDENTICAL_ACCOUNT_GROUP) {
            queryParams.userId = peerUserId;
        } else {
            queryParams.sharedUserId = peerUserId;
        }
        res = QueryGroups(osAccountId, &queryParams, accountVec);
    } while (0);
    HcFree(peerUserId);
    return res;
}

static int32_t AddSelfUserId(const TrustedGroupEntry *groupEntry, CJson *dataFromClient)
{
    const char *selfUserId = StringGet(&groupEntry->userId);
    if (selfUserId == NULL) {
        LOGE("Failed to get local userId info from db!");
        return HC_ERR_DB;
    }
    if (AddStringToJson(dataFromClient, FIELD_SELF_USER_ID, selfUserId) != HC_SUCCESS) {
        LOGE("Failed to add self userId for server in account-related auth!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddGroupIdForServer(const TrustedGroupEntry *groupEntry, CJson *dataFromClient)
{
    const char *groupId = StringGet(&groupEntry->id);
    if (groupId == NULL) {
        LOGE("Failed to get groupId info from db!");
        return HC_ERR_DB;
    }
    if (AddStringToJson(dataFromClient, FIELD_GROUP_ID, groupId) != HC_SUCCESS) {
        LOGE("Failed to add groupId for server in account-related auth!");
        return HC_ERR_JSON_FAIL;
    }
    return HC_SUCCESS;
}

static int32_t AddSelfDevInfoForServer(int32_t osAccountId, const TrustedGroupEntry *groupEntry, CJson *dataFromClient)
{
    TrustedDeviceEntry *localDevInfo = CreateDeviceEntry();
    if (localDevInfo == NULL) {
        LOGE("Failed to allocate memory for localDevInfo for server!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res;
    do {
        const char *groupId = StringGet(&groupEntry->id);
        if (groupId == NULL) {
            LOGE("Failed to get groupId for server!");
            res = HC_ERR_NULL_PTR;
            break;
        }
        res = GaGetLocalDeviceInfo(osAccountId, groupId, localDevInfo);
        const char *selfDevId = StringGet(&(localDevInfo->authId));
        const char *selfUdid = StringGet(&(localDevInfo->udid));
        if ((res != HC_SUCCESS) || (selfDevId == NULL) || (selfUdid == NULL)) {
            LOGE("Failed to get self id info from db!");
            res = HC_ERR_DB;
            break;
        }
        if (AddStringToJson(dataFromClient, FIELD_SELF_DEV_ID, selfDevId) != HC_SUCCESS) {
            LOGE("Failed to add self devId for server in account-related auth!");
            res = HC_ERR_JSON_ADD;
            break;
        }
        if (AddStringToJson(dataFromClient, FIELD_SELF_DEVICE_ID, selfUdid) != HC_SUCCESS) {
            LOGE("Failed to add self udid for server in account-related auth!");
            res = HC_ERR_JSON_ADD;
            break;
        }
        const char *peerUdid = GetStringFromJson(dataFromClient, FIELD_PEER_CONN_DEVICE_ID);
        if (peerUdid == NULL) {
            LOGE("Failed to get peer udid for server auth!");
            res = HC_ERR_JSON_FAIL;
            break;
        }
        res = FillAccountCredentialInfo(osAccountId, peerUdid, groupId, localDevInfo, dataFromClient);
    } while (0);
    DestroyDeviceEntry(localDevInfo);
    return res;
}

static void AddServerParamsForAccountPlugin(CJson *dataFromClient)
{
    int32_t osAccountId = INVALID_OS_ACCOUNT;
    if (GetIntFromJson(dataFromClient, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId!");
        return;
    }
    GroupEntryVec accountVec = CreateGroupEntryVec();
    if (QueryGroupForAccountPlugin(osAccountId, &accountVec, dataFromClient) != HC_SUCCESS) {
        LOGE("Failed to query group!");
        ClearGroupEntryVec(&accountVec);
        return;
    }
    if (accountVec.size(&accountVec) == 0) {
        LOGE("Group size is 0!");
        ClearGroupEntryVec(&accountVec);
        return;
    }
    TrustedGroupEntry *groupEntry = accountVec.get(&accountVec, 0);
    if (groupEntry == NULL) {
        LOGE("Group entry is null!");
        ClearGroupEntryVec(&accountVec);
        return;
    }
    (void)AddGroupIdForServer(groupEntry, dataFromClient);
    ClearGroupEntryVec(&accountVec);
}

static int32_t AddSelfAccountInfoForServer(CJson *dataFromClient)
{
    int32_t osAccountId = INVALID_OS_ACCOUNT;
    if (GetIntFromJson(dataFromClient, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId for server!");
        return HC_ERR_JSON_GET;
    }
    GroupEntryVec accountVec = CreateGroupEntryVec();
    int32_t res = QueryAuthGroupForServer(osAccountId, &accountVec, dataFromClient);
    do {
        if (res != HC_SUCCESS) {
            LOGE("Failed to query account group info for server auth!");
            break;
        }
        if (accountVec.size(&accountVec) == 0) {
            LOGE("Database don't have local device's account group info for server!");
            res = HC_ERR_NO_CANDIDATE_GROUP;
            break;
        }
        TrustedGroupEntry *groupEntry = accountVec.get(&accountVec, 0);
        if (groupEntry == NULL) {
            LOGE("Local group info is null!");
            res = HC_ERR_GROUP_NOT_EXIST;
            break;
        }
        res = AddSelfUserId(groupEntry, dataFromClient);
        if (res != HC_SUCCESS) {
            break;
        }
        res = AddGroupIdForServer(groupEntry, dataFromClient);
        if (res != HC_SUCCESS) {
            break;
        }
        res = AddSelfDevInfoForServer(osAccountId, groupEntry, dataFromClient);
    } while (0);
    ClearGroupEntryVec(&accountVec);
    return res;
}

static int32_t GetAuthParamsVecForServer(const CJson *dataFromClient, ParamsVecForAuth *authParamsVec)
{
    LOGI("Begin get account-related auth params for server.");
    CJson *dupData = DuplicateJson(dataFromClient);
    if (dupData == NULL) {
        LOGE("Failed to create dupData for dataFromClient!");
        return HC_ERR_JSON_FAIL;
    }

    int32_t res = HC_SUCCESS;
    if (HasAccountPlugin()) {
        // Try to add groupId to auth params. If add fail, ignore it.
        AddServerParamsForAccountPlugin(dupData);
    } else {
        res = AddSelfAccountInfoForServer(dupData);
    }
    if (res != HC_SUCCESS) {
        LOGE("Failed to add account server params!");
        FreeJson(dupData);
        return res;
    }

    if (authParamsVec->pushBack(authParamsVec, (const void **)&dupData) == NULL) {
        LOGE("Failed to push json data to vector in account-related auth!");
        FreeJson(dupData);
        return HC_ERR_ALLOC_MEMORY;
    }
    return HC_SUCCESS;
}

static int32_t AccountOnFinishToPeer(int64_t requestId, const CJson *out, const DeviceAuthCallback *callback)
{
    int32_t res = HC_SUCCESS;
    CJson *sendToPeer = GetObjFromJson(out, FIELD_SEND_TO_PEER);
    if (sendToPeer == NULL) {
        LOGI("No need to transmit data to peer for account-related auth.");
        return res;
    }
    if (AddBoolToJson(sendToPeer, FIELD_IS_DEVICE_LEVEL, false) != HC_SUCCESS) {
        LOGE("Failed to add device level flag!");
        return HC_ERR_JSON_ADD;
    }
    char *sendToPeerStr = PackJsonToString(sendToPeer);
    if (sendToPeerStr == NULL) {
        LOGE("Failed to pack sendToPeerStr!");
        return HC_ERR_ALLOC_MEMORY;
    }
    if ((callback != NULL) && (callback->onTransmit != NULL)) {
        LOGD("Begin to transmit data to peer for auth in AccountOnFinishToPeer.");
        UPDATE_PERFORM_DATA_BY_SELF_INDEX(requestId, HcGetCurTimeInMillis());
        if (!callback->onTransmit(requestId, (uint8_t *)sendToPeerStr, HcStrlen(sendToPeerStr) + 1)) {
            LOGE("Failed to transmit data to peer!");
            res = HC_ERR_TRANSMIT_FAIL;
        }
        LOGD("End to transmit data to peer for auth in AccountOnFinishToPeer.");
    }
    FreeJsonString(sendToPeerStr);
    return res;
}

static int32_t PrepareTrustedDeviceInfo(const char *peerUdid, const char *groupId,
    const CJson *out, TrustedDeviceEntry *devEntry)
{
    devEntry->source = SELF_CREATED;
    const CJson *sendToSelf = GetObjFromJson(out, FIELD_SEND_TO_SELF);
    if (sendToSelf == NULL) {
        LOGE("Failed to get sendToSelf data for account!");
        return HC_ERR_JSON_GET;
    }
    int32_t credentialType = INVALID_CRED;
    if (GetIntFromJson(sendToSelf, FIELD_CREDENTIAL_TYPE, &credentialType) != HC_SUCCESS) {
        LOGE("Failed to get credentialType from json sendToSelf!");
        return HC_ERR_JSON_GET;
    }
    devEntry->credential = credentialType;
    const char *peerAuthId = GetStringFromJson(sendToSelf, FIELD_DEV_ID);
    if (peerAuthId == NULL) {
        LOGE("Failed to get peer authId for account!");
        return HC_ERR_JSON_GET;
    }
    const char *peerUserId = GetStringFromJson(sendToSelf, FIELD_USER_ID);
    if (peerUserId == NULL) {
        LOGE("Failed to get peer userId!");
        return HC_ERR_JSON_GET;
    }
    if (!StringSetPointer(&(devEntry->userId), peerUserId) ||
        !StringSetPointer(&(devEntry->udid), peerUdid) ||
        !StringSetPointer(&(devEntry->authId), peerAuthId) ||
        !StringSetPointer(&(devEntry->groupId), groupId) ||
        !StringSetPointer(&(devEntry->serviceType), groupId)) {
        LOGE("Failed to add device info when adding a trusted device!");
        return HC_ERR_MEMORY_COPY;
    }
    return HC_SUCCESS;
}

static int32_t AddTrustedDeviceForAccount(const CJson *authParam, const CJson *out)
{
    int32_t osAccountId = ANY_OS_ACCOUNT;
    if (GetIntFromJson(authParam, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("Failed to get osAccountId for account!");
        return HC_ERR_JSON_GET;
    }
    const char *peerUdid = GetStringFromJson(authParam, FIELD_PEER_CONN_DEVICE_ID);
    if (peerUdid == NULL) {
        LOGE("Failed to get peer udid when adding peer trusted device!");
        return HC_ERR_JSON_GET;
    }
    const char *groupId = GetStringFromJson(authParam, FIELD_GROUP_ID);
    if (groupId == NULL) {
        LOGE("Failed to get groupId when adding peer trusted device!");
        return HC_ERR_JSON_GET;
    }
    if (IsDeviceImportedByCloud(osAccountId, peerUdid, groupId)) {
        LOGD("Peer trusted device is imported by cloud, we don't update peer device's trusted relationship.");
        return HC_SUCCESS;
    }
    TrustedDeviceEntry *devEntry = CreateDeviceEntry();
    if (devEntry == NULL) {
        LOGE("Failed to allocate device entry memory!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res;
    do {
        res = PrepareTrustedDeviceInfo(peerUdid, groupId, out, devEntry);
        if (res != HC_SUCCESS) {
            LOGE("Failed to prepare trust device params!");
            break;
        }
        res = AddTrustedDevice(osAccountId, devEntry);
        if (res != HC_SUCCESS) {
            LOGE("Failed to add trusted devices for account to database!");
            break;
        }
        res = SaveOsAccountDb(osAccountId);
    } while (0);
    DestroyDeviceEntry(devEntry);
    return res;
}

static int32_t PrepareAccountDataToSelf(const CJson *sendToSelf, CJson *returnToSelf)
{
    int32_t res = GetSessionKeyForAccount(sendToSelf, returnToSelf);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get session key info for account auth!");
        return res;
    }
    res = GetUserIdForAccount(sendToSelf, returnToSelf);
    if (res != HC_SUCCESS) {
        LOGE("Failed to get user id for account auth!");
    }
    return res;
}

static void ReportV1RelatedAuthCallEvent(int64_t requestId, const CJson *authParam)
{
#ifdef DEV_AUTH_HIVIEW_ENABLE
    DevAuthCallEvent eventData;
    eventData.appId = SOFTBUS_APP_ID;
    eventData.callResult = DEFAULT_CALL_RESULT;
    eventData.processCode = PROCESS_AUTH_V1;
    eventData.osAccountId = DEFAULT_OS_ACCOUNT;
    eventData.funcName = AUTH_DEV_EVENT;
    (void)GetIntFromJson(authParam, FIELD_OS_ACCOUNT_ID, &eventData.osAccountId);
    eventData.credType = DEFAULT_CRED_TYPE;
    eventData.groupType = IDENTICAL_ACCOUNT_GROUP;
    eventData.executionTime = GET_TOTAL_CONSUME_TIME_BY_REQ_ID(requestId);
    eventData.extInfo = DEFAULT_EXT_INFO;
    DEV_AUTH_REPORT_CALL_EVENT(eventData);
    return;
#endif
    (void)requestId;
    (void)authParam;
    return;
}

static int32_t AccountOnFinishToSelf(int64_t requestId, const CJson *authParam, const CJson *out,
    const DeviceAuthCallback *callback)
{
    const CJson *sendToSelf = GetObjFromJson(out, FIELD_SEND_TO_SELF);
    if (sendToSelf == NULL) {
        LOGE("No data to send to self for onFinish.");
        return HC_ERR_LOST_DATA;
    }

    CJson *returnToSelf = CreateJson();
    if (returnToSelf == NULL) {
        LOGE("Failed to create json for account-related auth in onFinish!");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = PrepareAccountDataToSelf(sendToSelf, returnToSelf);
    if (res != HC_SUCCESS) {
        LOGE("Failed to add account-related returnToSelf data!");
        ClearSensitiveStringInJson(returnToSelf, FIELD_SESSION_KEY);
        FreeJson(returnToSelf);
        return res;
    }
    char *returnStr = PackJsonToString(returnToSelf);
    ClearSensitiveStringInJson(returnToSelf, FIELD_SESSION_KEY);
    FreeJson(returnToSelf);
    if (returnStr == NULL) {
        LOGE("Failed to pack return data to string!");
        return HC_ERR_ALLOC_MEMORY;
    }
    do {
        int32_t authForm = AUTH_FORM_INVALID_TYPE;
        if (GetIntFromJson(authParam, FIELD_AUTH_FORM, &authForm) != HC_SUCCESS) {
            LOGE("Failed to get auth type!");
            res = HC_ERR_JSON_GET;
            break;
        }
        if ((callback != NULL) && (callback->onFinish != NULL)) {
            LOGD("Group auth call onFinish for account related auth.");
            UPDATE_PERFORM_DATA_BY_INPUT_INDEX(requestId, ON_FINISH_TIME, HcGetCurTimeInMillis());
            callback->onFinish(requestId, authForm, returnStr);
        }
    } while (0);
    ClearAndFreeJsonString(returnStr);
    ReportV1RelatedAuthCallEvent(requestId, authParam);
    return res;
}

static void OnAccountFinish(int64_t requestId, const CJson *authParam, const CJson *out,
    const DeviceAuthCallback *callback)
{
    LOGI("Begin call onFinish for account-related auth.");
    if (AccountOnFinishToPeer(requestId, out, callback) != HC_SUCCESS) {
        LOGE("Failed to send data to peer when account-related auth finished!");
        return;
    }
    if (ReturnSessionKey(requestId, out, callback) != HC_SUCCESS) {
        LOGE("Failed to return session key for account-related auth!");
        return;
    }
    if (AddTrustedDeviceForAccount(authParam, out) != HC_SUCCESS) {
        LOGD("Failed to add peer trusted devices to database for account-related auth!");
    }
    if (AccountOnFinishToSelf(requestId, authParam, out, callback) != HC_SUCCESS) {
        LOGE("Failed to send data to self when account-related auth finished!");
        return;
    }
    LOGI("Call onFinish for account-related auth successfully.");
}

BaseGroupAuth *GetAccountRelatedGroupAuth(void)
{
    return (BaseGroupAuth *)&g_accountRelatedGroupAuth;
}