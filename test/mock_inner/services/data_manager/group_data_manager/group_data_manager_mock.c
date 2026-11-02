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

/* Controllable mock of group_data_manager + group_data_manager_util.
 * All signatures match the headers exactly. Entry lifecycle helpers use
 * real HcString/HcVector management. DB operations return controllable results. */

#include "group_data_manager.h"
#include "group_data_manager_util.h"
#include "common_defs.h"
#include "device_auth_defines.h"
#include "hc_log.h"
#include "hc_string.h"
#include "hc_string_vector.h"
#include "hc_types.h"
#include "hc_vector.h"
#include "securec.h"
IMPLEMENT_HC_VECTOR(GroupEntryVec, TrustedGroupEntry*, 1)
IMPLEMENT_HC_VECTOR(DeviceEntryVec, TrustedDeviceEntry*, 1)

/* ===== controllable return values ===== */
static int32_t g_addGroupRet = HC_SUCCESS;
static int32_t g_addTrustedDeviceRet = HC_SUCCESS;
static int32_t g_queryGroupsRet = HC_SUCCESS;

void SetAddGroupResult(int32_t ret) { g_addGroupRet = ret; }
void SetAddTrustedDeviceResult(int32_t ret) { g_addTrustedDeviceRet = ret; }
void SetQueryGroupsResult(int32_t ret) { g_queryGroupsRet = ret; }
void ResetDbMock(void) { g_addGroupRet = HC_SUCCESS; g_addTrustedDeviceRet = HC_SUCCESS; g_queryGroupsRet = HC_SUCCESS; }

/* ===== entry lifecycle ===== */
TrustedGroupEntry *CreateGroupEntry(void)
{
    TrustedGroupEntry *e = (TrustedGroupEntry *)HcMalloc(sizeof(TrustedGroupEntry), 0);
    if (e != NULL) {
        e->id = CreateString();
        e->name = CreateString();
        e->userId = CreateString();
        e->sharedUserId = CreateString();
        e->managers = CreateStrVector();
        e->friends = CreateStrVector();
    }
    return e;
}

void DestroyGroupEntry(TrustedGroupEntry *groupEntry)
{
    if (groupEntry == NULL) { return; }
    DeleteString(&groupEntry->id);
    DeleteString(&groupEntry->name);
    DeleteString(&groupEntry->userId);
    DeleteString(&groupEntry->sharedUserId);
    DestroyStrVector(&groupEntry->managers);
    DestroyStrVector(&groupEntry->friends);
    HcFree(groupEntry);
}

TrustedGroupEntry *DeepCopyGroupEntry(const TrustedGroupEntry *entry)
{
    if (entry == NULL) { return NULL; }
    TrustedGroupEntry *c = CreateGroupEntry();
    if (c == NULL) { return NULL; }
    StringSet(&c->id, entry->id);
    StringSet(&c->name, entry->name);
    StringSet(&c->userId, entry->userId);
    StringSet(&c->sharedUserId, entry->sharedUserId);
    c->type = entry->type;
    c->visibility = entry->visibility;
    c->expireTime = entry->expireTime;
    c->upgradeFlag = entry->upgradeFlag;
    return c;
}

TrustedDeviceEntry *CreateDeviceEntry(void)
{
    TrustedDeviceEntry *e = (TrustedDeviceEntry *)HcMalloc(sizeof(TrustedDeviceEntry), 0);
    if (e != NULL) {
        e->groupEntry = NULL;
        e->groupId = CreateString();
        e->udid = CreateString();
        e->authId = CreateString();
        e->userId = CreateString();
        e->serviceType = CreateString();
    }
    return e;
}

void DestroyDeviceEntry(TrustedDeviceEntry *deviceEntry)
{
    if (deviceEntry == NULL) { return; }
    DeleteString(&deviceEntry->groupId);
    DeleteString(&deviceEntry->udid);
    DeleteString(&deviceEntry->authId);
    DeleteString(&deviceEntry->userId);
    DeleteString(&deviceEntry->serviceType);
    HcFree(deviceEntry);
}

TrustedDeviceEntry *DeepCopyDeviceEntry(const TrustedDeviceEntry *entry)
{
    if (entry == NULL) { return NULL; }
    TrustedDeviceEntry *c = CreateDeviceEntry();
    if (c == NULL) { return NULL; }
    StringSet(&c->groupId, entry->groupId);
    StringSet(&c->udid, entry->udid);
    StringSet(&c->authId, entry->authId);
    StringSet(&c->userId, entry->userId);
    StringSet(&c->serviceType, entry->serviceType);
    c->credential = entry->credential;
    c->devType = entry->devType;
    c->source = entry->source;
    c->upgradeFlag = entry->upgradeFlag;
    return c;
}


void ClearGroupEntryVec(GroupEntryVec *vec)
{
    if (vec == NULL) { return; }
    uint32_t index;
    TrustedGroupEntry **ptr = NULL;
    FOR_EACH_HC_VECTOR(*vec, index, ptr) { DestroyGroupEntry(*ptr); }
    DESTROY_HC_VECTOR(GroupEntryVec, vec);
}

void ClearDeviceEntryVec(DeviceEntryVec *vec)
{
    if (vec == NULL) { return; }
    uint32_t index;
    TrustedDeviceEntry **ptr = NULL;
    FOR_EACH_HC_VECTOR(*vec, index, ptr) { DestroyDeviceEntry(*ptr); }
    DESTROY_HC_VECTOR(DeviceEntryVec, vec);
}

QueryGroupParams InitQueryGroupParams(void) { QueryGroupParams p; (void)memset_s(&p, sizeof(p), 0, sizeof(p)); return p; }
QueryDeviceParams InitQueryDeviceParams(void) { QueryDeviceParams p; (void)memset_s(&p, sizeof(p), 0, sizeof(p)); return p; }

/* ===== DB operations (controllable) ===== */
int32_t AddGroup(int32_t osAccountId, const CJson *in, const TrustedGroupEntry *groupEntry)
    { (void)osAccountId; (void)in; (void)groupEntry; return g_addGroupRet; }
int32_t DelGroup(int32_t osAccountId, const CJson *in, const QueryGroupParams *params)
    { (void)osAccountId; (void)in; (void)params; return HC_SUCCESS; }
int32_t AddTrustedDevice(int32_t osAccountId, const CJson *in, const TrustedDeviceEntry *deviceEntry)
    { (void)osAccountId; (void)in; (void)deviceEntry; return g_addTrustedDeviceRet; }
int32_t DelTrustedDevice(int32_t osAccountId, const CJson *in, const QueryDeviceParams *params)
    { (void)osAccountId; (void)in; (void)params; return HC_SUCCESS; }
int32_t QueryGroups(int32_t osAccountId, const CJson *in, const QueryGroupParams *params, GroupEntryVec *vec)
{
    (void)osAccountId;
    (void)in;
    (void)params;
    if (g_queryGroupsRet != HC_SUCCESS || vec == NULL) {
        return g_queryGroupsRet;
    }
    /* Populate vec with one mock group so FillAuthParams can iterate. */
    TrustedGroupEntry *entry = CreateGroupEntry();
    if (entry != NULL) {
        StringSetPointer(&entry->id, "MockGroupId");
        StringSetPointer(&entry->name, "MockGroupName");
        entry->type = PEER_TO_PEER_GROUP;
        entry->visibility = GROUP_VISIBILITY_PUBLIC;
        TrustedGroupEntry *ptr = entry;
        vec->pushBack(vec, (const TrustedGroupEntry **)&ptr);
    }
    return HC_SUCCESS;
}
int32_t QueryDevices(int32_t osAccountId, const CJson *in, const QueryDeviceParams *params, DeviceEntryVec *vec)
    { (void)osAccountId; (void)in; (void)params; (void)vec; return HC_SUCCESS; }
int32_t SaveOsAccountDb(int32_t osAccountId) { (void)osAccountId; return HC_SUCCESS; }
void ReloadOsAccountDb(int32_t osAccountId) { (void)osAccountId; }
int32_t InitDatabase(void) { return HC_SUCCESS; }
void DestroyDatabase(void) {}

/* ===== stubs ===== */
bool GenerateGroupEntryFromEntry(const TrustedGroupEntry *entry, TrustedGroupEntry *returnEntry)
    { (void)entry; (void)returnEntry; return false; }
bool GenerateDeviceEntryFromEntry(const TrustedDeviceEntry *entry, TrustedDeviceEntry *returnEntry)
    { (void)entry; (void)returnEntry; return false; }
int32_t GenerateReturnGroupInfo(const TrustedGroupEntry *groupEntry, CJson *returnJson)
    { (void)groupEntry; (void)returnJson; return HC_SUCCESS; }
int32_t GenerateReturnDevInfo(const TrustedDeviceEntry *deviceEntry, CJson *returnJson)
    { (void)deviceEntry; (void)returnJson; return HC_SUCCESS; }
int32_t GenerateMessage(int32_t osAccountId, int32_t subProfileId, const TrustedGroupEntry *groupEntry,
    char **returnMessage)
    { (void)osAccountId; (void)subProfileId; (void)groupEntry; if (returnMessage) *returnMessage = NULL; return HC_ERR_NOT_SUPPORT; }
bool IsSelfDeviceEntry(const TrustedDeviceEntry *deviceEntry) { (void)deviceEntry; return false; }
void RecordAddTrustDeviceEvent(int32_t osAccountId, const TrustedDeviceEntry *deviceEntry) { (void)osAccountId; (void)deviceEntry; }
void DumpGroupsAndDevices(int fd, int32_t osAccountId, const GroupEntryVec *groups, const DeviceEntryVec *devices)
    { (void)fd; (void)osAccountId; (void)groups; (void)devices; }
bool IsSelfDeviceExistInGroup(int32_t osAccountId, const char *groupId) { (void)osAccountId; (void)groupId; return false; }
bool IsSelfDeviceExistInGroupForUser(int32_t osAccountId, int32_t subProfileId, const char *groupId)
    { (void)osAccountId; (void)subProfileId; (void)groupId; return false; }
