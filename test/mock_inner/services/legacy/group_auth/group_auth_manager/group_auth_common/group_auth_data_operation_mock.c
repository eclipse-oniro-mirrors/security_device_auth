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

/* Controllable mock of group_auth_data_operation so unit tests can drive the
 * Ga*-failure branches (AddSelfUpgradeFlag, AddUpgradeFlagToParams,
 * DelTrustDeviceOnAuthErrorV1, FillAuthParams candidate filtering). */

#include "group_auth_data_operation.h"
#include "common_defs.h"
#include "device_auth_defines.h"
#include "hc_log.h"

static int32_t g_gaGetLocalDeviceInfoRet = HC_SUCCESS;
static int32_t g_gaGetTrustedDeviceEntryRet = HC_SUCCESS;
static bool g_gaIsGroupAccessible = true;
static bool g_gaIsDeviceInGroup = true;
static uint8_t g_devUpgradeFlag = 0;
static uint8_t g_devSource = SELF_CREATED;

void SetGaGetLocalDeviceInfoResult(int32_t ret)
{
    g_gaGetLocalDeviceInfoRet = ret;
}

void SetGaGetTrustedDeviceEntryResult(int32_t ret)
{
    g_gaGetTrustedDeviceEntryRet = ret;
}

void SetGaIsGroupAccessible(bool accessible)
{
    g_gaIsGroupAccessible = accessible;
}

void SetGaIsDeviceInGroup(bool inGroup)
{
    g_gaIsDeviceInGroup = inGroup;
}

void SetGaDevUpgradeFlag(uint8_t flag)
{
    g_devUpgradeFlag = flag;
}

void SetGaDevSource(uint8_t source)
{
    g_devSource = source;
}

void ResetGaMock(void)
{
    g_gaGetLocalDeviceInfoRet = HC_SUCCESS;
    g_gaGetTrustedDeviceEntryRet = HC_SUCCESS;
    g_gaIsGroupAccessible = true;
    g_gaIsDeviceInGroup = true;
    g_devUpgradeFlag = 0;
    g_devSource = SELF_CREATED;
}

bool GaIsGroupAccessible(int32_t osAccountId, const char *groupId, const char *appId)
{
    (void)osAccountId;
    (void)groupId;
    (void)appId;
    return g_gaIsGroupAccessible;
}

int32_t GaGetTrustedDeviceEntryById(int32_t osAccountId, const char *deviceId,
    bool isUdid, const char *groupId, TrustedDeviceEntry *returnEntry)
{
    (void)osAccountId;
    (void)deviceId;
    (void)isUdid;
    (void)groupId;
    if (returnEntry == NULL) {
        return HC_ERR_INVALID_PARAMS;
    }
    if (g_gaGetTrustedDeviceEntryRet != HC_SUCCESS) {
        return g_gaGetTrustedDeviceEntryRet;
    }
    returnEntry->upgradeFlag = g_devUpgradeFlag;
    returnEntry->source = g_devSource;
    return HC_SUCCESS;
}

bool GaIsDeviceInGroup(int32_t groupType, int32_t osAccountId, const char *peerUdid,
    const char *peerAuthId, const char *groupId)
{
    (void)groupType;
    (void)osAccountId;
    (void)peerUdid;
    (void)peerAuthId;
    (void)groupId;
    return g_gaIsDeviceInGroup;
}

int32_t GaGetLocalDeviceInfo(int32_t osAccountId, const char *groupId, TrustedDeviceEntry *localAuthInfo)
{
    (void)osAccountId;
    (void)groupId;
    if (localAuthInfo == NULL) {
        return HC_ERR_INVALID_PARAMS;
    }
    if (g_gaGetLocalDeviceInfoRet != HC_SUCCESS) {
        return g_gaGetLocalDeviceInfoRet;
    }
    localAuthInfo->upgradeFlag = g_devUpgradeFlag;
    localAuthInfo->source = g_devSource;
    return HC_SUCCESS;
}

int32_t AuthFormToGroupType(int32_t authForm)
{
    switch (authForm) {
        case AUTH_FORM_ACCOUNT_UNRELATED:
            return PEER_TO_PEER_GROUP;
        case AUTH_FORM_IDENTICAL_ACCOUNT:
            return IDENTICAL_ACCOUNT_GROUP;
        case AUTH_FORM_ACROSS_ACCOUNT:
            return ACROSS_ACCOUNT_AUTHORIZE_GROUP;
        default:
            return GROUP_TYPE_INVALID;
    }
}

int32_t GroupTypeToAuthForm(int32_t groupType)
{
    switch (groupType) {
        case PEER_TO_PEER_GROUP:
            return AUTH_FORM_ACCOUNT_UNRELATED;
        case IDENTICAL_ACCOUNT_GROUP:
            return AUTH_FORM_IDENTICAL_ACCOUNT;
        case ACROSS_ACCOUNT_AUTHORIZE_GROUP:
            return AUTH_FORM_ACROSS_ACCOUNT;
        default:
            return AUTH_FORM_INVALID_TYPE;
    }
}
