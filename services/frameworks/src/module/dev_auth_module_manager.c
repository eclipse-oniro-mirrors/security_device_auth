/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include "dev_auth_module_manager.h"
#include "common_defs.h"
#include "das_module.h"
#include "hc_log.h"
#include "hc_types.h"
#include "hc_vector.h"
#include "account_module.h"
#include "das_version_util.h"
#include "hitrace_adapter.h"
#include "das_token_manager.h"

DECLARE_HC_VECTOR(AuthModuleVec, AuthModuleBase *);
IMPLEMENT_HC_VECTOR(AuthModuleVec, AuthModuleBase *, 2)

static AuthModuleVec g_authModuleVec;
static VersionStruct g_version;

static AuthModuleBase *GetModule(int moduleType)
{
    uint32_t index;
    AuthModuleBase **module;
    FOR_EACH_HC_VECTOR(g_authModuleVec, index, module) {
        if (moduleType == ((*module)->moduleType)) {
            return *module;
        }
    }
    LOGE("There is no matched module, moduleType: %" LOG_PUB "d", moduleType);
    return NULL;
}

static bool IsParamsForDasTokenManagerValid(const char *pkgName, const char *serviceType, Uint8Buff *authId,
    int userType, int moduleType)
{
    if (moduleType != DAS_MODULE) {
        LOGE("Unsupported method in the module, moduleType: %" LOG_PUB "d", moduleType);
        return false;
    }
    if (pkgName == NULL || serviceType == NULL || authId == NULL || authId->val == NULL) {
        LOGE("Params is null.");
        return false;
    }

    if (HcStrlen(pkgName) == 0 || HcStrlen(serviceType) == 0 || authId->length == 0) {
        LOGE("The length of params is invalid!");
        return false;
    }
    if (userType < DEVICE_TYPE_ACCESSORY || userType > DEVICE_TYPE_PROXY) {
        LOGE("Invalid userType, userType: %" LOG_PUB "d", userType);
        return false;
    }
    return true;
}

static TokenManagerParams BuildTokenManagerParams(const AuthModuleParams *moduleParams)
{
    TokenManagerParams params = {
        .osAccountId = moduleParams->osAccountId,
        .pkgName = { (uint8_t *)moduleParams->pkgName, HcStrlen(moduleParams->pkgName) },
        .serviceType = { (uint8_t *)moduleParams->serviceType, HcStrlen(moduleParams->serviceType) },
        .authId = { moduleParams->authId->val, moduleParams->authId->length },
        .userType = moduleParams->userType
    };
    return params;
}

int32_t RegisterLocalIdentity(const AuthModuleParams *moduleParams, int moduleType)
{
    if (!IsParamsForDasTokenManagerValid(moduleParams->pkgName, moduleParams->serviceType, moduleParams->authId,
        moduleParams->userType, moduleType)) {
        LOGE("Params for RegisterLocalIdentity is invalid.");
        return HC_ERR_INVALID_PARAMS;
    }
    AuthModuleBase *module = GetModule(moduleType);
    if (module == NULL) {
        LOGE("Failed to get module for das with moduleType.");
        return HC_ERR_MODULE_NOT_FOUNT;
    }
    TokenManagerParams params = BuildTokenManagerParams(moduleParams);
    DasAuthModule *dasModule = (DasAuthModule *)module;
    int32_t res = dasModule->registerLocalIdentity(&params);
    if (res != HC_SUCCESS) {
        LOGE("Register local identity failed, res: %" LOG_PUB "x", res);
        return res;
    }
    return HC_SUCCESS;
}

int32_t UnregisterLocalIdentity(const AuthModuleParams *moduleParams, int moduleType)
{
    if (!IsParamsForDasTokenManagerValid(moduleParams->pkgName, moduleParams->serviceType, moduleParams->authId,
        moduleParams->userType, moduleType)) {
        LOGE("Params for UnregisterLocalIdentity is invalid.");
        return HC_ERR_INVALID_PARAMS;
    }
    AuthModuleBase *module = GetModule(moduleType);
    if (module == NULL) {
        LOGE("Failed to get module for das with moduleType.");
        return HC_ERR_MODULE_NOT_FOUNT;
    }
    TokenManagerParams params = BuildTokenManagerParams(moduleParams);
    DasAuthModule *dasModule = (DasAuthModule *)module;
    int32_t res = dasModule->unregisterLocalIdentity(&params);
    if (res != HC_SUCCESS) {
        LOGE("Unregister local identity failed, res: %" LOG_PUB "x", res);
        return res;
    }
    return HC_SUCCESS;
}

int32_t DeletePeerAuthInfo(const AuthModuleParams *moduleParams, int moduleType)
{
    if (!IsParamsForDasTokenManagerValid(moduleParams->pkgName, moduleParams->serviceType, moduleParams->authId,
        moduleParams->userType, moduleType)) {
        LOGE("Params for DeletePeerAuthInfo is invalid.");
        return HC_ERR_INVALID_PARAMS;
    }
    AuthModuleBase *module = GetModule(moduleType);
    if (module == NULL) {
        LOGE("Failed to get module for das.");
        return HC_ERR_MODULE_NOT_FOUNT;
    }
    TokenManagerParams params = BuildTokenManagerParams(moduleParams);
    DasAuthModule *dasModule = (DasAuthModule *)module;
    int32_t res = dasModule->deletePeerAuthInfo(&params);
    if (res != HC_SUCCESS) {
        LOGE("Delete peer authInfo failed, res: %" LOG_PUB "x", res);
        return res;
    }
    return HC_SUCCESS;
}

int32_t GetPublicKey(int moduleType, AuthModuleParams *moduleParams, Uint8Buff *returnPk)
{
    if (moduleParams == NULL || returnPk == NULL ||
        !IsParamsForDasTokenManagerValid(moduleParams->pkgName, moduleParams->serviceType,
        moduleParams->authId, moduleParams->userType, moduleType)) {
        LOGE("Params for GetPublicKey is invalid.");
        return HC_ERR_INVALID_PARAMS;
    }
    AuthModuleBase *module = GetModule(moduleType);
    if (module == NULL) {
        LOGE("Failed to get module for das.");
        return HC_ERR_MODULE_NOT_FOUNT;
    }
    TokenManagerParams params = BuildTokenManagerParams(moduleParams);
    DasAuthModule *dasModule = (DasAuthModule *)module;
    int32_t res = dasModule->getPublicKey(&params, returnPk);
    if (res != HC_SUCCESS) {
        LOGE("Get public key failed, res: %" LOG_PUB "d", res);
        return res;
    }
    return HC_SUCCESS;
}

int32_t CheckMsgRepeatability(const CJson *in, int moduleType)
{
    if (in == NULL) {
        LOGE("Params is null.");
        return HC_ERR_NULL_PTR;
    }
    AuthModuleBase *module = GetModule(moduleType);
    if (module == NULL) {
        LOGE("Failed to get module for das.");
        return HC_ERR_MODULE_NOT_FOUNT;
    }
    return module->isMsgNeedIgnore(in) ? HC_ERR_IGNORE_MSG : HC_SUCCESS;
}

int32_t CreateTask(int32_t *taskId, const CJson *in, CJson *out, int moduleType)
{
    if (in == NULL || out == NULL || taskId == NULL) {
        LOGE("Params is null.");
        return HC_ERR_NULL_PTR;
    }
    LOGI("Start to create task, moduleType: %" LOG_PUB "d", moduleType);
    AuthModuleBase *module = GetModule(moduleType);
    if (module == NULL) {
        LOGE("Failed to get module!");
        return HC_ERR_MODULE_NOT_FOUNT;
    }
    int32_t res = module->createTask(taskId, in, out);
    if (res != HC_SUCCESS) {
        LOGE("Create task failed, taskId: %" LOG_PUB "d, moduleType: %" LOG_PUB "d, res: %" LOG_PUB "d", *taskId,
            moduleType, res);
        return res;
    }
    LOGI("Create task success, taskId: %" LOG_PUB "d, moduleType: %" LOG_PUB "d", *taskId, moduleType);
    return HC_SUCCESS;
}

int32_t ProcessTask(int taskId, const CJson *in, CJson *out, int32_t *status, int moduleType)
{
    if (in == NULL || out == NULL || status == NULL) {
        LOGE("Params is null.");
        return HC_ERR_NULL_PTR;
    }
    AuthModuleBase *module = GetModule(moduleType);
    if (module == NULL) {
        LOGE("Failed to get module!");
        return HC_ERR_MODULE_NOT_FOUNT;
    }
    int32_t res = module->processTask(taskId, in, out, status);
    if (res != HC_SUCCESS) {
        LOGE("Process task failed, taskId: %" LOG_PUB "d, moduleType: %" LOG_PUB "d, res: %" LOG_PUB "d.",
            taskId, moduleType, res);
        return res;
    }
    res = AddSingleVersionToJson(out, &g_version);
    if (res != HC_SUCCESS) {
        LOGE("AddSingleVersionToJson failed, res: %" LOG_PUB "x.", res);
        return res;
    }
    LOGI("Process task success, taskId: %" LOG_PUB "d, moduleType: %" LOG_PUB "d.", taskId, moduleType);
    return res;
}

void DestroyTask(int taskId, int moduleType)
{
    AuthModuleBase *module = GetModule(moduleType);
    if (module == NULL) {
        return;
    }
    module->destroyTask(taskId);
}

int32_t InitModules(void)
{
    g_authModuleVec = CREATE_HC_VECTOR(AuthModuleVec);
    InitGroupAndModuleVersion(&g_version);
    int32_t res;
    const AuthModuleBase *dasModule = GetDasModule();
    if (dasModule != NULL) {
        res = dasModule->init();
        if (res != HC_SUCCESS) {
            LOGE("[ModuleMgr]: Init das module fail. [Res]: %" LOG_PUB "d", res);
            DestroyModules();
            return res;
        }
        if (g_authModuleVec.pushBack(&g_authModuleVec, &dasModule) == NULL) {
            LOGE("[ModuleMgr]: Failed to push dasModule!");
            DestroyModules();
            return HC_ERR_ALLOC_MEMORY;
        }
        g_version.third |= dasModule->moduleType;
    }
    const AuthModuleBase *accountModule = GetAccountModule();
    if (accountModule != NULL) {
        res = accountModule->init();
        if (res != HC_SUCCESS) {
            LOGE("[ModuleMgr]: Init account module fail. [Res]: %" LOG_PUB "d", res);
            DestroyModules();
            return res;
        }
        if (g_authModuleVec.pushBack(&g_authModuleVec, &accountModule) == NULL) {
            LOGE("[ModuleMgr]: Failed to push dasModule!");
            DestroyModules();
            return HC_ERR_ALLOC_MEMORY;
        }
        g_version.third |= accountModule->moduleType;
    }
    LOGI("Init modules success!");
    return HC_SUCCESS;
}

void DestroyModules(void)
{
    uint32_t index;
    AuthModuleBase **module;
    FOR_EACH_HC_VECTOR(g_authModuleVec, index, module) {
        (*module)->destroy();
    }
    DESTROY_HC_VECTOR(AuthModuleVec, &g_authModuleVec);
    (void)memset_s(&g_version, sizeof(VersionStruct), 0, sizeof(VersionStruct));
}

int32_t AddAuthModulePlugin(const AuthModuleBase *plugin)
{
    if (plugin == NULL || plugin->init == NULL || plugin->destroy == NULL ||
        plugin->createTask == NULL || plugin->processTask == NULL || plugin->destroyTask == NULL) {
        LOGE("The plugin is invalid.");
        return HC_ERR_INVALID_PARAMS;
    }
    int32_t res = plugin->init();
    if (res != HC_SUCCESS) {
        LOGE("[ModuleMgr]: Init module plugin fail. [Res]: %" LOG_PUB "d", res);
        return HC_ERR_INIT_FAILED;
    }
    bool isNeedReplace = false;
    uint32_t index;
    AuthModuleBase **pluginPtr;
    FOR_EACH_HC_VECTOR(g_authModuleVec, index, pluginPtr) {
        if ((*pluginPtr)->moduleType == plugin->moduleType) {
            isNeedReplace = true;
            break;
        }
    }
    if (g_authModuleVec.pushBack(&g_authModuleVec, &plugin) == NULL) {
        LOGE("[ModuleMgr]: Push module plugin to vector fail.");
        plugin->destroy();
        return HC_ERR_ALLOC_MEMORY;
    }
    if (isNeedReplace) {
        LOGI("[ModuleMgr]: Replace module plugin. [Name]: %" LOG_PUB "d", plugin->moduleType);
        HC_VECTOR_POPELEMENT(&g_authModuleVec, pluginPtr, index);
    } else {
        LOGI("[ModuleMgr]: Add new module plugin. [Name]: %" LOG_PUB "d", plugin->moduleType);
    }
    return HC_SUCCESS;
}

void DelAuthModulePlugin(int32_t moduleType)
{
    uint32_t index;
    AuthModuleBase **pluginPtr;
    FOR_EACH_HC_VECTOR(g_authModuleVec, index, pluginPtr) {
        if ((*pluginPtr)->moduleType == moduleType) {
            LOGI("[ModuleMgr]: Delete module plugin success. [Name]: %" LOG_PUB "d", moduleType);
            (*pluginPtr)->destroy();
            HC_VECTOR_POPELEMENT(&g_authModuleVec, pluginPtr, index);
            break;
        }
    }
}
