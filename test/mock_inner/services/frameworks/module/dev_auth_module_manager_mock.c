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

/* Controllable mock of dev_auth_module_manager so unit tests can drive the V1
 * sub-session process/finish branches (ProcessTask returning CONTINUE/FINISH/
 * IGNORE_MSG/error, CreateTask failing) without running a real protocol task. */

#include "dev_auth_module_manager.h"
#include "common_defs.h"
#include "device_auth_defines.h"
#include "hc_log.h"

static int32_t g_createTaskRet = HC_SUCCESS;
static int32_t g_processTaskRet = HC_SUCCESS;
static int32_t g_processTaskStatus = CONTINUE;
static int32_t g_curTaskId = 1001;

void SetCreateTaskResult(int32_t ret)
{
    g_createTaskRet = ret;
}

void SetProcessTaskResult(int32_t ret, int32_t status)
{
    g_processTaskRet = ret;
    g_processTaskStatus = status;
}

void ResetModuleMock(void)
{
    g_createTaskRet = HC_SUCCESS;
    g_processTaskRet = HC_SUCCESS;
    g_processTaskStatus = CONTINUE;
    g_curTaskId = 1001;
}

int32_t InitModules(void)
{
    return HC_SUCCESS;
}

void DestroyModules(void) {}

int32_t AddAuthModulePlugin(const AuthModuleBase *plugin)
{
    (void)plugin;
    return HC_SUCCESS;
}

void DelAuthModulePlugin(int32_t moduleType)
{
    (void)moduleType;
}

int32_t CreateTask(int32_t *taskId, const CJson *in, CJson *out, int moduleType)
{
    (void)in;
    (void)out;
    (void)moduleType;
    if (g_createTaskRet != HC_SUCCESS) {
        LOGE("[mock] CreateTask forced fail.");
        return g_createTaskRet;
    }
    g_curTaskId += 1;
    if (taskId != NULL) {
        *taskId = g_curTaskId;
    }
    return HC_SUCCESS;
}

int32_t ProcessTask(int taskId, const CJson *in, CJson *out, int32_t *status, int moduleType)
{
    (void)taskId;
    (void)in;
    (void)moduleType;
    if (status != NULL) {
        *status = g_processTaskStatus;
    }
    /* Inject a minimal sendToPeer into out so the CONTINUE/FINISH paths in
     * ProcessBindTaskInner/OnSessionFinish can exercise SendBindDataToPeer. */
    if (out != NULL && (g_processTaskStatus == CONTINUE || g_processTaskStatus == FINISH) &&
        g_processTaskRet == HC_SUCCESS) {
        CJson *sendToPeer = CreateJson();
        if (sendToPeer != NULL) {
            AddIntToJson(sendToPeer, FIELD_AUTH_FORM, AUTH_FORM_ACCOUNT_UNRELATED);
            AddStringToJson(sendToPeer, FIELD_GROUP_ID, "MockGroupId");
            AddObjToJson(out, FIELD_SEND_TO_PEER, sendToPeer);
            FreeJson(sendToPeer);
        }
    }
    return g_processTaskRet;
}

void DestroyTask(int taskId, int moduleType)
{
    (void)taskId;
    (void)moduleType;
}

int32_t CheckMsgRepeatability(const CJson *in, int moduleType)
{
    (void)in;
    (void)moduleType;
    return HC_SUCCESS;
}

int32_t RegisterLocalIdentity(const AuthModuleParams *moduleParams, int moduleType)
{
    (void)moduleParams;
    (void)moduleType;
    return HC_SUCCESS;
}

int32_t UnregisterLocalIdentity(const AuthModuleParams *moduleParams, int moduleType)
{
    (void)moduleParams;
    (void)moduleType;
    return HC_SUCCESS;
}

int32_t DeletePeerAuthInfo(const AuthModuleParams *moduleParams, int moduleType)
{
    (void)moduleParams;
    (void)moduleType;
    return HC_SUCCESS;
}

int32_t GetPublicKey(int moduleType, AuthModuleParams *moduleParams, Uint8Buff *returnPk)
{
    (void)moduleType;
    (void)moduleParams;
    (void)returnPk;
    return HC_SUCCESS;
}
