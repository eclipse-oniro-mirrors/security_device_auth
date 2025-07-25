/*
 * Copyright (C) 2023-2025 Huawei Device Co., Ltd.
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

#include "dev_session_fwk.h"

#include <inttypes.h>
#include <time.h>
#include "alg_loader.h"
#include "callback_manager.h"
#include "channel_manager.h"
#include "identity_common.h"
#include "common_defs.h"
#include "compatible_sub_session.h"
#include "compatible_bind_sub_session_util.h"
#include "compatible_auth_sub_session_util.h"
#include "group_data_manager.h"
#include "dev_session_v2.h"
#include "hc_dev_info.h"
#include "hc_log.h"
#include "hc_time.h"
#include "hc_types.h"
#include "performance_dumper.h"
#include "hisysevent_common.h"

static int32_t StartV1Session(SessionImpl *impl, CJson **sendMsg)
{
    bool isBind = true;
    bool isDeviceLevel = false;
    (void)GetBoolFromJson(impl->context, FIELD_IS_BIND, &isBind);
    (void)GetBoolFromJson(impl->context, FIELD_IS_DEVICE_LEVEL, &isDeviceLevel);
    SubSessionTypeValue subSessionType = isBind ? TYPE_CLIENT_BIND_SUB_SESSION : TYPE_CLIENT_AUTH_SUB_SESSION;
    int32_t res = CreateCompatibleSubSession(subSessionType, impl->context, &impl->base.callback,
        &impl->compatibleSubSession);
    if (res != HC_SUCCESS) {
        if (isDeviceLevel && res == HC_ERR_NO_CANDIDATE_GROUP) {
            LOGI("create compatibleSubSession fail. no candidate group");
        } else {
            LOGE("create compatibleSubSession fail. [Res]: %" LOG_PUB "d", res);
        }
        return res;
    }
    int32_t status;
    res = ProcessCompatibleSubSession(impl->compatibleSubSession, impl->context, sendMsg, &status);
    if (res != HC_SUCCESS) {
        LOGE("process compatibleSubSession fail. [Res]: %" LOG_PUB "d", res);
        DestroyCompatibleSubSession(impl->compatibleSubSession);
        impl->compatibleSubSession = NULL;
        return res;
    }
    return HC_SUCCESS;
}

static void DestroySession(DevSession *self)
{
    if (self == NULL) {
        LOGD("self is NULL.");
        return;
    }
    SessionImpl *impl = (SessionImpl *)self;
    HcFree(impl->base.appId);
    FreeJson(impl->context);
    ClearFreeUint8Buff(&impl->salt);
    ClearFreeUint8Buff(&impl->sessionKey);
    ClearIdentityInfoVec(&impl->credList);
    DestroyEventList(&impl->eventList);
    uint32_t index;
    AuthSubSession **ptr;
    FOR_EACH_HC_VECTOR(impl->authSubSessionList, index, ptr) {
        AuthSubSession *authSubSesion = *ptr;
        authSubSesion->destroy(authSubSesion);
    }
    DestroyAuthSubSessionList(&impl->authSubSessionList);
    if (impl->expandSubSession != NULL) {
        impl->expandSubSession->destroy(impl->expandSubSession);
    }
    if (impl->compatibleSubSession != NULL) {
        DestroyCompatibleSubSession(impl->compatibleSubSession);
        impl->compatibleSubSession = NULL;
    }
    HcFree(impl);
}

static int32_t DecodeEvent(const CJson *inputEvent)
{
    if (inputEvent == NULL) {
        return SESSION_UNKNOWN_EVENT;
    }
    int32_t eventType;
    if (GetIntFromJson(inputEvent, FIELD_TYPE, &eventType) != HC_SUCCESS) {
        LOGE("get eventType from inputEvent fail.");
        return SESSION_UNKNOWN_EVENT;
    }
    if (START_EVENT <= eventType && eventType <= SESSION_UNKNOWN_EVENT) {
        return eventType;
    }
    LOGE("unknown event.");
    return SESSION_UNKNOWN_EVENT;
}

static int32_t PackSendMsg(SessionImpl *impl, CJson *sessionMsg, CJson *sendMsg)
{
    if (AddInt64StringToJson(sendMsg, FIELD_REQUEST_ID, impl->base.id) != HC_SUCCESS) {
        LOGE("add requestId to json fail!");
        return HC_ERR_JSON_ADD;
    }
    if (AddStringToJson(sendMsg, FIELD_APP_ID, impl->base.appId) != HC_SUCCESS) {
        LOGE("add appId to json fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddObjToJson(sendMsg, FIELD_MSG, sessionMsg) != HC_SUCCESS) {
        LOGE("add sessionMsg to json fail.");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t SendJsonMsg(const SessionImpl *impl, const CJson *sendMsg)
{
    char *sendMsgStr = PackJsonToString(sendMsg);
    if (sendMsgStr == NULL) {
        LOGE("convert sendMsg to sendMsgStr fail.");
        return HC_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    UPDATE_PERFORM_DATA_BY_SELF_INDEX(impl->base.id, HcGetCurTimeInMillis());
    int32_t res = HcSendMsg(impl->channelType, impl->base.id, impl->channelId, &impl->base.callback, sendMsgStr);
    FreeJsonString(sendMsgStr);
    return res;
}

static int32_t SendSessionMsg(SessionImpl *impl, CJson *sessionMsg)
{
    if (GetItemNum(sessionMsg) == 0) {
        return HC_SUCCESS;
    }
    CJson *sendMsg = CreateJson();
    if (sendMsg == NULL) {
        LOGE("allocate sendMsg fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = PackSendMsg(impl, sessionMsg, sendMsg);
    if (res != HC_SUCCESS) {
        LOGE("pack send msg fail.");
        FreeJson(sendMsg);
        return res;
    }
    res = SendJsonMsg(impl, sendMsg);
    FreeJson(sendMsg);
    return res;
}

static int32_t ProcEventList(SessionImpl *impl)
{
    CJson *sessionMsg = CreateJsonArray();
    if (sessionMsg == NULL) {
        LOGE("allocate sessionMsg memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = HC_SUCCESS;
    uint32_t index;
    SessionEvent *eventPtr = NULL;
    SessionEvent event;
    FOR_EACH_HC_VECTOR(impl->eventList, index, eventPtr) {
        if ((eventPtr != NULL) && (SESSION_FAIL_EVENT == eventPtr->type)) {
            res = SessionSwitchState(impl, eventPtr, sessionMsg);
            HC_VECTOR_POPELEMENT(&impl->eventList, &event, index);
            break;
        }
    }
    while ((HC_SUCCESS == res) && (HC_VECTOR_SIZE(&impl->eventList) > 0)) {
        HC_VECTOR_POPELEMENT(&impl->eventList, &event, 0);
        res = SessionSwitchState(impl, &event, sessionMsg);
    }
    if (res != HC_SUCCESS) {
        (void)SendSessionMsg(impl, sessionMsg);
        FreeJson(sessionMsg);
        return res;
    }
    res = SendSessionMsg(impl, sessionMsg);
    FreeJson(sessionMsg);
    return res;
}

static int32_t AddSessionInfo(SessionImpl *impl, CJson *sendMsg)
{
    if (AddIntToJson(sendMsg, FIELD_OP_CODE, impl->base.opCode) != HC_SUCCESS) {
        LOGE("add opCode to json fail.");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t StartV2Session(SessionImpl *impl, CJson *sendMsg)
{
    CJson *sessionMsg = CreateJsonArray();
    if (sessionMsg == NULL) {
        LOGE("allocate sessionMsg fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    SessionEvent startEvent = { START_EVENT, NULL };
    int32_t res = SessionSwitchState(impl, &startEvent, sessionMsg);
    if (res != HC_SUCCESS) {
        FreeJson(sessionMsg);
        return res;
    }
    res = PackSendMsg(impl, sessionMsg, sendMsg);
    FreeJson(sessionMsg);
    if (res != HC_SUCCESS) {
        LOGE("pack send msg fail.");
        return res;
    }
    return AddSessionInfo(impl, sendMsg);
}

static bool IsMetaNode(const CJson *context)
{
    return GetStringFromJson(context, FIELD_META_NODE_TYPE) != NULL;
}

static void ReportBehaviorEvent(const SessionImpl *impl, bool isProcessEnd, bool isBehaviorEnd, int32_t res)
{
#ifdef DEV_AUTH_HIVIEW_ENABLE
    bool isBind = true;
    (void)GetBoolFromJson(impl->context, FIELD_IS_BIND, &isBind);
    char *funcName = isBind ? ADD_MEMBER_EVENT : AUTH_DEV_EVENT;
    DevAuthBizScene scene = GetBizScene(isBind, impl->isClient);
    DevAuthBehaviorEvent eventData = { 0 };
    DevAuthBizState state = BIZ_STATE_PROCESS;
    if (isBehaviorEnd) {
        state = BIZ_STATE_END;
    }
    BuildBehaviorEventData(&eventData, funcName, scene, state, BIZ_STAGE_PROCESS);
    char anonymousLocalUdid[ANONYMOUS_UDID_LEN + 1] = { 0 };
    char anonymousPeerUdid[ANONYMOUS_UDID_LEN + 1] = { 0 };
    if (isBind) {
        eventData.hostPkg = ADD_MEMBER_HOST_PKG_NAME;
        eventData.toCallPkg = ADD_MEMBER_TO_CALL_PKG_NAME;
    } else {
        eventData.hostPkg = AUTH_DEVICE_HOST_PKG_NAME;
        char selfUdid[INPUT_UDID_LEN] = { 0 };
        (void)HcGetUdid((uint8_t *)selfUdid, INPUT_UDID_LEN);
        if (GetAnonymousString(selfUdid, anonymousLocalUdid, ANONYMOUS_UDID_LEN) == HC_SUCCESS) {
            eventData.localUdid = anonymousLocalUdid;
        }
        const char *peerUdid = GetStringFromJson(impl->context, FIELD_PEER_CONN_DEVICE_ID);
        if (GetAnonymousString(peerUdid, anonymousPeerUdid, ANONYMOUS_UDID_LEN) == HC_SUCCESS) {
            eventData.peerUdid = anonymousPeerUdid;
        }
    }
    char concurrentId[MAX_REQUEST_ID_LEN] = { 0 };
    (void)sprintf_s(concurrentId, sizeof(concurrentId), "%" PRId64, impl->base.id);
    eventData.concurrentId = concurrentId;
    if (isProcessEnd || isBehaviorEnd) {
        if (res == HC_SUCCESS) {
            eventData.stageRes = STAGE_RES_SUCCESS;
        } else {
            BuildStageRes(&eventData, res);
            eventData.errorCode = res;
        }
    }
    DevAuthReportBehaviorEvent(&eventData);
#else
    (void)impl;
    (void)isProcessEnd;
    (void)isBehaviorEnd;
    (void)res;
#endif
}

static void ReportBindAndAuthCallEvent(const SessionImpl *impl, int32_t callResult, bool isV1Session)
{
#ifdef DEV_AUTH_HIVIEW_ENABLE
    DevAuthCallEvent eventData;
    eventData.appId = impl->base.appId;
    (void)GetIntFromJson(impl->context, FIELD_OS_ACCOUNT_ID, &eventData.osAccountId);
    eventData.callResult = callResult;
    eventData.credType = DEFAULT_CRED_TYPE;
    bool isBind = true;
    (void)GetBoolFromJson(impl->context, FIELD_IS_BIND, &isBind);
    if (isBind) {
        eventData.funcName = ADD_MEMBER_EVENT;
        eventData.processCode = isV1Session ? PROCESS_BIND_V1 : PROCESS_BIND_V2;
        eventData.groupType = PEER_TO_PEER_GROUP;
    } else {
        eventData.funcName = AUTH_DEV_EVENT;
        eventData.processCode = isV1Session ? PROCESS_AUTH_V1 : PROCESS_AUTH_V2;
        eventData.groupType =
            (impl->base.opCode == AUTH_FORM_ACCOUNT_UNRELATED) ? PEER_TO_PEER_GROUP : IDENTICAL_ACCOUNT_GROUP;
    }
    eventData.executionTime = GET_TOTAL_CONSUME_TIME_BY_REQ_ID(impl->base.id);
    eventData.extInfo = DEFAULT_EXT_INFO;
    DEV_AUTH_REPORT_CALL_EVENT(eventData);
    return;
#endif
    (void)impl;
    (void)callResult;
    (void)isV1Session;
    return;
}

static void ReportBindAndAuthFaultEvent(const SessionImpl *impl, int32_t errorCode, bool isV1Session)
{
#ifdef DEV_AUTH_HIVIEW_ENABLE
    DevAuthFaultEvent eventData;
    eventData.appId = impl->base.appId;
    eventData.reqId = impl->base.id;
    eventData.errorCode = errorCode;
    eventData.faultInfo = DEFAULT_FAULT_INFO;
    bool isBind = true;
    (void)GetBoolFromJson(impl->context, FIELD_IS_BIND, &isBind);
    if (isBind) {
        eventData.funcName = ADD_MEMBER_EVENT;
        eventData.processCode = isV1Session ? PROCESS_BIND_V1 : PROCESS_BIND_V2;
    } else {
        eventData.funcName = AUTH_DEV_EVENT;
        eventData.processCode = isV1Session ? PROCESS_AUTH_V1 : PROCESS_AUTH_V2;
    }
    DEV_AUTH_REPORT_FAULT_EVENT(eventData);
    return;
#endif
    (void)impl;
    (void)errorCode;
    (void)isV1Session;
    return;
}

static void OnDevSessionError(const SessionImpl *impl, int32_t errorCode, const char *errorReturn, bool isV1Session)
{
    ReportBehaviorEvent(impl, false, true, errorCode);
    ProcessErrorCallback(impl->base.id, impl->base.opCode, errorCode, errorReturn, &impl->base.callback);
    CloseChannel(impl->channelType, impl->channelId);
    ReportBindAndAuthFaultEvent(impl, errorCode, isV1Session);
    ReportBindAndAuthCallEvent(impl, errorCode, isV1Session);
}

static int32_t StartSession(DevSession *self)
{
    if (self == NULL) {
        LOGE("self is NULL.");
        return HC_ERR_INVALID_PARAMS;
    }
    SessionImpl *impl = (SessionImpl *)self;
    ReportBehaviorEvent(impl, false, false, HC_SUCCESS);
    int32_t res;
    do {
        CJson *sendMsg = NULL;
        /* auth with credentials directly no need to start the v1 session. */
        bool isDirectAuth = false;
        bool isDeviceLevel = false;
        (void)GetBoolFromJson(impl->context, FIELD_IS_DIRECT_AUTH, &isDirectAuth);
        if (!isDirectAuth && !impl->isCredAuth) {
            (void)GetBoolFromJson(impl->context, FIELD_IS_DEVICE_LEVEL, &isDeviceLevel);
            res = StartV1Session(impl, &sendMsg);
            if ((res != HC_SUCCESS)
                && (res != HC_ERR_NO_CANDIDATE_GROUP || !isDeviceLevel)) {
                // if it's device level auth and no group founded,
                // we also need try auth with credentails directly.
                LOGE("start v1 session event fail.");
                break;
            }
        }
        sendMsg = (sendMsg == NULL ? CreateJson() : sendMsg);
        if (sendMsg == NULL) {
            LOGE("allocate sendMsg fail.");
            return HC_ERR_ALLOC_MEMORY;
        }
        if (IsSupportSessionV2() && !IsMetaNode(impl->context)) {
            res = StartV2Session(impl, sendMsg);
            if (res != HC_SUCCESS) {
                LOGE("start v2 session event fail.");
                FreeJson(sendMsg);
                break;
            }
        }
        res = SendJsonMsg(impl, sendMsg);
        FreeJson(sendMsg);
        if (res != HC_SUCCESS) {
            LOGE("send msg fail.");
            break;
        }
    } while (0);
    ReportBehaviorEvent(impl, true, false, res);
    if (res != HC_SUCCESS) {
        OnDevSessionError(impl, res, NULL, false);
    }
    return res;
}

static int32_t ParseAllRecvEvent(SessionImpl *impl, const CJson *receviedMsg)
{
    CJson *sessionMsg = GetObjFromJson(receviedMsg, FIELD_MSG);
    if (sessionMsg == NULL) {
        LOGE("get sessionMsg from receviedMsg fail.");
        return HC_ERR_JSON_GET;
    }
    int32_t eventNum = GetItemNum(sessionMsg);
    if (eventNum <= 0) {
        LOGE("There are no events in the received session message.");
        return HC_ERR_BAD_MESSAGE;
    }
    for (int32_t i = 0; i < eventNum; i++) {
        CJson *inputEventJson = GetItemFromArray(sessionMsg, i);
        if (inputEventJson == NULL) {
            LOGE("get inputEventJson from sessionMsg fail.");
            return HC_ERR_JSON_GET;
        }
        int32_t eventType = DecodeEvent(inputEventJson);
        CJson *eventData = GetObjFromJson(inputEventJson, FIELD_DATA);
        if (eventData == NULL) {
            LOGE("get eventData fail.");
            return HC_ERR_JSON_GET;
        }
        SessionEvent event = { eventType, eventData };
        if (HC_VECTOR_PUSHBACK(&impl->eventList, &event) == NULL) {
            LOGE("push event fail.");
            return HC_ERR_ALLOC_MEMORY;
        }
        LOGI("push event success. [Type]: %" LOG_PUB "d", eventType);
    }
    return HC_SUCCESS;
}

static bool IsV1SessionMsg(const CJson *receviedMsg)
{
    return (GetObjFromJson(receviedMsg, FIELD_MSG) == NULL);
}

static int32_t AddChannelInfoToParams(SessionImpl *impl, CJson *receviedMsg)
{
    int32_t channelType;
    if (GetIntFromJson(impl->context, FIELD_CHANNEL_TYPE, &channelType) != HC_SUCCESS) {
        LOGE("get channelType from context fail.");
        return HC_ERR_JSON_GET;
    }
    int64_t channelId;
    if (GetByteFromJson(impl->context, FIELD_CHANNEL_ID, (uint8_t *)&channelId, sizeof(int64_t)) != HC_SUCCESS) {
        LOGE("get channelId from context fail.");
        return HC_ERR_JSON_GET;
    }
    if (AddIntToJson(receviedMsg, FIELD_CHANNEL_TYPE, channelType) != HC_SUCCESS) {
        LOGE("add channelType to params fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddByteToJson(receviedMsg, FIELD_CHANNEL_ID, (uint8_t *)&channelId, sizeof(int64_t)) != HC_SUCCESS) {
        LOGE("add channelId to params fail.");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t CombindServerBindParams(SessionImpl *impl, CJson *receviedMsg)
{
    int32_t osAccountId;
    if (GetIntFromJson(impl->context, FIELD_OS_ACCOUNT_ID, &osAccountId) != HC_SUCCESS) {
        LOGE("get osAccountId from context fail.");
        return HC_ERR_JSON_GET;
    }
    if (AddIntToJson(receviedMsg, FIELD_OS_ACCOUNT_ID, osAccountId) != HC_SUCCESS) {
        LOGE("add osAccountId to receviedMsg fail.");
        return HC_ERR_JSON_ADD;
    }
    int32_t protocolExpandVal = INVALID_PROTOCOL_EXPAND_VALUE;
    (void)GetIntFromJson(impl->context, FIELD_PROTOCOL_EXPAND, &protocolExpandVal);
    if (AddIntToJson(receviedMsg, FIELD_PROTOCOL_EXPAND, protocolExpandVal) != HC_SUCCESS) {
        LOGE("Failed to add protocol expand val to receviedMsg!");
        return HC_ERR_JSON_ADD;
    }
    return CombineConfirmData(impl->opCode, impl->context, receviedMsg);
}

static int32_t CombindServerAuthParams(SessionImpl *impl, CJson *receviedMsg)
{
    if (AddInt64StringToJson(receviedMsg, FIELD_REQUEST_ID, impl->base.id) != HC_SUCCESS) {
        LOGE("add requestId to receviedMsg fail.");
        return HC_ERR_JSON_ADD;
    }
    if (AddIntToJson(receviedMsg, FIELD_OPERATION_CODE, AUTHENTICATE) != HC_SUCCESS) {
        LOGE("add operationCode to receviedMsg fail.");
        return HC_ERR_JSON_ADD;
    }
    return CombineAuthConfirmData(impl->context, receviedMsg);
}

static int32_t AddConfirmationToParams(const CJson *context, CJson *receviedMsg)
{
    uint32_t confirmation = REQUEST_REJECTED;
    (void)GetUnsignedIntFromJson(context, FIELD_CONFIRMATION, &confirmation);
    if (AddIntToJson(receviedMsg, FIELD_CONFIRMATION, (int32_t)confirmation) != HC_SUCCESS) {
        LOGE("add confirmation to receviedMsg fail.");
        return HC_ERR_JSON_ADD;
    }
    return HC_SUCCESS;
}

static int32_t CombineServerParams(SessionImpl *impl, bool isBind, CJson *receviedMsg)
{
    int32_t res = AddChannelInfoToParams(impl, receviedMsg);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = AddConfirmationToParams(impl->context, receviedMsg);
    if (res != HC_SUCCESS) {
        return res;
    }
    return isBind ? CombindServerBindParams(impl, receviedMsg) : CombindServerAuthParams(impl, receviedMsg);
}

static int32_t InitServerV1Session(SessionImpl *impl, const CJson *receviedMsg)
{
    bool isBind = true;
    (void)GetBoolFromJson(impl->context, FIELD_IS_BIND, &isBind);
    int32_t res = CombineServerParams(impl, isBind, (CJson *)receviedMsg);
    if (res != HC_SUCCESS) {
        return res;
    }
    SubSessionTypeValue subSessionType = isBind ? TYPE_SERVER_BIND_SUB_SESSION : TYPE_SERVER_AUTH_SUB_SESSION;
    res = CreateCompatibleSubSession(subSessionType, (CJson *)receviedMsg, &impl->base.callback,
        &impl->compatibleSubSession);
    if (res != HC_SUCCESS) {
        LOGE("create compatibleSubSession fail. [Res]: %" LOG_PUB "d", res);
        return res;
    }
    return HC_SUCCESS;
}

static int32_t ProcV1SessionMsg(SessionImpl *impl, const CJson *receviedMsg, bool *isFinish)
{
    CJson *out = NULL;
    int32_t status;
    int32_t res = ProcessCompatibleSubSession(impl->compatibleSubSession, (CJson *)receviedMsg, &out, &status);
    if (res != HC_SUCCESS) {
        DestroyCompatibleSubSession(impl->compatibleSubSession);
        impl->compatibleSubSession = NULL;
        if (status == FINISH) {
            LOGI("process compatibleSubSession finish.");
            *isFinish = true;
            return HC_SUCCESS;
        } else {
            LOGE("process compatibleSubSession fail. [Res]: %" LOG_PUB "d", res);
            return res;
        }
    }
    *isFinish = false;
    return HC_SUCCESS;
}

static inline bool HasNextAuthGroup(const CJson *receviedMsg)
{
    return GetStringFromJson(receviedMsg, FIELD_ALTERNATIVE) != NULL;
}

static void GenerateErrorReturn(const CJson *receviedMsg, char **errorReturn)
{
    const char *pkInfoStr = GetStringFromJson(receviedMsg, FIELD_AUTH_PK_INFO);
    if (pkInfoStr == NULL) {
        LOGI("receviedMsg without authPkInfo.");
        return;
    }
    CJson *pkInfoJson = CreateJsonFromString(pkInfoStr);
    if (pkInfoJson == NULL) {
        LOGE("create json from string failed.");
        return;
    }

    const char *deviceId = GetStringFromJson(pkInfoJson, FIELD_DEVICE_ID);
    if (deviceId == NULL) {
        LOGI("receviedMsg without devcieId.");
        FreeJson(pkInfoJson);
        return;
    }
    CJson *message = CreateJson();
    if (message == NULL) {
        LOGE("create json failed.");
        FreeJson(pkInfoJson);
        return;
    }
    if (AddStringToJson(message, FIELD_AUTH_ID, deviceId) != HC_SUCCESS) {
        LOGE("add string to json failed.");
        FreeJson(message);
        FreeJson(pkInfoJson);
        return;
    }

    *errorReturn = PackJsonToString(message);
    if (*errorReturn == NULL) {
        LOGE("Pack authId Json To String fail.");
    }
    FreeJson(message);
    FreeJson(pkInfoJson);
}

static void OnV1SessionError(SessionImpl *impl, int32_t errorCode, const CJson *receviedMsg)
{
    bool isSingleCred = false;
    (void)GetBoolFromJson(impl->context, FIELD_IS_SINGLE_CRED, &isSingleCred);
    if (HasNextAuthGroup(receviedMsg) && !isSingleCred) {
        return;
    }
    char *errorReturn = NULL;
    GenerateErrorReturn(receviedMsg, &errorReturn);
    OnDevSessionError(impl, errorCode, errorReturn, true);
    FreeJsonString(errorReturn);
}

static int32_t ProcV1Session(SessionImpl *impl, const CJson *receviedMsg, bool *isFinish)
{
    ReportBehaviorEvent(impl, false, false, HC_SUCCESS);
    int32_t res;
    if (impl->compatibleSubSession == NULL) {
        res = InitServerV1Session(impl, receviedMsg);
        if (res != HC_SUCCESS) {
            ReportBehaviorEvent(impl, true, false, res);
            OnV1SessionError(impl, res, receviedMsg);
            return res;
        }
    }
    res = ProcV1SessionMsg(impl, receviedMsg, isFinish);
    ReportBehaviorEvent(impl, true, false, res);
    if (*isFinish) {
        ReportBehaviorEvent(impl, false, true, HC_SUCCESS);
    }
    if (res != HC_SUCCESS) {
        OnV1SessionError(impl, res, receviedMsg);
    }
    return res;
}

static char *GetSessionReturnData(const SessionImpl *impl)
{
    CJson *returnData = CreateJson();
    if (returnData == NULL) {
        LOGW("allocate returnData memory fail.");
        return NULL;
    }
    if (!impl->isCredAuth) {
        const char *groupId = GetStringFromJson(impl->context, FIELD_GROUP_ID);
        if (groupId == NULL) {
            LOGW("get groupId from context fail.");
            FreeJson(returnData);
            return NULL;
        }
        if (AddStringToJson(returnData, FIELD_GROUP_ID, groupId) != HC_SUCCESS) {
            LOGW("add groupId to returnData fail.");
            FreeJson(returnData);
            return NULL;
        }
    }
    char *returnDataStr = PackJsonToString(returnData);
    FreeJson(returnData);
    if (returnDataStr == NULL) {
        LOGW("pack returnData to returnDataStr fail.");
    }
    return returnDataStr;
}

static void OnDevSessionFinish(const SessionImpl *impl)
{
    ReportBehaviorEvent(impl, false, true, HC_SUCCESS);
    UPDATE_PERFORM_DATA_BY_INPUT_INDEX(impl->base.id, ON_SESSION_KEY_RETURN_TIME, HcGetCurTimeInMillis());
    ProcessSessionKeyCallback(impl->base.id, impl->sessionKey.val, impl->sessionKey.length, &impl->base.callback);

    char *returnData = GetSessionReturnData(impl);
    UPDATE_PERFORM_DATA_BY_INPUT_INDEX(impl->base.id, ON_FINISH_TIME, HcGetCurTimeInMillis());
    ProcessFinishCallback(impl->base.id, impl->base.opCode, returnData, &impl->base.callback);
    FreeJsonString(returnData);

    bool isBind = true;
    (void)GetBoolFromJson(impl->context, FIELD_IS_BIND, &isBind);
    if (isBind) {
        NotifyBindResult(impl->channelType, impl->channelId);
    }
    ReportBindAndAuthCallEvent(impl, HC_SUCCESS, false);
    CloseChannel(impl->channelType, impl->channelId);
}

static int32_t ProcV2Session(SessionImpl *impl, const CJson *receviedMsg, bool *isFinish)
{
    ReportBehaviorEvent(impl, false, false, HC_SUCCESS);
    if (impl->compatibleSubSession != NULL) {
        DestroyCompatibleSubSession(impl->compatibleSubSession);
        impl->compatibleSubSession = NULL;
    }
    int32_t res;
    do {
        res = ParseAllRecvEvent(impl, receviedMsg);
        if (res != HC_SUCCESS) {
            break;
        }
        res = ProcEventList(impl);
    } while (0);
    ReportBehaviorEvent(impl, true, false, res);
    if (res != HC_SUCCESS) {
        OnDevSessionError(impl, res, NULL, false);
        return res;
    }
    if (impl->curState == SESSION_FINISH_STATE) {
        *isFinish = true;
        OnDevSessionFinish(impl);
    } else {
        *isFinish = false;
    }
    return HC_SUCCESS;
}

static int32_t ProcessSession(DevSession *self, const CJson *receviedMsg, bool *isFinish)
{
    if ((self == NULL) || (receviedMsg == NULL) || (isFinish == NULL)) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    SessionImpl *impl = (SessionImpl *)self;
    if (!IsSupportSessionV2() || IsV1SessionMsg(receviedMsg)) {
        return ProcV1Session(impl, receviedMsg, isFinish);
    } else {
        return ProcV2Session(impl, receviedMsg, isFinish);
    }
}

static int32_t BuildDevSessionByContext(const CJson *context, SessionImpl *session)
{
    int32_t opCode;
    if (GetIntFromJson(context, FIELD_OPERATION_CODE, &opCode) != HC_SUCCESS) {
        LOGE("get opCode from context fail.");
        return HC_ERR_JSON_GET;
    }
    int32_t channelType;
    if (GetIntFromJson(context, FIELD_CHANNEL_TYPE, &channelType) != HC_SUCCESS) {
        LOGE("get channelType from context fail.");
        return HC_ERR_JSON_GET;
    }
    int64_t channelId;
    if (GetByteFromJson(context, FIELD_CHANNEL_ID, (uint8_t *)&channelId, sizeof(int64_t)) != HC_SUCCESS) {
        LOGE("get channelId from context fail.");
        return HC_ERR_JSON_GET;
    }
    bool isClient;
    if (GetBoolFromJson(context, FIELD_IS_CLIENT, &isClient) != HC_SUCCESS) {
        LOGE("get isClient from context fail.");
        return HC_ERR_JSON_GET;
    }
    bool isCredAuth = false;
    (void)GetBoolFromJson(context, FIELD_IS_CRED_AUTH, &isCredAuth);
    session->base.opCode = opCode;
    session->channelType = channelType;
    session->channelId = channelId;
    session->isClient = isClient;
    session->isCredAuth = isCredAuth;
    return HC_SUCCESS;
}

static int32_t BuildDevSession(int64_t sessionId, const char *appId, SessionInitParams *params, SessionImpl *session)
{
    int32_t res = BuildDevSessionByContext(params->context, session);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = DeepCopyString(appId, &session->base.appId);
    if (res != HC_SUCCESS) {
        LOGE("copy appId fail.");
        return res;
    }
    CJson *copyContext = DuplicateJson(params->context);
    if (copyContext == NULL) {
        LOGE("copy context fail.");
        HcFree(session->base.appId);
        return HC_ERR_ALLOC_MEMORY;
    }
    session->base.id = sessionId;
    session->base.start = StartSession;
    session->base.process = ProcessSession;
    session->base.destroy = DestroySession;
    session->context = copyContext;
    session->base.callback = params->callback;
    session->curState = session->isClient ? INIT_CLIENT_STATE : INIT_SERVER_STATE;
    session->restartState = session->curState;
    session->credCurIndex = 0;
    session->credTotalNum = 0;
    session->credList = CreateIdentityInfoVec();
    session->eventList = CreateEventList();
    session->authSubSessionList = CreateAuthSubSessionList();
    return HC_SUCCESS;
}

int32_t CreateDevSession(int64_t sessionId, const char *appId, SessionInitParams *params, DevSession **returnObj)
{
    if (appId == NULL || params == NULL || returnObj == NULL) {
        LOGE("invalid params.");
        return HC_ERR_INVALID_PARAMS;
    }
    SessionImpl *session = (SessionImpl *)HcMalloc(sizeof(SessionImpl), 0);
    if (session == NULL) {
        LOGE("allocate session memory fail.");
        return HC_ERR_ALLOC_MEMORY;
    }
    int32_t res = BuildDevSession(sessionId, appId, params, session);
    if (res != HC_SUCCESS) {
        HcFree(session);
        return res;
    }
    *returnObj = (DevSession *)session;
    return HC_SUCCESS;
}
