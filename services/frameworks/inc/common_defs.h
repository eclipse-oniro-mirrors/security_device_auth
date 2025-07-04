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

#ifndef COMMON_DEFS_H
#define COMMON_DEFS_H

#include "device_auth.h"
#include "device_auth_defines.h"
#include "hc_string.h"
#include "hc_vector.h"
#include "json_utils.h"

#define FIELD_DEVICE_PK "devicePk"
#define FIELD_UDID "udid"
#define FIELD_PK_INFO_SIGNATURE "pkInfoSignature"
#define FIELD_CREDENTIAL "credential"
#define FIELD_SERVER_PK "serverPk"

#define FIELD_ADD_TYPE "addType"
#define FIELD_ADD_ID "addId"
#define FIELD_ADD_KEY "addKey"
#define FIELD_AUTH_DATA "authData"
#define FIELD_AUTH_RETURN "authReturn"
#define FIELD_AUTH_ID "authId"
#define FIELD_AUTH_PK "authPk"
#define FIELD_ADD_AUTH_INFO "addAuthInfo"
#define FIELD_ADD_RETURN "addReturn"
#define FIELD_APP_ID "appId"
#define FIELD_BIND_SESSION_TYPE "bindSessionType"
#define FIELD_CHALLENGE "challenge"
#define FIELD_CHANNEL_ID "channelId"
#define FIELD_CHANNEL_TYPE "channelType"
#define FIELD_CONN_DEVICE_ID "connDeviceId"
#define FIELD_CONNECT_PARAMS "connectParams"
#define FIELD_CROSS_USER_ID_LIST "crossUserIdList"
#define FIELD_CURRENT_VERSION "currentVersion"
#define FIELD_DELETE_ID "deleteId"
#define FIELD_DELETED_RESULT "deletedResult"
#define FIELD_DEVICE_CLOUD_CREDENTIAL "devCloudCred"
#define FIELD_DEV_ID "devId"
#define FIELD_DEVICES_CREDENTIAL "devicesCredential"
#define FIELD_ENC_AUTH_TOKEN "encAuthToken"
#define FIELD_ENC_RESULT "encResult"
#define FIELD_ENC_DATA "encData"
#define FIELD_EPK "epk"
#define FIELD_EPK_LEN "epkLen"
#define FIELD_EX_AUTH_INFO "exAuthInfo"
#define FIELD_EXPIRE_TIME "expireTime"
#define FIELD_ERROR_CODE "errorCode"
#define FIELD_GROUP_INFO "groupInfo"
#define FIELD_GROUP_MANAGERS "groupManagers"
#define FIELD_GROUP_NAME "groupName"
#define FIELD_GROUP_OP "groupOp"
#define FIELD_GROUP_TYPE "groupType"
#define FIELD_GROUP_VISIBILITY "groupVisibility"
#define FIELD_IS_ADMIN "isAdmin"
#define FIELD_IS_ACCOUNT_BIND "isAccountBind"
#define FIELD_IS_BIND "isBind"
#define FIELD_IS_FORCE_DELETE "isForceDelete"
#define FIELD_IS_CREDENTIAL_EXISTS "isCredentialExists"
#define FIELD_IS_DIRECT_AUTH "isDirectAuth"
#define FIELD_KCF_DATA "kcfData"
#define FIELD_KEY_TYPE "keyType"
#define FIELD_TRUST_TYPE "trustType"
#define FIELD_MESSAGE "message"
#define FIELD_GROUP_ERROR_MSG "groupErrorMsg"
#define FIELD_MIN_VERSION "minVersion"
#define FIELD_GROUP_AND_MODULE_VERSION "groupAndModuleVersion"
#define FIELD_NONCE "nonce"
#define FIELD_OP_CODE "opCode"
#define FIELD_OPERATION_CODE "operationCode"
#define FIELD_OPERATION_PARAMS "operationParams"
#define FIELD_OWNER_ID "ownerId"
#define FIELD_OWNER_NAME "ownerName"
#define FIELD_PERMISSION "Permission"
#define FIELD_PAYLOAD "payload"
#define FIELD_PIN_CODE "pinCode"
#define FIELD_PUBLIC_KEY "publicKey"
#define FIELD_SIGN_ALG "signAlg"
#define FIELD_PK_INFO "pkInfo"
#define FIELD_REAL_INFO "realInfo"
#define FIELD_PSEUDONYM_ID "pseudonymId"
#define FIELD_INDEX_KEY "indexKey"
#define FIELD_PKG_NAME "pkgName"
#define FIELD_SELF_AUTH_ID "selfAuthId"
#define FIELD_SELF_DEVICE_ID "selfDeviceId"
#define FIELD_SELF_DEV_ID "selfDevId"
#define FIELD_SELF_USER_ID "selfUserId"
#define FIELD_REQUEST_ID "requestId"
#define FIELD_RECEIVED_DATA "receivedData"
#define FIELD_RETURN_CODE "returnCode"
#define FIELD_RETURN_DATA "returnData"
#define FIELD_RETURN_CODE_MAC "returnCodeMac"
#define FIELD_RMV_TYPE "rmvType"
#define FIELD_RMV_ID "rmvId"
#define FIELD_RMV_AUTH_INFO "rmvAuthInfo"
#define FIELD_RMV_RETURN "rmvReturn"
#define FIELD_SALT "salt"
#define FIELD_ISO_SALT "isoSalt"
#define FIELD_SEED "seed"
#define FIELD_SELF_TYPE "selfType"
#define FIELD_SEND_TO_PEER "sendToPeer"
#define FIELD_SEND_TO_SELF "sendToSelf"
#define FIELD_SHARED_USER_ID_LIST "sharedUserIdList"
#define FIELD_SUPPORT_256_MOD "support256mod"
#define FIELD_TOKEN "token"
#define FIELD_IS_UUID "uuIdAsDeviceId"
#define FIELD_VERSION "version"
#define FIELD_MK_AGREE_MSG "mkaMsg"
#define FIELD_PEER_ID_FROM_REQUEST "peerIdFromRequest"
#define FIELD_STEP "step"
#define FIELD_DATA "data"
#define FIELD_AUTH_KEY_ALG_ENCODE "authKeyAlgEncode"
#define FIELD_AUTH_PK_INFO "authPkInfo"
#define FIELD_AUTH_PK_INFO_SIGN "authPkInfoSign"
#define FIELD_AUTH_RESULT_MAC "authResultMac"
#define FIELD_LOCAL_DEVICE_TYPE "localDeviceType"
#define FIELD_PLUGIN_EXT_DATA "originPeerData"
#define FIELD_META_NODE_TYPE "metaNodeType"
#define FIELD_UPGRADE_FLAG "upgradeFlag"
#define FIELD_COMMON_EVENT_NAME "commonEventName"
#define FIELD_COMMON_EVENT_CODE "commonEventCode"
#define FIELD_IS_SINGLE_CRED "isSingleCred"
#define FIELD_ACCOUNT_PEER_PK_WITH_SIG "peerPkWithSig"
#define FIELD_ACCOUNT_SERVICE_ID "serviceId"
#define FIELD_ACCOUNT_SHARED_KEY_LEN "sharedKeyLen"
#define FIELD_ACCOUNT_SHARED_KEY_VAL "sharedKeyVal"
#define FIELD_ACCOUNT_RANDOM_LEN "randomLen"
#define FIELD_ACCOUNT_RANDOM_VAL "randomVal"
#define FIELD_LIGHT_ACCOUNT_MSG "lightAccountMsg"
#define FIELD_PEER_ACCOUNT_RANDOM_LEN "peerRandomLen"
#define FIELD_PEER_ACCOUNT_RANDOM_VAL "peerRandomVal"

#define INVALID_MODULE_TYPE (-1)
#define GROUP_ERR_MSG 0x8080

#define CLIENT 1
#define SERVER 0

#define CREATE_KEY_PAIR 1
#define DELETE_KEY_PAIR 2

/* DefaultValue */
#define DEFAULT_MEMORY_SIZE 64
#define DEFAULT_USER_ID_HASH ""
#define DEFAULT_REQUEST_ID 0
#define DEFAULT_CHANNEL_ID (-1)
#define DEFAULT_EXPIRE_TIME 90
#define DEFAULT_SERVICE_TYPE "service.type.default"
#define SERVICE_TYPE_IMPORT "service.type.import"
#define DEFAULT_PACKAGE_NAME "deviceauth_service"
#define GROUP_MANAGER_PACKAGE_NAME "com.huawei.devicegroupmanage"
#define DM_APP_ID "ohos.distributedhardware.devicemanager"
#define SOFTBUS_APP_ID "softbus_auth"
#define DEFAULT_RETURN_KEY_LENGTH 32
#define MAX_BUFFER_LEN 1024
#define MAX_DATA_BUFFER_SIZE 4096
#define MAX_AUTH_ID_LEN 256
#define MAX_REQUEST_ID_LEN 128

#define IS_UPGRADE 1
#define IS_NOT_UPGRADE 0

#define COMPATIBLE_GROUP 512
#define GROUP_TYPE_INVALID (-1)
#define INVALID_OS_ACCOUNT (-1)
#define ALL_GROUP_VISIBILITY (-2)
#define INVALID_CRED 0
#define PUBLIC_KEY_MAX_LENGTH 128
#define PIN_CODE_LEN_SHORT 6
#define PIN_CODE_LEN_LONG 128
#define INVALID_PROTOCOL_EXPAND_VALUE (-1)

typedef enum {
    NO_CHANNEL = 1,
    SERVICE_CHANNEL = 2,
    SOFT_BUS = 3,
} ChannelType;

typedef enum {
    SELF_CREATED = 0,
    IMPORTED_FROM_CLOUD = 1,
} RelationShipSource;

#define MAX_IN_PARAM_LEN 4096

#define CHECK_PTR_RETURN_NULL(ptr, paramTag) \
    do { \
        if ((ptr) == NULL) { \
            LOGE(paramTag " is null ptr"); \
            return NULL; \
        } \
    } while (0)

#define CHECK_PTR_RETURN_ERROR_CODE(ptr, paramTag) \
    do { \
        if ((ptr) == NULL) { \
            LOGE(paramTag " is null ptr"); \
            return HC_ERR_NULL_PTR; \
        } \
    } while (0)

#define CHECK_PTR_RETURN_NONE(ptr, paramTag) \
        do { \
            if ((ptr) == NULL) { \
                LOGE(paramTag " is null ptr"); \
                return; \
            } \
        } while (0)

#define GOTO_IF_ERR(x) do { \
        int32_t res = x; \
        if ((res) != HC_SUCCESS) { \
            goto ERR; \
        } \
    } while (0)

#define GOTO_IF_CHECK_NULL(ptr, paramTag) \
    do { \
        if ((ptr) == NULL) { \
            LOGE(paramTag " is null ptr"); \
            goto ERR; \
        } \
    } while (0)

#define GOTO_ERR_AND_SET_RET(x, res) do { \
        res = x; \
        if ((res) != HC_SUCCESS) { \
            goto ERR; \
        } \
    } while (0)

#define RETURN_IF_ERR(x) do { \
        int32_t res = x; \
        if ((res) != HC_SUCCESS) { \
            return res; \
        } \
    } while (0)

typedef enum {
    ACCOUNT_RELATED_PLUGIN = 0x0010,
} EnumCredPluginType;

typedef enum {
    DAS_MODULE = 0x0001,
    ACCOUNT_MODULE = 0x0010,
} EnumModuleType;

typedef enum {
    CONTINUE = 0,
    IGNORE_MSG = 1,
    FINISH,
} TaskStatus;

typedef enum {
    CODE_NULL = 0,
    OP_BIND = 1,
    AUTHENTICATE = 2,
    ADD_AUTH_INFO = 3,
    REMOVE_AUTH_INFO = 4,
    OP_UNBIND = 5,
    AUTH_KEY_AGREEMENT = 6,
    REGISTER = 7,
    SECURE_CLONE = 8,
} OperationCode;

typedef enum {
    IMPORT_SELF_CREDENTIAL = 0,
    DELETE_SELF_CREDENTIAL = 1,
    QUERY_SELF_CREDENTIAL_INFO = 2,
    IMPORT_TRUSTED_CREDENTIALS = 3,
    DELETE_TRUSTED_CREDENTIALS = 4,
    QUERY_TRUSTED_CREDENTIALS = 5,
    REQUEST_SIGNATURE = 6,
    GET_SHARED_SECRET_BY_PEER_CERT = 8,
    UPGRADE_DATA = 10,
    CHECK_UPGRADE_IDENTITY = 11,
    CHECK_UPGRADE_DATA = 12,
    HANDLE_COMMON_EVENT = 13,
    RELOAD_CRED_MGR = 14,
    ACCOUNT_GET_CLIENT_SHARED_KEY = 15,
    ACCOUNT_GET_SERVER_SHARED_KEY = 16,
    QUERY_ACCOUNT_STATE_BY_USER_ID = 17,
    LIGHT_ACCOUNT_AUTH_START = 18,
    LIGHT_ACCOUNT_AUTH_PROCESS_CLIENT = 19,
    LIGHT_ACCOUNT_AUTH_PROCESS_SERVER = 20,
    LIGHT_ACCOUNT_AUTH_VERIFY_SIGN = 21,
} CredentialCode;

#endif
