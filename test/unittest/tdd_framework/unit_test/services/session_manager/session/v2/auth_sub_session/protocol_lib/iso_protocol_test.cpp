/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "device_auth_defines.h"
#include "exception_controller.h"
#include "hc_types.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_type.h"
#include "iso_protocol.h"
#include "json_utils.h"
#include "memory_mock.h"
#include "memory_monitor.h"
#include "uint8buff_utils.h"
#include "device_auth.h"

using namespace std;
using namespace testing::ext;

namespace {
#define PSK_SIZE 32
static const uint8_t PSK_VAL[PSK_SIZE] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
static const char *AUTH_ID_C_VAL = "5420459D93FE773F9945FD64277FBA2CAB8FB996DDC1D0B97676FBB1242B3930";
static const char *AUTH_ID_S_VAL = "52E2706717D5C39D736E134CC1E3BE1BAA2AA52DB7C76A37C749558BD2E6492C";
static const char *MSG_C_VAL = "client send msg";
static const char *MSG_S_VAL = "server send msg";

static Uint8Buff g_psk = { (uint8_t *)PSK_VAL, PSK_SIZE };
static Uint8Buff g_authIdC = { (uint8_t *)AUTH_ID_C_VAL, 64 };
static Uint8Buff g_authIdS = { (uint8_t *)AUTH_ID_S_VAL, 64 };
static Uint8Buff g_msgC = { (uint8_t *)MSG_C_VAL, 16 };
static Uint8Buff g_msgS = { (uint8_t *)MSG_S_VAL, 16 };
static IsoInitParams g_paramsC = { g_authIdC, DEFAULT_OS_ACCOUNT };
static IsoInitParams g_paramsS = { g_authIdS, DEFAULT_OS_ACCOUNT };

class IsoProtocolTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void IsoProtocolTest::SetUpTestCase()
{
    HksInitialize();
}

void IsoProtocolTest::TearDownTestCase() {}

void IsoProtocolTest::SetUp()
{
    InitExceptionController();
    HcInitMallocMonitor();
    cJSON_Hooks hooks = {
        .malloc_fn = MockMallocForJson,
        .free_fn = MockFree
    };
    cJSON_InitHooks(&hooks);
}

void IsoProtocolTest::TearDown()
{
    bool isMemoryLeak = IsMemoryLeak();
    EXPECT_FALSE(isMemoryLeak);
    if (isMemoryLeak) {
        ReportMonitor();
    }
    cJSON_Hooks hooks = {
        .malloc_fn = malloc,
        .free_fn = free
    };
    cJSON_InitHooks(&hooks);
    HcDestroyMallocMonitor();
    DestroyExceptionController();
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest001, TestSize.Level0)
{
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);
    self->destroy(self);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest002, TestSize.Level0)
{
    BaseProtocol *client;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &client);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(client, nullptr);

    BaseProtocol *server;
    res = CreateIsoProtocol(&g_paramsS, false, &server);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(server, nullptr);

    res = client->setPsk(client, &g_psk);
    ASSERT_EQ(res, HC_SUCCESS);
    res = server->setPsk(server, &g_psk);
    ASSERT_EQ(res, HC_SUCCESS);

    CJson *clientOut = nullptr;
    CJson *serverOut = nullptr;

    res = client->setSelfProtectedMsg(client, &g_msgC);
    ASSERT_EQ(res, HC_SUCCESS);
    res = client->setPeerProtectedMsg(client, &g_msgS);
    ASSERT_EQ(res, HC_SUCCESS);
    res = server->setSelfProtectedMsg(server, &g_msgS);
    ASSERT_EQ(res, HC_SUCCESS);
    res = server->setPeerProtectedMsg(server, &g_msgC);
    ASSERT_EQ(res, HC_SUCCESS);

    res = client->start(client, &clientOut);
    ASSERT_EQ(res, HC_SUCCESS);

    while (clientOut != nullptr || serverOut != nullptr) {
        if (clientOut != nullptr) {
            res = server->process(server, clientOut, &serverOut);
            ASSERT_EQ(res, HC_SUCCESS);
            FreeJson(clientOut);
            clientOut = nullptr;
        } else {
            res = client->process(client, serverOut, &clientOut);
            ASSERT_EQ(res, HC_SUCCESS);
            FreeJson(serverOut);
            serverOut = nullptr;
        }
    }
    Uint8Buff clientKey = { nullptr, 0 };
    res = client->getSessionKey(client, &clientKey);
    ASSERT_EQ(res, HC_SUCCESS);
    FreeUint8Buff(&clientKey);
    Uint8Buff serverKey = { nullptr, 0 };
    res = server->getSessionKey(server, &serverKey);
    ASSERT_EQ(res, HC_SUCCESS);
    FreeUint8Buff(&serverKey);

    client->destroy(client);
    server->destroy(server);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest003, TestSize.Level0)
{
    BaseProtocol *client;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &client);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(client, nullptr);

    BaseProtocol *server;
    res = CreateIsoProtocol(&g_paramsS, false, &server);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(server, nullptr);

    res = client->setPsk(client, &g_psk);
    ASSERT_EQ(res, HC_SUCCESS);
    res = server->setPsk(server, &g_psk);
    ASSERT_EQ(res, HC_SUCCESS);

    CJson *clientOut = nullptr;
    CJson *serverOut = nullptr;

    res = client->start(client, &clientOut);
    ASSERT_EQ(res, HC_SUCCESS);

    while (clientOut != nullptr || serverOut != nullptr) {
        if (clientOut != nullptr) {
            res = server->process(server, clientOut, &serverOut);
            ASSERT_EQ(res, HC_SUCCESS);
            FreeJson(clientOut);
            clientOut = nullptr;
        } else {
            res = client->process(client, serverOut, &clientOut);
            ASSERT_EQ(res, HC_SUCCESS);
            FreeJson(serverOut);
            serverOut = nullptr;
        }
    }
    Uint8Buff clientKey;
    res = client->getSessionKey(client, &clientKey);
    ASSERT_EQ(res, HC_SUCCESS);
    FreeUint8Buff(&clientKey);
    Uint8Buff serverKey;
    res = server->getSessionKey(server, &serverKey);
    ASSERT_EQ(res, HC_SUCCESS);
    FreeUint8Buff(&serverKey);

    client->destroy(client);
    server->destroy(server);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest101, TestSize.Level0)
{
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(nullptr, true, &self);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest102, TestSize.Level0)
{
    int32_t res = CreateIsoProtocol(&g_paramsC, true, nullptr);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest103, TestSize.Level0)
{
    IsoInitParams errParams = { { nullptr, 32 }, DEFAULT_OS_ACCOUNT };
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&errParams, true, &self);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest104, TestSize.Level0)
{
    IsoInitParams errParams = { { (uint8_t *)AUTH_ID_C_VAL, 0 }, DEFAULT_OS_ACCOUNT };
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&errParams, true, &self);
    ASSERT_NE(res, HC_SUCCESS);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest105, TestSize.Level0)
{
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    res = self->setPsk(nullptr, &g_psk);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest106, TestSize.Level0)
{
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    res = self->setPsk(self, nullptr);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest107, TestSize.Level0)
{
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    Uint8Buff errParams = { nullptr, PSK_SIZE };
    res = self->setPsk(self, &errParams);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest108, TestSize.Level0)
{
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    Uint8Buff errParams = { (uint8_t *)PSK_VAL, 0 };
    res = self->setPsk(self, &errParams);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest109, TestSize.Level0)
{
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    CJson *out = nullptr;
    res = self->start(nullptr, &out);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest110, TestSize.Level0)
{
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    res = self->start(self, nullptr);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest111, TestSize.Level0)
{
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    self->curState = self->finishState;

    CJson *out = nullptr;
    res = self->start(self, &out);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest112, TestSize.Level0)
{
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    self->curState = self->failState;

    CJson *out = nullptr;
    res = self->start(self, &out);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest113, TestSize.Level0)
{
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    CJson recvMsg;
    CJson *sendMsg = nullptr;
    res = self->process(nullptr, &recvMsg, &sendMsg);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest114, TestSize.Level0)
{
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    CJson *sendMsg = nullptr;
    res = self->process(self, nullptr, &sendMsg);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest115, TestSize.Level0)
{
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    CJson recvMsg;
    res = self->process(self, &recvMsg, nullptr);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest116, TestSize.Level0)
{
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    self->curState = self->finishState;

    CJson recvMsg;
    CJson *sendMsg = nullptr;
    res = self->process(self, &recvMsg, &sendMsg);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest117, TestSize.Level0)
{
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    self->curState = self->failState;

    CJson recvMsg;
    CJson *sendMsg = nullptr;
    res = self->process(self, &recvMsg, &sendMsg);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest118, TestSize.Level0)
{
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    res = self->setSelfProtectedMsg(nullptr, &g_msgC);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest119, TestSize.Level0)
{
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    res = self->setSelfProtectedMsg(self, nullptr);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest120, TestSize.Level0)
{
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    res = self->setPeerProtectedMsg(nullptr, &g_msgS);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest121, TestSize.Level0)
{
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    res = self->setPeerProtectedMsg(self, nullptr);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest122, TestSize.Level0)
{
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    Uint8Buff key = { nullptr, 0 };
    res = self->getSessionKey(nullptr, &key);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest123, TestSize.Level0)
{
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    res = self->getSessionKey(self, nullptr);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest124, TestSize.Level0)
{
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    Uint8Buff key = { nullptr, 0 };
    res = self->getSessionKey(self, &key);
    ASSERT_NE(res, HC_SUCCESS);

    self->destroy(self);
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest125, TestSize.Level0)
{
    BaseProtocol *self;
    int32_t res = CreateIsoProtocol(&g_paramsC, true, &self);
    ASSERT_EQ(res, HC_SUCCESS);
    ASSERT_NE(self, nullptr);

    self->destroy(nullptr);
    self->destroy(self);
}

static int32_t LoopProcess(BaseProtocol *client, BaseProtocol *server)
{
    CJson *clientOut = nullptr;
    CJson *serverOut = nullptr;
    int32_t res = client->start(client, &clientOut);
    if (res != HC_SUCCESS) {
        return res;
    }
    while (clientOut != nullptr || serverOut != nullptr) {
        if (clientOut != nullptr) {
            res = server->process(server, clientOut, &serverOut);
            if (res != HC_SUCCESS) {
                break;
            }
            FreeJson(clientOut);
            clientOut = nullptr;
        } else {
            res = client->process(client, serverOut, &clientOut);
            if (res != HC_SUCCESS) {
                break;
            }
            FreeJson(serverOut);
            serverOut = nullptr;
        }
    }
    if (clientOut != nullptr) {
        FreeJson(clientOut);
        clientOut = nullptr;
    }
    if (serverOut != nullptr) {
        FreeJson(serverOut);
        serverOut = nullptr;
    }
    return res;
}

static int32_t TestMemoryInner(BaseProtocol **clientPtr, BaseProtocol **serverPtr,
    Uint8Buff *clientKey, Uint8Buff *serverKey)
{
    int32_t res = CreateIsoProtocol(&g_paramsC, true, clientPtr);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = CreateIsoProtocol(&g_paramsS, false, serverPtr);
    if (res != HC_SUCCESS) {
        return res;
    }
    BaseProtocol *client = *clientPtr;
    BaseProtocol *server = *serverPtr;
    res = client->setPsk(client, &g_psk);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = server->setPsk(server, &g_psk);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = client->setSelfProtectedMsg(client, &g_msgC);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = client->setPeerProtectedMsg(client, &g_msgS);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = server->setSelfProtectedMsg(server, &g_msgS);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = server->setPeerProtectedMsg(server, &g_msgC);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = LoopProcess(client, server);
    if (res != HC_SUCCESS) {
        return res;
    }
    res = client->getSessionKey(client, clientKey);
    if (res != HC_SUCCESS) {
        return res;
    }
    return server->getSessionKey(server, serverKey);
}

static int32_t TestMemoryException(void)
{
    BaseProtocol *client = nullptr;
    BaseProtocol *server = nullptr;
    Uint8Buff clientKey = { nullptr, 0 };
    Uint8Buff serverKey = { nullptr, 0 };
    int32_t res = TestMemoryInner(&client, &server, &clientKey, &serverKey);
    if (client != nullptr) {
        client->destroy(client);
    }
    if (server != nullptr) {
        server->destroy(server);
    }
    FreeUint8Buff(&clientKey);
    FreeUint8Buff(&serverKey);
    return res;
}

HWTEST_F(IsoProtocolTest, IsoProtocolTest126, TestSize.Level0)
{
    SetControllerMode(true);
    int32_t res = TestMemoryException();
    ASSERT_EQ(res, HC_SUCCESS);

    uint32_t callNum = GetCallNum();
    for (uint32_t i = 0; i < callNum; i++) {
        SetThrowExceptionIndex(i);
        (void)TestMemoryException();
        bool isMemoryLeak = IsMemoryLeak();
        EXPECT_FALSE(isMemoryLeak);
        if (isMemoryLeak) {
            ReportMonitor();
            break;
        }
    }
}
}
