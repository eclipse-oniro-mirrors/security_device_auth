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

#include <cinttypes>
#include <unistd.h>
#include <gtest/gtest.h>
#include "securec.h"
#include "common_defs.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "json_utils.h"
#include "hc_log.h"
#include "hc_types.h"
#include "hc_file.h"
#include "string_util.h"
#include "huks_adapter.h"

#define GetLoaderInstance GetLoaderInstance_TestOverride  // NOLINT
extern "C" const AlgLoader *GetLoaderInstance_TestOverride(void);
#include "base/security/device_auth/services/data_manager/cred_data_manager/src/credential_data_manager.c"
#undef GetLoaderInstance

#include "cred_listener.h"
using namespace std;
using namespace testing::ext;

namespace {
#define DEFAULT_OS_ACCOUNT 100

static AlgLoader g_mockLoader;
static bool g_mockInited = false;
static volatile bool g_useMock = false;
static int32_t g_mockGenKeyRet = HAL_SUCCESS;
static int32_t g_mockEncRet = HAL_SUCCESS;
static int32_t g_mockDecRet = HAL_SUCCESS;
static volatile bool g_mockKeyExistEnabled = false;
static int32_t g_mockKeyExistRet = HAL_SUCCESS;

static int32_t MockGenKey(const KeyParams *kp, uint32_t keyLen, KeyPurpose purpose)
{
    if (g_mockGenKeyRet != HAL_SUCCESS) {
        return g_mockGenKeyRet;
    }
    return GetRealLoaderInstance()->generateAesGcmKeyWithStorage(kp, keyLen, purpose);
}

static int32_t MockEncrypt(const KeyParams *kp, const Uint8Buff *plain,
    const GcmParam *enc, Uint8Buff *cipher)
{
    if (g_mockEncRet != HAL_SUCCESS) {
        return g_mockEncRet;
    }
    return GetRealLoaderInstance()->aesGcmEncrypt(kp, plain, enc, cipher);
}

static int32_t MockDecrypt(const KeyParams *kp, const Uint8Buff *cipher,
    const GcmParam *dec, Uint8Buff *plain)
{
    if (g_mockDecRet != HAL_SUCCESS) {
        return g_mockDecRet;
    }
    return GetRealLoaderInstance()->aesGcmDecrypt(kp, cipher, dec, plain);
}

static int32_t MockCheckKeyExist(const Uint8Buff *alias, bool isDe, int32_t osAccount)
{
    if (g_mockKeyExistEnabled) {
        return g_mockKeyExistRet;
    }
    return GetRealLoaderInstance()->checkKeyExist(alias, isDe, osAccount);
}

static void EnableMockLoader()
{
    if (!g_mockInited) {
        const AlgLoader *real = GetRealLoaderInstance();
        AlgLoader *dst = &g_mockLoader;
        const AlgLoader *src = real;
        if (memcpy_s(dst, sizeof(g_mockLoader), src, sizeof(AlgLoader)) != EOK) {
            return;
        }
        g_mockLoader.generateAesGcmKeyWithStorage = MockGenKey;
        g_mockLoader.aesGcmEncrypt = MockEncrypt;
        g_mockLoader.aesGcmDecrypt = MockDecrypt;
        g_mockLoader.checkKeyExist = MockCheckKeyExist;
        g_mockInited = true;
    }
    g_useMock = true;
}

static void DisableMockLoader()
{
    g_useMock = false;
    g_mockGenKeyRet = HAL_SUCCESS;
    g_mockEncRet = HAL_SUCCESS;
    g_mockDecRet = HAL_SUCCESS;
    g_mockKeyExistEnabled = false;
    g_mockKeyExistRet = HAL_SUCCESS;
}

extern "C" __attribute__((noinline, used))
const AlgLoader *GetLoaderInstance_TestOverride(void)
{
    if (g_useMock) {
        return &g_mockLoader;
    }
    return GetRealLoaderInstance();
}
} // namespace

class CredFileEncryptionTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp();
    void TearDown();
};

void CredFileEncryptionTest::SetUp()
{
    int ret = InitDeviceAuthService();
    EXPECT_EQ(ret, IS_SUCCESS);
    DeleteCredFileEncKey(DEFAULT_OS_ACCOUNT);
}

void CredFileEncryptionTest::TearDown()
{
    DestroyDeviceAuthService();
    DeleteCredFileEncKey(DEFAULT_OS_ACCOUNT);
}

HWTEST_F(CredFileEncryptionTest, CredFileEncryptionTest001, TestSize.Level0)
{
    EXPECT_EQ(EnsureCredFileEncKeyExist(DEFAULT_OS_ACCOUNT), IS_SUCCESS);
    const char *plain = "plain credential tlv payload for round-trip";
    uint32_t plainLen = HcStrlen(plain);
    uint8_t *enc = nullptr;
    uint32_t encLen = 0;
    EXPECT_EQ(EncryptCredFileData(reinterpret_cast<const uint8_t *>(plain),
        plainLen, DEFAULT_OS_ACCOUNT, &enc, &encLen), IS_SUCCESS);
    ASSERT_NE(enc, nullptr);
    EXPECT_GT(encLen, CRED_FILE_ENC_NONCE_LEN + AE_TAG_LEN);
    HcParcel parcel = CreateParcel(0, 0);
    EXPECT_EQ(DecryptCredFileToParcel(enc, encLen, DEFAULT_OS_ACCOUNT, &parcel), IS_SUCCESS);
    EXPECT_EQ(GetParcelDataSize(&parcel), plainLen);
    EXPECT_EQ(memcmp(reinterpret_cast<const uint8_t *>(GetParcelData(&parcel)),
        plain, plainLen), 0);
    DeleteParcel(&parcel);
    HcFree(enc);
}

HWTEST_F(CredFileEncryptionTest, CredFileEncryptionTest002, TestSize.Level0)
{
    EXPECT_EQ(EnsureCredFileEncKeyExist(DEFAULT_OS_ACCOUNT), IS_SUCCESS);
    const char *forged = "forged plaintext tlv that is not valid ciphertext";
    uint32_t forgedLen = HcStrlen(forged);
    HcParcel parcel = CreateParcel(0, 0);
    EXPECT_NE(DecryptCredFileToParcel(reinterpret_cast<const uint8_t *>(forged),
        forgedLen, DEFAULT_OS_ACCOUNT, &parcel), IS_SUCCESS);
    DeleteParcel(&parcel);
}

HWTEST_F(CredFileEncryptionTest, CredFileEncryptionTest003, TestSize.Level0)
{
    EXPECT_FALSE(CredFileEncKeyExist(DEFAULT_OS_ACCOUNT));
    EXPECT_EQ(SaveOsAccountCredDb(DEFAULT_OS_ACCOUNT), IS_SUCCESS);
    EXPECT_FALSE(CredFileEncKeyExist(DEFAULT_OS_ACCOUNT));
    DestroyDeviceAuthService();
    EXPECT_EQ(InitDeviceAuthService(), IS_SUCCESS);
    EXPECT_TRUE(CredFileEncKeyExist(DEFAULT_OS_ACCOUNT));
    EXPECT_TRUE(IsOsAccountCredDataLoaded(DEFAULT_OS_ACCOUNT));
}

HWTEST_F(CredFileEncryptionTest, CredFileEncryptionTest004, TestSize.Level0)
{
    EXPECT_EQ(SaveOsAccountCredDb(DEFAULT_OS_ACCOUNT), IS_SUCCESS);
    EXPECT_EQ(EnsureCredFileEncKeyExist(DEFAULT_OS_ACCOUNT), IS_SUCCESS);
    EXPECT_EQ(SaveOsAccountCredDb(DEFAULT_OS_ACCOUNT), IS_SUCCESS);
    DestroyDeviceAuthService();
    EXPECT_EQ(InitDeviceAuthService(), IS_SUCCESS);
    EXPECT_TRUE(IsOsAccountCredDataLoaded(DEFAULT_OS_ACCOUNT));
}

HWTEST_F(CredFileEncryptionTest, CredFileEncryptionTest005, TestSize.Level0)
{
    EXPECT_EQ(EnsureCredFileEncKeyExist(DEFAULT_OS_ACCOUNT), IS_SUCCESS);
    EXPECT_EQ(EnsureCredFileEncKeyExist(DEFAULT_OS_ACCOUNT), IS_SUCCESS);
    EXPECT_TRUE(CredFileEncKeyExist(DEFAULT_OS_ACCOUNT));
}

HWTEST_F(CredFileEncryptionTest, CredFileEncryptionTest006, TestSize.Level0)
{
    uint8_t shortBuf[10] = {0};
    HcParcel parcel = CreateParcel(0, 0);
    EXPECT_NE(DecryptCredFileToParcel(shortBuf, sizeof(shortBuf),
        DEFAULT_OS_ACCOUNT, &parcel), IS_SUCCESS);
    DeleteParcel(&parcel);
}

HWTEST_F(CredFileEncryptionTest, CredFileEncryptionTest007, TestSize.Level0)
{
    DeleteCredFileEncKey(DEFAULT_OS_ACCOUNT);
    EXPECT_FALSE(CredFileEncKeyExist(DEFAULT_OS_ACCOUNT));
    EXPECT_EQ(EnsureCredFileEncKeyExist(DEFAULT_OS_ACCOUNT), IS_SUCCESS);
    EXPECT_EQ(SaveOsAccountCredDb(DEFAULT_OS_ACCOUNT), IS_SUCCESS);
    EXPECT_TRUE(CredFileEncKeyExist(DEFAULT_OS_ACCOUNT));
}

HWTEST_F(CredFileEncryptionTest, CredFileEncryptionTest008, TestSize.Level0)
{
    EXPECT_EQ(EnsureCredFileEncKeyExist(DEFAULT_OS_ACCOUNT), IS_SUCCESS);
    EXPECT_TRUE(CredFileEncKeyExist(DEFAULT_OS_ACCOUNT));
    DeleteCredFileEncKey(DEFAULT_OS_ACCOUNT);
    EXPECT_FALSE(CredFileEncKeyExist(DEFAULT_OS_ACCOUNT));
}

HWTEST_F(CredFileEncryptionTest, CredFileEncryptionTest009, TestSize.Level0)
{
    DeleteCredFileEncKey(DEFAULT_OS_ACCOUNT);
    EnableMockLoader();
    g_mockGenKeyRet = HAL_ERR_HUKS;
    EXPECT_NE(EnsureCredFileEncKeyExist(DEFAULT_OS_ACCOUNT), IS_SUCCESS);
    DisableMockLoader();
}

HWTEST_F(CredFileEncryptionTest, CredFileEncryptionTest010, TestSize.Level0)
{
    DeleteCredFileEncKey(DEFAULT_OS_ACCOUNT);
    EnableMockLoader();
    g_mockKeyExistEnabled = true;
    g_mockKeyExistRet = HAL_ERR_HUKS;
    EXPECT_NE(EnsureCredFileEncKeyExist(DEFAULT_OS_ACCOUNT), IS_SUCCESS);
    DisableMockLoader();
}

HWTEST_F(CredFileEncryptionTest, CredFileEncryptionTest011, TestSize.Level0)
{
    EXPECT_EQ(EnsureCredFileEncKeyExist(DEFAULT_OS_ACCOUNT), IS_SUCCESS);
    EnableMockLoader();
    g_mockEncRet = HAL_ERR_HUKS;
    uint8_t *enc = nullptr;
    uint32_t encLen = 0;
    EXPECT_NE(EncryptCredFileData(reinterpret_cast<const uint8_t *>("test"),
        4, DEFAULT_OS_ACCOUNT, &enc, &encLen), IS_SUCCESS);
    DisableMockLoader();
}

HWTEST_F(CredFileEncryptionTest, CredFileEncryptionTest012, TestSize.Level0)
{
    EXPECT_EQ(EnsureCredFileEncKeyExist(DEFAULT_OS_ACCOUNT), IS_SUCCESS);
    const char *plain = "data for decrypt fail test";
    uint32_t plainLen = HcStrlen(plain);
    uint8_t *enc = nullptr;
    uint32_t encLen = 0;
    EXPECT_EQ(EncryptCredFileData(reinterpret_cast<const uint8_t *>(plain),
        plainLen, DEFAULT_OS_ACCOUNT, &enc, &encLen), IS_SUCCESS);
    ASSERT_NE(enc, nullptr);
    EnableMockLoader();
    g_mockDecRet = HAL_ERR_HUKS;
    HcParcel parcel = CreateParcel(0, 0);
    EXPECT_NE(DecryptCredFileToParcel(enc, encLen,
        DEFAULT_OS_ACCOUNT, &parcel), IS_SUCCESS);
    DeleteParcel(&parcel);
    DisableMockLoader();
    HcFree(enc);
}

HWTEST_F(CredFileEncryptionTest, CredFileEncryptionTest013, TestSize.Level0)
{
    uint8_t buf[1];
    uint32_t len = 0;
    EXPECT_NE(BuildCredFileEncKeyAlias(DEFAULT_OS_ACCOUNT, buf, 0, &len), IS_SUCCESS);
    HcParcel parcel = CreateParcel(0, 0);
    EXPECT_FALSE(ReadCredFileToParcel("/nonexistent/cred.dat",
        DEFAULT_OS_ACCOUNT, &parcel));
    DeleteParcel(&parcel);
}
