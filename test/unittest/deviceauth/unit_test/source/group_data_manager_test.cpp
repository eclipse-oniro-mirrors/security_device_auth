/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "gtest/gtest.h"
#include "group_data_manager.h"
#include "device_auth_defines.h"
#include "device_auth.h"
#include "common_defs.h"
using namespace testing::ext;
namespace {
static const int32_t TEST_OS_ACCOUNT_ID = 0;
static const char *TEST_OWNER = "test_owner";
static const char *TEST_GROUP_ID = "test_group_id";
static const char *TEST_GROUP_NAME = "test_group_name";
static const char *TEST_USER_ID = "0";
static const char *TEST_SHARED_USER_ID = "test_sharedUser_id";
class GroupDataManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void GroupDataManagerTest::SetUpTestCase(void) {}
void GroupDataManagerTest::TearDownTestCase(void) {}

void GroupDataManagerTest::SetUp(void)
{
    InitDatabase();
}

void GroupDataManagerTest::TearDown(void)
{
    DestroyDatabase();
}

static TrustedGroupEntry *generateTestGroupEntry(void)
{
    TrustedGroupEntry *entry = CreateGroupEntry();
    if (entry == NULL) {
        return NULL;
    }
    entry->type = ALL_GROUP;
    entry->visibility = ALL_GROUP_VISIBILITY;
    HcString ownerName = CreateString();
    StringSetPointer(&(ownerName), TEST_OWNER);
    entry->managers.pushBack(&entry->managers, &ownerName);
    StringSetPointer(&(entry->name), TEST_GROUP_NAME);
    StringSetPointer(&(entry->id), TEST_GROUP_ID);
    StringSetPointer(&(entry->userId), TEST_USER_ID);
    StringSetPointer(&(entry->sharedUserId), TEST_SHARED_USER_ID);
    return entry;
}

HWTEST_F(GroupDataManagerTest, DelGroupTEST001, TestSize.Level0)
{
    QueryGroupParams param = InitQueryGroupParams();
    TrustedGroupEntry *entry = generateTestGroupEntry();
    GroupEntryVec vec = CreateGroupEntryVec();
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(AddGroup(TEST_OS_ACCOUNT_ID, nullptr, entry), HC_SUCCESS);
    EXPECT_EQ(DelGroup(TEST_OS_ACCOUNT_ID, nullptr, nullptr), HC_ERR_NULL_PTR);
    EXPECT_EQ(QueryGroups(TEST_OS_ACCOUNT_ID, nullptr, &param, &vec), HC_SUCCESS);
    EXPECT_EQ(HC_VECTOR_SIZE(&vec), 1);
    ClearGroupEntryVec(&vec);
    DestroyGroupEntry(entry);
}

/* Cover the NULL-guard branches added to the group entry copy/generate
 * functions (discovered by commonlib_fuzzer); also assert the happy path
 * is unchanged. */
HWTEST_F(GroupDataManagerTest, GenerateGroupEntryFromEntryNullParam001, TestSize.Level0)
{
    EXPECT_FALSE(GenerateGroupEntryFromEntry(nullptr, nullptr));
    TrustedGroupEntry *src = generateTestGroupEntry();
    ASSERT_NE(src, nullptr);
    EXPECT_FALSE(GenerateGroupEntryFromEntry(nullptr, src));
    EXPECT_FALSE(GenerateGroupEntryFromEntry(src, nullptr));
    DestroyGroupEntry(src);
}

HWTEST_F(GroupDataManagerTest, GenerateGroupEntryFromEntryValid001, TestSize.Level0)
{
    TrustedGroupEntry *src = generateTestGroupEntry();
    ASSERT_NE(src, nullptr);
    TrustedGroupEntry *dst = CreateGroupEntry();
    ASSERT_NE(dst, nullptr);
    EXPECT_TRUE(GenerateGroupEntryFromEntry(src, dst));
    EXPECT_STREQ(StringGet(&dst->id), TEST_GROUP_ID);
    EXPECT_EQ(dst->type, src->type);
    DestroyGroupEntry(src);
    DestroyGroupEntry(dst);
}

HWTEST_F(GroupDataManagerTest, DeepCopyGroupEntryNullParam001, TestSize.Level0)
{
    EXPECT_EQ(DeepCopyGroupEntry(nullptr), nullptr);
}

HWTEST_F(GroupDataManagerTest, DeepCopyGroupEntryValid001, TestSize.Level0)
{
    TrustedGroupEntry *src = generateTestGroupEntry();
    ASSERT_NE(src, nullptr);
    TrustedGroupEntry *copy = DeepCopyGroupEntry(src);
    EXPECT_NE(copy, nullptr);
    if (copy != nullptr) {
        EXPECT_STREQ(StringGet(&copy->id), TEST_GROUP_ID);
        DestroyGroupEntry(copy);
    }
    DestroyGroupEntry(src);
}

HWTEST_F(GroupDataManagerTest, GenerateDeviceEntryFromEntryNullParam001, TestSize.Level0)
{
    EXPECT_FALSE(GenerateDeviceEntryFromEntry(nullptr, nullptr));
    TrustedDeviceEntry *src = CreateDeviceEntry();
    ASSERT_NE(src, nullptr);
    EXPECT_FALSE(GenerateDeviceEntryFromEntry(nullptr, src));
    EXPECT_FALSE(GenerateDeviceEntryFromEntry(src, nullptr));
    DestroyDeviceEntry(src);
}
}