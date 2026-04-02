/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <cstring>
#include <gtest/gtest.h>

#include "interaction_desc.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class InteractionDescTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void InteractionDescTest::SetUpTestCase()
{
}

void InteractionDescTest::TearDownTestCase()
{
}

void InteractionDescTest::SetUp()
{
}

void InteractionDescTest::TearDown()
{
}

HWTEST_F(InteractionDescTest, DefaultConstructor_001, TestSize.Level0)
{
    InteractionDesc desc;
    EXPECT_STREQ(desc.GetCStr(), "");
}

HWTEST_F(InteractionDescTest, ConstructorWithPrefixAndType_001, TestSize.Level0)
{
    InteractionDesc desc(REQUEST_PREFIX, "HObT");
    EXPECT_STREQ(desc.GetCStr(), "CdaR(HObT)");
}

HWTEST_F(InteractionDescTest, SetConnectionName_001, TestSize.Level0)
{
    InteractionDesc desc(REQUEST_PREFIX, "HObT");
    desc.SetConnectionName("conn1");
    EXPECT_STREQ(desc.GetCStr(), "CdaR(HObT,conn1)");
}

HWTEST_F(InteractionDescTest, SetConnectionName_002, TestSize.Level0)
{
    InteractionDesc desc(REQUEST_PREFIX, "HObT");
    desc.SetConnectionName("");
    EXPECT_STREQ(desc.GetCStr(), "CdaR(HObT)");
}

HWTEST_F(InteractionDescTest, SetRequestId_001, TestSize.Level0)
{
    InteractionDesc desc(REQUEST_PREFIX, "HObT");
    desc.SetRequestId(0x00000001);
    EXPECT_STREQ(desc.GetCStr(), "CdaR(HObT,0x00000001)");
}

HWTEST_F(InteractionDescTest, SetRequestId_002, TestSize.Level0)
{
    InteractionDesc desc(REQUEST_PREFIX, "HObT");
    desc.SetRequestId(0xABCD1234);
    EXPECT_STREQ(desc.GetCStr(), "CdaR(HObT,0xABCD1234)");
}

HWTEST_F(InteractionDescTest, SetBindingId_001, TestSize.Level0)
{
    InteractionDesc desc(REQUEST_PREFIX, "CIsT");
    desc.SetBindingId(42);
    EXPECT_STREQ(desc.GetCStr(), "CdaR(CIsT,002a)");
}

HWTEST_F(InteractionDescTest, SetTemplateId_001, TestSize.Level0)
{
    InteractionDesc desc(REQUEST_PREFIX, "HTkA");
    desc.SetTemplateId(123);
    EXPECT_STREQ(desc.GetCStr(), "CdaR(HTkA,007b)");
}

HWTEST_F(InteractionDescTest, SetTemplateIdList_001, TestSize.Level0)
{
    InteractionDesc desc(REQUEST_PREFIX, "HMixA");
    desc.SetTemplateIdList({ 100, 200, 300 });
    EXPECT_STREQ(desc.GetCStr(), "CdaR(HMixA,T=[0064,00c8,012c])");
}

HWTEST_F(InteractionDescTest, SetTemplateIdList_002, TestSize.Level0)
{
    InteractionDesc desc(REQUEST_PREFIX, "HMixA");
    desc.SetTemplateIdList({ 100 });
    EXPECT_STREQ(desc.GetCStr(), "CdaR(HMixA,T=[0064])");
}

HWTEST_F(InteractionDescTest, SetTemplateIdList_003, TestSize.Level0)
{
    InteractionDesc desc(REQUEST_PREFIX, "HMixA");
    desc.SetTemplateIdList({});
    EXPECT_STREQ(desc.GetCStr(), "CdaR(HMixA)");
}

HWTEST_F(InteractionDescTest, TemplateIdAndListMutuallyExclusive_001, TestSize.Level0)
{
    InteractionDesc desc(REQUEST_PREFIX, "HMixA");
    desc.SetTemplateId(50);
    EXPECT_STREQ(desc.GetCStr(), "CdaR(HMixA,0032)");

    desc.SetTemplateIdList({ 100, 200 });
    EXPECT_STREQ(desc.GetCStr(), "CdaR(HMixA,T=[0064,00c8])");

    desc.SetTemplateId(50);
    EXPECT_STREQ(desc.GetCStr(), "CdaR(HMixA,0032)");
}

HWTEST_F(InteractionDescTest, FullFields_001, TestSize.Level0)
{
    InteractionDesc desc(REQUEST_PREFIX, "HTkA");
    desc.SetConnectionName("conn1");
    desc.SetRequestId(0x00000042);
    desc.SetTemplateId(99);
    EXPECT_STREQ(desc.GetCStr(), "CdaR(HTkA,conn1,0x00000042,0063)");
}

HWTEST_F(InteractionDescTest, HandlerPrefix_001, TestSize.Level0)
{
    InteractionDesc desc(HANDLER_PREFIX, "CSync");
    desc.SetConnectionName("sess1");
    EXPECT_STREQ(desc.GetCStr(), "CdaH(CSync,sess1)");
}

HWTEST_F(InteractionDescTest, IncrementalUpdate_001, TestSize.Level0)
{
    InteractionDesc desc(REQUEST_PREFIX, "HObT");
    EXPECT_STREQ(desc.GetCStr(), "CdaR(HObT)");

    desc.SetRequestId(0x00000001);
    EXPECT_STREQ(desc.GetCStr(), "CdaR(HObT,0x00000001)");

    desc.SetConnectionName("conn2");
    EXPECT_STREQ(desc.GetCStr(), "CdaR(HObT,conn2,0x00000001)");

    desc.SetBindingId(7);
    EXPECT_STREQ(desc.GetCStr(), "CdaR(HObT,conn2,0x00000001,0007)");
}

HWTEST_F(InteractionDescTest, GetCStrReturnsSamePointer_001, TestSize.Level0)
{
    InteractionDesc desc(REQUEST_PREFIX, "HObT");
    const char *ptr1 = desc.GetCStr();
    const char *ptr2 = desc.GetCStr();
    EXPECT_EQ(ptr1, ptr2);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
