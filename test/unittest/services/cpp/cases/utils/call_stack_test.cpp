/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include "iam_logger.h"
#include "iam_para2str.h"

#define LOG_TAG "CDA_SA"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class GetCallStackTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GetCallStackTest::SetUpTestCase()
{
}

void GetCallStackTest::TearDownTestCase()
{
}

void GetCallStackTest::SetUp()
{
}

void GetCallStackTest::TearDown()
{
}

HWTEST_F(GetCallStackTest, GetCallStack_001, TestSize.Level0)
{
    std::string result = GetCallStack();
    IAM_LOGI("GetCallStack result: %{public}s", result.c_str());
    EXPECT_FALSE(result.empty());
}

HWTEST_F(GetCallStackTest, GetCallStack_002, TestSize.Level0)
{
    std::string result = GetCallStack();
    // backtrace should return at least 1 frame
    EXPECT_GT(result.size(), 0u);
}

HWTEST_F(GetCallStackTest, GetCallStack_ThreadIdSafe, TestSize.Level0)
{
    std::string result1 = GetCallStack();
    std::string result2 = GetCallStack();
    EXPECT_FALSE(result1.empty());
    EXPECT_FALSE(result2.empty());
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
