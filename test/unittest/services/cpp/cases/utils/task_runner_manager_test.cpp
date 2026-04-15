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

#include <cstddef>
#include <memory>
#include <string>

#include <gtest/gtest.h>

#include "mock_guard.h"

#include "task_runner_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class TaskRunnerManagerTest : public Test {
protected:
    void TearDown() override
    {
        // Execute all pending tasks so temporary runners are cleaned up.
        TaskRunnerManager::GetInstance().ExecuteAll();
    }
};

HWTEST_F(TaskRunnerManagerTest, PostTaskOnTemporary_RejectsWhenTooManyConcurrentRunners, TestSize.Level0)
{
    MockGuard guard;
    auto &trm = TaskRunnerManager::GetInstance();

    // Saturate with 8 concurrent temporary runners by directly creating entries.
    constexpr size_t maxConcurrentTemporaryRunners = 8;
    for (size_t i = 0; i < maxConcurrentTemporaryRunners; ++i) {
        std::string runnerName = "saturation_runner_" + std::to_string(i);
        ASSERT_TRUE(trm.CreateTaskRunner(runnerName));
    }

    // The 9th temporary task should be silently rejected.
    auto flag = std::make_shared<bool>(false);
    trm.PostTaskOnTemporary("overflow_test", [flag]() { *flag = true; });

    trm.ExecuteAll();
    EXPECT_FALSE(*flag);

    // Cleanup: remove the saturated runners from the map.
    for (size_t i = 0; i < maxConcurrentTemporaryRunners; ++i) {
        trm.DeleteTaskRunner("saturation_runner_" + std::to_string(i));
    }
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
