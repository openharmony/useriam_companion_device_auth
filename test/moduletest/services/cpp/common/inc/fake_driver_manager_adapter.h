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

#ifndef COMPANION_DEVICE_AUTH_FAKE_DRIVER_MANAGER_ADAPTER_H
#define COMPANION_DEVICE_AUTH_FAKE_DRIVER_MANAGER_ADAPTER_H

#include <memory>
#include <vector>

#include "companion_device_auth_driver.h"
#include "driver_manager_adapter.h"
#include "fwk_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class FakeDriverManagerAdapter : public IDriverManagerAdapter {
public:
    FakeDriverManagerAdapter() = default;
    ~FakeDriverManagerAdapter() override = default;

    bool Start(std::shared_ptr<CompanionDeviceAuthDriver> driver) override
    {
        if (driver == nullptr) {
            return false;
        }

        // Simulate UserAuth::IDriverManager::Start framework behavior
        std::vector<std::shared_ptr<FwkIAuthExecutorHdi>> executorList;
        driver->GetExecutorList(executorList);
        if (executorList.empty()) {
            return false;
        }

        executor_ = executorList[0];
        driver_ = driver;

        // Framework registration: call GetExecutorInfo
        FwkExecutorInfo info {};
        auto ret = executor_->GetExecutorInfo(info);
        if (ret != FwkResultCode::SUCCESS) {
            return false;
        }

        // Framework registration: call OnRegisterFinish
        ret = executor_->OnRegisterFinish({}, {}, {});
        return ret == FwkResultCode::SUCCESS;
    }

    // Test backdoor: get registered executor
    std::shared_ptr<FwkIAuthExecutorHdi> TestGetRegisteredExecutor() const
    {
        return executor_;
    }

    // Test backdoor: simulate framework sending persistent templateId list
    void TestNotifyFrameworkTemplates(const std::vector<uint64_t> &templateIds, const std::vector<uint8_t> &pubKey = {},
        const std::vector<uint8_t> &extra = {})
    {
        if (executor_) {
            executor_->OnRegisterFinish(templateIds, pubKey, extra);
        }
    }

private:
    std::shared_ptr<FwkIAuthExecutorHdi> executor_;
    std::shared_ptr<CompanionDeviceAuthDriver> driver_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_FAKE_DRIVER_MANAGER_ADAPTER_H
