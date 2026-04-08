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

#ifndef COMPANION_DEVICE_AUTH_FAKE_SA_MANAGER_ADAPTER_H
#define COMPANION_DEVICE_AUTH_FAKE_SA_MANAGER_ADAPTER_H

#include <map>
#include <memory>

#include "refbase.h"
#include "sa_manager_adapter.h"
#include "system_ability_status_change_stub.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class FakeSaManagerAdapter : public ISaManagerAdapter {
public:
    FakeSaManagerAdapter() = default;
    ~FakeSaManagerAdapter() override = default;

    bool SubscribeSystemAbility(int32_t saId, const sptr<SystemAbilityStatusChangeStub> &listener) override
    {
        if (saId < 0 || listener == nullptr) {
            return false;
        }
        subscribers_[saId] = listener;
        return true;
    }

    bool UnSubscribeSystemAbility(int32_t saId, const sptr<SystemAbilityStatusChangeStub> &) override
    {
        subscribers_.erase(saId);
        return true;
    }

    // Test backdoor: simulate SA online
    void TestSimulateSaOnline(int32_t saId)
    {
        auto it = subscribers_.find(saId);
        if (it != subscribers_.end() && it->second) {
            it->second->OnAddSystemAbility(saId, "");
        }
    }

    // Test backdoor: simulate SA offline
    void TestSimulateSaOffline(int32_t saId)
    {
        auto it = subscribers_.find(saId);
        if (it != subscribers_.end() && it->second) {
            it->second->OnRemoveSystemAbility(saId, "");
        }
    }

private:
    std::map<int32_t, sptr<SystemAbilityStatusChangeStub>> subscribers_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_FAKE_SA_MANAGER_ADAPTER_H
