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

#ifndef COMPANION_DEVICE_AUTH_FAKE_SYSTEM_PARAM_MANAGER_H
#define COMPANION_DEVICE_AUTH_FAKE_SYSTEM_PARAM_MANAGER_H

#include <map>
#include <memory>
#include <string>

#include "subscription.h"
#include "system_param_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class FakeSystemParamManager : public ISystemParamManager {
public:
    FakeSystemParamManager() = default;
    ~FakeSystemParamManager() override = default;

    std::string GetParam(const std::string &key, const std::string &defaultValue) override
    {
        auto it = params_.find(key);
        return it != params_.end() ? it->second : defaultValue;
    }

    void SetParam(const std::string &key, const std::string &value) override
    {
        params_[key] = value;
        auto it = watchers_.find(key);
        if (it != watchers_.end()) {
            it->second(value);
        }
    }

    void SetParamTwice(const std::string &key, const std::string &v1, const std::string &v2) override
    {
        SetParam(key, v1);
        SetParam(key, v2);
    }

    std::unique_ptr<Subscription> WatchParam(const std::string &key, SystemParamCallback &&callback) override
    {
        watchers_[key] = std::move(callback);
        return std::make_unique<Subscription>([this, key]() { watchers_.erase(key); });
    }

    void OnParamChange(const std::string &key, const std::string &value) override
    {
        auto it = watchers_.find(key);
        if (it != watchers_.end()) {
            it->second(value);
        }
    }

private:
    std::map<std::string, std::string> params_;
    std::map<std::string, SystemParamCallback> watchers_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_FAKE_SYSTEM_PARAM_MANAGER_H
