/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef COMPANION_DEVICE_AUTH_TEST_UNITTEST_CLIENT_MOCK_MOCK_CALLBACK_H
#define COMPANION_DEVICE_AUTH_TEST_UNITTEST_CLIENT_MOCK_MOCK_CALLBACK_H

#include "iavailable_device_status_callback.h"
#include "icontinuous_auth_status_callback.h"
#include "idevice_select_callback.h"
#include "itemplate_status_callback.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class FakeDeviceSelectCallback : public IDeviceSelectCallback {
public:
    ~FakeDeviceSelectCallback() override = default;
    void OnDeviceSelect(int32_t selectPurpose, const std::shared_ptr<SetDeviceSelectResultCallback> &callback) override
    {
        (void)selectPurpose;
        (void)callback;
    }
};

class FakeTemplateStatusCallback : public ITemplateStatusCallback {
public:
    ~FakeTemplateStatusCallback() override = default;
    void OnTemplateStatusChange(const std::vector<ClientTemplateStatus> templateStatusList) override
    {
        (void)templateStatusList;
    }
};

class FakeAvailableDeviceStatusCallback : public IAvailableDeviceStatusCallback {
public:
    ~FakeAvailableDeviceStatusCallback() override = default;
    void OnAvailableDeviceStatusChange(const std::vector<ClientDeviceStatus> deviceStatusList) override
    {
        (void)deviceStatusList;
    }
};

class FakeContinuousAuthStatusCallback : public IContinuousAuthStatusCallback {
public:
    ~FakeContinuousAuthStatusCallback() override = default;
    void OnContinuousAuthStatusChange(const bool isAuthPassed, std::optional<int32_t> remainingTime) override
    {
        (void)isAuthPassed;
        (void)remainingTime;
    }
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_TEST_UNITTEST_CLIENT_MOCK_MOCK_CALLBACK_H
