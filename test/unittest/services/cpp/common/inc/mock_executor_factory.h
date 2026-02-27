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

#ifndef COMPANION_DEVICE_AUTH_MOCK_EXECUTOR_FACTORY_H
#define COMPANION_DEVICE_AUTH_MOCK_EXECUTOR_FACTORY_H

#include <gmock/gmock.h>
#include <memory>

#include "fwk_comm/executor_factory.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class MockExecutorFactory : public IExecutorFactory {
public:
    MOCK_METHOD(std::shared_ptr<FwkIAuthExecutorHdi>, CreateExecutor, (), (override));
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_MOCK_EXECUTOR_FACTORY_H
