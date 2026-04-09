/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef COMPANION_DEVICE_AUTH_MOCK_EVENT_BUS_H
#define COMPANION_DEVICE_AUTH_MOCK_EVENT_BUS_H

#include <gmock/gmock.h>

#include "event_bus/event_bus.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class MockEventBus : public IEventBus {
public:
    MOCK_METHOD(void, Publish, (EventType type, const EventData &data), (override));
    MOCK_METHOD(std::shared_ptr<Subscription>, Subscribe,
        (EventType type, EventDataHandler &&handler), (override));
    MOCK_METHOD(void, PersistSubscribe, (EventType type, EventDataHandler &&handler), (override));
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_MOCK_EVENT_BUS_H
