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

#ifndef COMPANION_DEVICE_AUTH_EVENT_BUS_IMPL_H
#define COMPANION_DEVICE_AUTH_EVENT_BUS_IMPL_H

#include <functional>
#include <memory>
#include <unordered_map>

#include "event_bus.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class EventBusImpl : public std::enable_shared_from_this<EventBusImpl>, public IEventBus {
public:
    static std::shared_ptr<EventBusImpl> Create();

    ~EventBusImpl() override = default;

    void Publish(EventType type, const EventData &data) override;
    std::shared_ptr<Subscription> Subscribe(EventType type, EventDataHandler &&handler) override;
    void PersistSubscribe(EventType type, EventDataHandler &&handler) override;

private:
    EventBusImpl();
    void Unsubscribe(EventType type, SubscribeId id);

    std::unordered_map<EventType, std::unordered_map<SubscribeId, EventDataHandler>> subscribers_;
    SubscribeId nextSubscribeId_ { 0 };
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_EVENT_BUS_IMPL_H
