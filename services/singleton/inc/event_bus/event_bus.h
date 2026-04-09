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

#ifndef COMPANION_DEVICE_AUTH_EVENT_BUS_H
#define COMPANION_DEVICE_AUTH_EVENT_BUS_H

#include <functional>
#include <memory>
#include <optional>
#include <vector>

#include "nocopyable.h"
#include "service_common.h"
#include "subscription.h"

#include "common_defines.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

enum class EventType : uint16_t {
    AUTH_SUCCESS = 1,
};

using EventData = std::vector<uint8_t>;
using EventDataHandler = std::function<void(const EventData &)>;

class IEventBus : public NoCopyable {
public:
    virtual ~IEventBus() = default;

    virtual void Publish(EventType type, const EventData &data) = 0;
    virtual std::shared_ptr<Subscription> Subscribe(EventType type, EventDataHandler &&handler) = 0;
    virtual void PersistSubscribe(EventType type, EventDataHandler &&handler) = 0;

protected:
    IEventBus() = default;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_EVENT_BUS_H
