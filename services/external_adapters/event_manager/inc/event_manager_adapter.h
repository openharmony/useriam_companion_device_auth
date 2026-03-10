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

#ifndef COMPANION_DEVICE_AUTH_EVENT_MANAGER_ADAPTER_H
#define COMPANION_DEVICE_AUTH_EVENT_MANAGER_ADAPTER_H

#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "nocopyable.h"

#include "common_defines.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

enum class FaultType : uint32_t {
    NONE = 0,
    TA_CRASH = 1,
    TA_INIT_FAILED = 2,
};

class InteractionEventCollector {
public:
    explicit InteractionEventCollector(const std::string &requestType) : requestType_(requestType)
    {
    }
    ~InteractionEventCollector() = default;

    void UpdateHostUserId(UserId hostUserId);
    void UpdateHostDeviceKey(const DeviceKey &hostDeviceKey);
    void UpdateCompanionUserId(UserId companionUserId);
    void UpdateCompanionDeviceKey(const DeviceKey &companionDeviceKey);
    void UpdateConnectionName(const std::string &connectionName);
    void UpdateScheduleId(ScheduleId scheduleId);
    void UpdateTriggerReason(const std::string &triggerReason);
    void UpdateTemplateIdList(const std::vector<TemplateId> &templateIdList);

    template <typename T>
    void AppendExtraInfo(const std::string &key, const T &value);

    template <typename T>
    void AppendExtraInfo(const std::string &key, const std::vector<T> &value);

    void Report(ResultCode result);

    const std::string &GetRequestType() const
    {
        return requestType_;
    }
    ResultCode GetResult() const
    {
        return result_;
    }
    const std::optional<UserId> &GetHostUserId() const
    {
        return hostUserId_;
    }
    const std::optional<DeviceKey> &GetHostDeviceKey() const
    {
        return hostDeviceKey_;
    }
    const std::optional<UserId> &GetCompanionUserId() const
    {
        return companionUserId_;
    }
    const std::optional<DeviceKey> &GetCompanionDeviceKey() const
    {
        return companionDeviceKey_;
    }
    const std::optional<std::string> &GetConnectionName() const
    {
        return connectionName_;
    }
    const std::optional<ScheduleId> &GetScheduleId() const
    {
        return scheduleId_;
    }
    const std::optional<std::string> &GetTriggerReason() const
    {
        return triggerReason_;
    }
    const std::optional<std::vector<TemplateId>> &GetTemplateIdList() const
    {
        return templateIdList_;
    }
    const std::string &GetExtraInfo() const
    {
        return extraInfo_;
    }

private:
    std::string requestType_;
    ResultCode result_ = ResultCode::SUCCESS;
    std::optional<UserId> hostUserId_;
    std::optional<DeviceKey> hostDeviceKey_;
    std::optional<UserId> companionUserId_;
    std::optional<DeviceKey> companionDeviceKey_;
    std::optional<std::string> connectionName_;
    std::optional<ScheduleId> scheduleId_;
    std::optional<std::string> triggerReason_;
    std::optional<std::vector<TemplateId>> templateIdList_;
    std::string extraInfo_;
};

class IEventManagerAdapter : public NoCopyable {
public:
    virtual ~IEventManagerAdapter() = default;
    virtual void ReportSystemFault(FaultType faultType, std::string faultId, std::string faultInfo) = 0;
    virtual void ReportInteractionEvent(const InteractionEventCollector &eventCollector) = 0;

protected:
    IEventManagerAdapter() = default;
};

void ReportSystemFault(FaultType faultType, std::string faultId, std::string faultInfo);
void ReportInteractionEvent(const InteractionEventCollector &eventCollector);

template <typename T>
std::string ConvertVectorToString(const std::vector<T> &vec);

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_EVENT_MANAGER_ADAPTER_H
