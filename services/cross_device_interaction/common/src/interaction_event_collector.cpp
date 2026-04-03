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

#include "interaction_event_collector.h"

#include "event_manager_adapter.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

void InteractionEventCollector::UpdateHostUserId(UserId hostUserId)
{
    hostUserId_ = hostUserId;
}

void InteractionEventCollector::UpdateHostDeviceKey(const DeviceKey &hostDeviceKey)
{
    hostDeviceKey_ = hostDeviceKey;
}

void InteractionEventCollector::UpdateCompanionUserId(UserId companionUserId)
{
    companionUserId_ = companionUserId;
}

void InteractionEventCollector::UpdateCompanionDeviceKey(const DeviceKey &companionDeviceKey)
{
    companionDeviceKey_ = companionDeviceKey;
}

void InteractionEventCollector::UpdateConnectionName(const std::string &connectionName)
{
    connectionName_ = connectionName;
}

void InteractionEventCollector::UpdateScheduleId(ScheduleId scheduleId)
{
    scheduleId_ = scheduleId;
}

void InteractionEventCollector::UpdateTriggerReason(const std::string &triggerReason)
{
    triggerReason_ = triggerReason;
}

void InteractionEventCollector::UpdateTemplateIdList(const std::vector<TemplateId> &templateIdList)
{
    templateIdList_ = templateIdList;
}

template <typename T>
void InteractionEventCollector::AppendExtraInfo(const std::string &key, const T &value)
{
    std::ostringstream oss;
    oss << key << ":" << value;
    if (!extraInfo_.empty()) {
        extraInfo_ += ", ";
    }
    extraInfo_ += oss.str();
}

template <typename T>
void InteractionEventCollector::AppendExtraInfo(const std::string &key, const std::vector<T> &value)
{
    std::ostringstream oss;
    oss << key << ":" << ConvertVectorToString(value);
    if (!extraInfo_.empty()) {
        extraInfo_ += ", ";
    }
    extraInfo_ += oss.str();
}

void InteractionEventCollector::Report(ResultCode result)
{
    result_ = result;
    ReportInteractionEvent(*this);
}

template <typename T>
std::string ConvertVectorToString(const std::vector<T> &vec)
{
    if (vec.empty()) {
        return "[]";
    }

    std::string result = "[";
    for (size_t i = 0; i < vec.size(); ++i) {
        if (i > 0) {
            result += ", ";
        }
        result += std::to_string(vec[i]);
    }

    result += "]";
    return result;
}

template void InteractionEventCollector::AppendExtraInfo<uint16_t>(const std::string &key, const uint16_t &value);
template void InteractionEventCollector::AppendExtraInfo<uint32_t>(const std::string &key, const uint32_t &value);
template void InteractionEventCollector::AppendExtraInfo<uint64_t>(const std::string &key, const uint64_t &value);
template void InteractionEventCollector::AppendExtraInfo<int32_t>(const std::string &key, const int32_t &value);
template void InteractionEventCollector::AppendExtraInfo<std::string>(const std::string &key, const std::string &value);
template void InteractionEventCollector::AppendExtraInfo<uint16_t>(const std::string &key,
    const std::vector<uint16_t> &value);

template std::string ConvertVectorToString<uint64_t>(const std::vector<uint64_t> &vec);

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
