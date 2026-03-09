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

#include "event_manager_adapter_impl.h"

#include "adapter_manager.h"
#include "hisysevent.h"
#include "iam_logger.h"

#define LOG_TAG "CDA_SA"

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

template<typename T>
void InteractionEventCollector::AppendExtraInfo(const std::string &key, const T &value)
{
    std::ostringstream oss;
    oss << key << ":" << value;
    if (!extraInfo_.empty()) {
        extraInfo_ += ", ";
    }
    extraInfo_ += oss.str();
}

template<typename T>
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

using HiSysEvent = OHOS::HiviewDFX::HiSysEvent;

constexpr char STR_REQUEST_TYPE[] = "REQUEST_TYPE";
constexpr char STR_RESULT[] = "RESULT";
constexpr char STR_HOST_USER_ID[] = "HOST_USER_ID";
constexpr char STR_HOST_DEVICE_KEY[] = "HOST_DEVICE_KEY";
constexpr char STR_COMPANION_USER_ID[] = "COMPANION_USER_ID";
constexpr char STR_COMPANION_DEVICE_KEY[] = "COMPANION_DEVICE_KEY";
constexpr char STR_CONNECTION_NAME[] = "CONNECTION_NAME";
constexpr char STR_SCHEDULE_ID[] = "SCHEDULE_ID";
constexpr char STR_TRIGGER_REASON[] = "TRIGGER_REASON";
constexpr char STR_TEMPLATE_ID_LIST[] = "TEMPLATE_ID_LIST";
constexpr char STR_EXTRA_INFO[] = "EXTRA_INFO";
constexpr char STR_FAULT_TYPE[] = "FAULT_TYPE";
constexpr char STR_FAULT_ID[] = "FAULT_ID";
constexpr char STR_FAULT_INFO[] = "FAULT_INFO";

std::string ConvertFaultTypeToString(FaultType faultType)
{
    switch (faultType) {
        case FaultType::NONE: return "NONE";
        case FaultType::TA_CRASH: return "TA_CRASH";
        case FaultType::TA_INIT_FAILED: return "TA_INIT_FAILED";
        default: return "UNKNOWN";
    }
}

void EventManagerAdapterImpl::ReportSystemFault(FaultType faultType, std::string faultId, std::string faultInfo)
{
    std::string faultTypeStr = ConvertFaultTypeToString(faultType);

    int32_t ret = HiSysEventWrite(HiSysEvent::Domain::COMPANION_AUTH, "SYSTEM_FAULT",
        HiSysEvent::EventType::FAULT,
        STR_FAULT_TYPE, faultTypeStr,
        STR_FAULT_ID, faultId,
        STR_FAULT_INFO, faultInfo);
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d", ret);
    }
}

void EventManagerAdapterImpl::ReportInteractionEvent(const InteractionEventCollector &eventCollector)
{
    std::string resultStr = std::to_string(static_cast<int32_t>(eventCollector.GetResult()));
    int32_t hostUserId = eventCollector.GetHostUserId().value_or(0);
    std::string hostDeviceKey = eventCollector.GetHostDeviceKey().has_value() ?
        eventCollector.GetHostDeviceKey()->GetDesc() : "";
    int32_t companionUserId = eventCollector.GetCompanionUserId().value_or(0);
    std::string companionDeviceKey = eventCollector.GetCompanionDeviceKey().has_value() ?
        eventCollector.GetCompanionDeviceKey()->GetDesc() : "";
    std::string connectionName = eventCollector.GetConnectionName().value_or("");
    uint64_t scheduleId = eventCollector.GetScheduleId().value_or(0);
    std::string triggerReason = eventCollector.GetTriggerReason().value_or("");

    std::string templateIdList;
    if (eventCollector.GetTemplateIdList().has_value() && !eventCollector.GetTemplateIdList()->empty()) {
        templateIdList = ConvertVectorToString(*eventCollector.GetTemplateIdList());
    }

    int32_t ret = HiSysEventWrite(HiSysEvent::Domain::COMPANION_AUTH, "INTERACTION_EVENT",
        HiSysEvent::EventType::FAULT,
        STR_REQUEST_TYPE, eventCollector.GetRequestType(),
        STR_RESULT, resultStr,
        STR_HOST_USER_ID, hostUserId,
        STR_HOST_DEVICE_KEY, hostDeviceKey,
        STR_COMPANION_USER_ID, companionUserId,
        STR_COMPANION_DEVICE_KEY, companionDeviceKey,
        STR_CONNECTION_NAME, connectionName,
        STR_SCHEDULE_ID, scheduleId,
        STR_TRIGGER_REASON, triggerReason,
        STR_TEMPLATE_ID_LIST, templateIdList,
        STR_EXTRA_INFO, eventCollector.GetExtraInfo());
    if (ret != 0) {
        IAM_LOGE("hisusysevent write failed! ret %{public}d", ret);
    }
}

void ReportSystemFault(FaultType faultType, std::string faultId, std::string faultInfo)
{
    GetEventManagerAdapter().ReportSystemFault(faultType, faultId, faultInfo);
}

void ReportInteractionEvent(const InteractionEventCollector &eventCollector)
{
    GetEventManagerAdapter().ReportInteractionEvent(eventCollector);
}

template<typename T>
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
template void InteractionEventCollector::AppendExtraInfo<std::string>(const std::string &key,
    const std::string &value);
template void InteractionEventCollector::AppendExtraInfo<uint16_t>(const std::string &key,
    const std::vector<uint16_t> &value);

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
