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

#include "host_mix_auth_request.h"

#include <cinttypes>

#include "iam_check.h"
#include "iam_logger.h"

#include "common_defines.h"
#include "companion_manager.h"
#include "misc_manager.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
HostMixAuthRequest::HostMixAuthRequest(const HostMixAuthParams &params, FwkResultCallback &&requestCallback)
    : BaseRequest(RequestType::HOST_MIX_AUTH_REQUEST, params.scheduleId, DEFAULT_REQUEST_TIMEOUT_MS, "-"),
      fwkMsg_(params.fwkMsg),
      hostUserId_(params.hostUserId),
      templateIdList_(params.templateIdList),
      tokenId_(params.tokenId),
      requestCallback_(std::move(requestCallback))
{
    UpdateDescription(GenerateDescription(requestType_, requestId_, "-", templateIdList_));
}

bool HostMixAuthRequest::AnyTemplateValid() const
{
    for (auto templateId : templateIdList_) {
        auto companionStatus = GetCompanionManager().GetCompanionStatus(templateId);
        if (!companionStatus.has_value()) {
            IAM_LOGE("%{public}s templateId:%{public}s not found", GetDescription(), GET_MASKED_NUM_CSTR(templateId));
            continue;
        }
        if (!companionStatus->isValid) {
            IAM_LOGE("%{public}s templateId:%{public}s is invalid", GetDescription(), GET_MASKED_NUM_CSTR(templateId));
            continue;
        }
        return true;
    }
    return false;
}

void HostMixAuthRequest::HandleDeviceSelectResult(const std::vector<DeviceKey> &selectedDevices)
{
    IAM_LOGI("%{public}s HandleDeviceSelectResult size:%{public}zu", GetDescription(), selectedDevices.size());

    if (selectedDevices.empty()) {
        IAM_LOGI("%{public}s selected devices is empty, use all templates", GetDescription());
        StartAuthWithTemplateList(templateIdList_);
        return;
    }

    auto filteredList = GetFilteredTemplateList(selectedDevices);
    if (filteredList.empty()) {
        IAM_LOGE("%{public}s filtered list is empty", GetDescription());
        CompleteWithError(ResultCode::NO_VALID_CREDENTIAL);
        return;
    }

    StartAuthWithTemplateList(filteredList);
}

std::vector<TemplateId> HostMixAuthRequest::GetFilteredTemplateList(const std::vector<DeviceKey> &selectedDevices)
{
    std::vector<TemplateId> result;

    for (const auto &deviceKey : selectedDevices) {
        auto companionStatus = GetCompanionManager().GetCompanionStatus(hostUserId_, deviceKey);
        if (!companionStatus.has_value()) {
            IAM_LOGE("%{public}s companion status not found for device", GetDescription());
            continue;
        }

        TemplateId templateId = companionStatus->templateId;
        if (std::find(templateIdList_.begin(), templateIdList_.end(), templateId) != templateIdList_.end()) {
            result.push_back(templateId);
        }
    }

    return result;
}

void HostMixAuthRequest::StartAuthWithTemplateList(const std::vector<TemplateId> &templateList)
{
    for (auto templateId : templateList) {
        auto hostSingleMixAuthRequest =
            GetRequestFactory().CreateHostSingleMixAuthRequest(GetScheduleId(), fwkMsg_, hostUserId_, templateId,
                [weakSelf = weak_from_this(), templateId, description = GetDescription()](ResultCode result,
                    const std::vector<uint8_t> &extraInfo) {
                    auto self = weakSelf.lock();
                    ENSURE_OR_RETURN_DESC(description, self != nullptr);
                    self->HandleAuthResult(templateId, result, extraInfo);
                });
        if (hostSingleMixAuthRequest == nullptr) {
            IAM_LOGE("%{public}s factory returned nullptr for templateId:%{public}s", GetDescription(),
                GET_MASKED_NUM_CSTR(templateId));
            continue;
        }
        if (!GetRequestManager().Start(hostSingleMixAuthRequest)) {
            IAM_LOGE("%{public}s start request fail templateId:%{public}s", GetDescription(),
                GET_MASKED_NUM_CSTR(templateId));
            continue;
        }
        requestMap_.emplace(templateId, std::move(hostSingleMixAuthRequest));
    }
    if (requestMap_.empty()) {
        IAM_LOGE("%{public}s no request exist", GetDescription());
        CompleteWithError(ResultCode::GENERAL_ERROR);
        return;
    }
}

void HostMixAuthRequest::Start()
{
    if (!AnyTemplateValid()) {
        IAM_LOGE("%{public}s no valid templateId found", GetDescription());
        CompleteWithError(ResultCode::NO_VALID_CREDENTIAL);
        return;
    }

    if (!tokenId_.has_value()) {
        IAM_LOGI("%{public}s no tokenId, skip device selection, use all templates", GetDescription());
        StartAuthWithTemplateList(templateIdList_);
        return;
    }

    bool selectorSet = GetMiscManager().GetDeviceDeviceSelectResult(tokenId_.value(), SelectPurpose::SELECT_AUTH_DEVICE,
        [weakSelf = weak_from_this(), description = GetDescription()](const std::vector<DeviceKey> &selectedDevices) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN_DESC(description, self != nullptr);
            self->HandleDeviceSelectResult(selectedDevices);
        });
    if (!selectorSet) {
        IAM_LOGE("%{public}s no device selector set", GetDescription());
        CompleteWithError(ResultCode::GENERAL_ERROR);
        return;
    }

    IAM_LOGI("%{public}s waiting for device select result", GetDescription());
}

bool HostMixAuthRequest::Cancel(ResultCode resultCode)
{
    if (cancelled_) {
        IAM_LOGI("%{public}s already cancelled, skip", GetDescription());
        return true;
    }
    cancelled_ = true;
    std::unordered_map<uint64_t, std::shared_ptr<IRequest>> requestMap = std::move(requestMap_);
    for (auto &entry : requestMap) {
        if (entry.second != nullptr) {
            entry.second->Cancel(resultCode);
        }
    }
    CompleteWithError(resultCode);
    return true;
}

void HostMixAuthRequest::HandleAuthResult(TemplateId templateId, ResultCode result,
    const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("%{public}s templateId:%{public}s result:%{public}d", GetDescription(), GET_MASKED_NUM_CSTR(templateId),
        result);
    auto it = requestMap_.find(templateId);
    if (it == requestMap_.end()) {
        IAM_LOGE("%{public}s request already released", GetDescription());
        return;
    }
    if (it->second == nullptr) {
        IAM_LOGE("%{public}s request is nullptr", GetDescription());
        return;
    }
    requestMap_.erase(it);
    if (result != ResultCode::SUCCESS) {
        if (requestMap_.empty()) {
            CompleteWithError(ResultCode::FAIL);
            return;
        }
        IAM_LOGE("%{public}s wait for other request result, current size:%{public}zu", GetDescription(),
            requestMap_.size());
        return;
    }
    std::unordered_map<uint64_t, std::shared_ptr<IRequest>> requestMap = std::move(requestMap_);
    for (auto &entry : requestMap) {
        if (entry.second != nullptr) {
            entry.second->Cancel(ResultCode::CANCELED);
        }
    }
    CompleteWithSuccess(extraInfo);
}

uint32_t HostMixAuthRequest::GetMaxConcurrency() const
{
    return 1; // Spec: max 1 concurrent HostMixAuthRequest
}

bool HostMixAuthRequest::ShouldCancelOnNewRequest(RequestType newRequestType,
    [[maybe_unused]] const std::optional<DeviceKey> &newPeerDevice,
    [[maybe_unused]] uint32_t subsequentSameTypeCount) const
{
    // Spec: new HostMixAuthRequest preempts existing one
    if (newRequestType == RequestType::HOST_MIX_AUTH_REQUEST) {
        IAM_LOGI("%{public}s: preempted by new HostMixAuth", GetDescription());
        return true;
    }

    return false;
}

void HostMixAuthRequest::InvokeCallback(ResultCode result, const std::vector<uint8_t> &extraInfo)
{
    if (requestCallback_ == nullptr) {
        IAM_LOGI("%{public}s callback already sent", GetDescription());
        return;
    }
    TaskRunnerManager::GetInstance().PostTaskOnResident(
        [cb = std::move(requestCallback_), result, extra = extraInfo]() mutable {
            if (cb) {
                cb(result, extra);
            }
        });
}

void HostMixAuthRequest::CompleteWithError(ResultCode result)
{
    IAM_LOGI("%{public}s complete with error: %{public}d", GetDescription(), result);
    InvokeCallback(result, {});
    Destroy();
}

void HostMixAuthRequest::CompleteWithSuccess(const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("%{public}s complete with success", GetDescription());
    InvokeCallback(ResultCode::SUCCESS, extraInfo);
    Destroy();
}

void HostMixAuthRequest::Destroy()
{
    IAM_LOGI("%{public}s destroy", GetDescription());
    BaseRequest::Destroy();
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
