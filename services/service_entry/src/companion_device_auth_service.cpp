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

#include "companion_device_auth_service.h"

#include "base_service_core.h"
#include "base_service_initializer.h"

#include <cstdint>
#include <memory>
#include <mutex>
#include <new>

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "iremote_object.h"
#include "iservice_registry.h"
#include "refbase.h"
#include "system_ability.h"
#include "system_ability_definition.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "access_token_kit_adapter_impl.h"
#include "adapter_manager.h"
#include "common_defines.h"
#include "companion_manager_impl.h"
#include "cross_device_comm_manager_impl.h"
#include "event_manager_adapter_impl.h"
#include "fwk_comm_manager.h"
#include "host_binding_manager_impl.h"
#include "misc_manager_impl.h"
#include "sa_manager_adapter_impl.h"
#include "security_command_adapter_impl.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "subscription_manager.h"
#include "system_param_manager_impl.h"
#include "task_runner_manager.h"
#include "tokenid_kit.h"
#include "user_id_manager.h"
#include "xcollie_helper.h"

#ifdef HAS_USER_AUTH_FRAMEWORK
#include "driver_manager_adapter_impl.h"
#include "idm_adapter_impl.h"
#include "user_auth_adapter_impl.h"
#endif

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
// Get service instance with BaseServiceInitializer
sptr<CompanionDeviceAuthService> GetServiceInstance()
{
    static sptr<CompanionDeviceAuthService> instance = sptr<CompanionDeviceAuthService>::MakeSptr(
        []() -> std::shared_ptr<BaseServiceInitializer> { return BaseServiceInitializer::Create(); },
        [](const std::shared_ptr<SubscriptionManager> &subscriptionManager,
            const std::vector<BusinessId> &supportedBusinessIds) -> std::shared_ptr<BaseServiceCore> {
            return BaseServiceCore::Create(subscriptionManager, supportedBusinessIds);
        });
    return instance;
}

#ifndef ENABLE_TEST
[[maybe_unused]] const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(GetServiceInstance().GetRefPtr());
#endif // ENABLE_TEST
} // namespace

CompanionDeviceAuthService::CompanionDeviceAuthService(BaseServiceInitializerCreater initializerCreater,
    BaseServiceCoreCreater coreCreater)
    : SystemAbility(SUBSYS_USERIAM_SYS_ABILITY_COMPANIONDEVICEAUTH, true),
      initializerCreater_(std::move(initializerCreater)),
      coreCreater_(std::move(coreCreater))
{
}

bool CompanionDeviceAuthService::CheckPermission(int32_t &companionDeviceAuthResult)
{
    if (!GetAccessTokenKitAdapter().CheckPermission(*this, USE_USER_IDM_PERMISSION)) {
        IAM_LOGE("check use user idm permission failed");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::CHECK_PERMISSION_FAILED);
        return false;
    }
    if (!GetAccessTokenKitAdapter().CheckSystemPermission(*this)) {
        IAM_LOGE("check is system app permission failed");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::CHECK_SYSTEM_PERMISSION_FAILED);
        return false;
    }
    return true;
}

void CompanionDeviceAuthService::OnStart()
{
    IAM_LOGI("Start");
    auto resultOpt = RunOnResidentSync(
        [initializerCreater = initializerCreater_, coreCreater = coreCreater_]()
            -> std::pair<std::shared_ptr<BaseServiceInitializer>, std::shared_ptr<BaseServiceCore>> {
            auto baseServiceInitializer = initializerCreater();
            ENSURE_OR_RETURN_VAL(baseServiceInitializer != nullptr, std::make_pair(nullptr, nullptr));
            GetSystemParamManager().SetParam(CDA_IS_FUNCTION_READY_KEY, TRUE_STR);
            IAM_LOGI("created base service initializer");

            auto inner = coreCreater(baseServiceInitializer->GetSubscriptionManager(),
                baseServiceInitializer->GetSupportedBusinessIds());
            ENSURE_OR_RETURN_VAL(inner != nullptr, std::make_pair(nullptr, nullptr));
            IAM_LOGI("created inner service");

            return std::make_pair(baseServiceInitializer, inner);
        },
        MAX_ON_START_WAIT_TIME_SEC);
    if (!resultOpt.has_value()) {
        IAM_LOGE("failed to create service - timeout");
        return;
    }

    auto [baseServiceInitializer, inner] = resultOpt.value();
    if (baseServiceInitializer == nullptr || inner == nullptr) {
        IAM_LOGE("failed to create base service initializer or inner service");
        return;
    }

    {
        std::lock_guard<std::mutex> lock(innerMutex_);
        baseServiceInitializer_ = baseServiceInitializer;
        inner_ = inner;
    }

    if (!Publish(GetServiceInstance())) {
        IAM_LOGE("fail to publish companion device auth service");
        std::lock_guard<std::mutex> lock(innerMutex_);
        inner_.reset();
        baseServiceInitializer_.reset();
        return;
    }
    IAM_LOGI("End");
}

void CompanionDeviceAuthService::OnStop()
{
    IAM_LOGE("OnStop called unexpectedly - this service should remain resident");
}

ErrCode CompanionDeviceAuthService::SubscribeAvailableDeviceStatus(int32_t localUserId,
    const sptr<IIpcAvailableDeviceStatusCallback> &deviceStatusCallback, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<BaseServiceCore> inner;
    {
        std::lock_guard<std::mutex> lock(innerMutex_);
        inner = inner_;
    }
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    auto resultOpt = RunOnResidentSync([inner, localUserId, deviceStatusCallback]() {
        return inner->SubscribeAvailableDeviceStatus(localUserId, deviceStatusCallback);
    });
    if (!resultOpt.has_value()) {
        IAM_LOGE("SubscribeAvailableDeviceStatus timeout");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::TIMEOUT);
        return ERR_OK;
    }
    companionDeviceAuthResult = static_cast<int32_t>(resultOpt.value());
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::UnsubscribeAvailableDeviceStatus(
    const sptr<IIpcAvailableDeviceStatusCallback> &deviceStatusCallback, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<BaseServiceCore> inner;
    {
        std::lock_guard<std::mutex> lock(innerMutex_);
        inner = inner_;
    }
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    auto resultOpt = RunOnResidentSync(
        [inner, deviceStatusCallback]() { return inner->UnsubscribeAvailableDeviceStatus(deviceStatusCallback); });
    if (!resultOpt.has_value()) {
        IAM_LOGE("UnsubscribeAvailableDeviceStatus timeout");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::TIMEOUT);
        return ERR_OK;
    }
    companionDeviceAuthResult = static_cast<int32_t>(resultOpt.value());
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::SubscribeTemplateStatusChange(int32_t localUserId,
    const sptr<IIpcTemplateStatusCallback> &templateStatusCallback, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<BaseServiceCore> inner;
    {
        std::lock_guard<std::mutex> lock(innerMutex_);
        inner = inner_;
    }
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    auto resultOpt = RunOnResidentSync([inner, localUserId, templateStatusCallback]() {
        return inner->SubscribeTemplateStatusChange(localUserId, templateStatusCallback);
    });
    if (!resultOpt.has_value()) {
        IAM_LOGE("SubscribeTemplateStatusChange timeout");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::TIMEOUT);
        return ERR_OK;
    }
    companionDeviceAuthResult = static_cast<int32_t>(resultOpt.value());
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::UnsubscribeTemplateStatusChange(
    const sptr<IIpcTemplateStatusCallback> &templateStatusCallback, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<BaseServiceCore> inner;
    {
        std::lock_guard<std::mutex> lock(innerMutex_);
        inner = inner_;
    }
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    auto resultOpt = RunOnResidentSync(
        [inner, templateStatusCallback]() { return inner->UnsubscribeTemplateStatusChange(templateStatusCallback); });
    if (!resultOpt.has_value()) {
        IAM_LOGE("UnsubscribeTemplateStatusChange timeout");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::TIMEOUT);
        return ERR_OK;
    }
    companionDeviceAuthResult = static_cast<int32_t>(resultOpt.value());
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::SubscribeContinuousAuthStatusChange(
    const IpcSubscribeContinuousAuthStatusParam &subscribeContinuousAuthStatusParam,
    const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<BaseServiceCore> inner;
    {
        std::lock_guard<std::mutex> lock(innerMutex_);
        inner = inner_;
    }
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    auto resultOpt = RunOnResidentSync([inner, subscribeContinuousAuthStatusParam, continuousAuthStatusCallback]() {
        return inner->SubscribeContinuousAuthStatusChange(subscribeContinuousAuthStatusParam,
            continuousAuthStatusCallback);
    });
    if (!resultOpt.has_value()) {
        IAM_LOGE("SubscribeContinuousAuthStatusChange timeout");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::TIMEOUT);
        return ERR_OK;
    }
    companionDeviceAuthResult = static_cast<int32_t>(resultOpt.value());
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::UnsubscribeContinuousAuthStatusChange(
    const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<BaseServiceCore> inner;
    {
        std::lock_guard<std::mutex> lock(innerMutex_);
        inner = inner_;
    }
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    auto resultOpt = RunOnResidentSync([inner, continuousAuthStatusCallback]() {
        return inner->UnsubscribeContinuousAuthStatusChange(continuousAuthStatusCallback);
    });
    if (!resultOpt.has_value()) {
        IAM_LOGE("UnsubscribeContinuousAuthStatusChange timeout");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::TIMEOUT);
        return ERR_OK;
    }
    companionDeviceAuthResult = static_cast<int32_t>(resultOpt.value());
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::UpdateTemplateEnabledBusinessIds(uint64_t templateId,
    const std::vector<int32_t> &enabledBusinessIds, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<BaseServiceCore> inner;
    {
        std::lock_guard<std::mutex> lock(innerMutex_);
        inner = inner_;
    }
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    auto resultOpt = RunOnResidentSync([inner, templateId, enabledBusinessIds]() {
        return inner->UpdateTemplateEnabledBusinessIds(templateId, enabledBusinessIds);
    });
    if (!resultOpt.has_value()) {
        IAM_LOGE("UpdateTemplateEnabledBusinessIds timeout");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::TIMEOUT);
        return ERR_OK;
    }
    companionDeviceAuthResult = static_cast<int32_t>(resultOpt.value());
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::GetTemplateStatus(int32_t localUserId,
    std::vector<IpcTemplateStatus> &templateStatusArray, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<BaseServiceCore> inner;
    {
        std::lock_guard<std::mutex> lock(innerMutex_);
        inner = inner_;
    }
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    auto resultPair = RunOnResidentSync([inner, localUserId]() {
        std::vector<IpcTemplateStatus> array;
        ResultCode result = inner->GetTemplateStatus(localUserId, array);
        return std::make_pair(result, std::move(array));
    });
    if (!resultPair.has_value()) {
        IAM_LOGE("GetTemplateStatus timeout");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::TIMEOUT);
        return ERR_OK;
    }
    companionDeviceAuthResult = static_cast<int32_t>(resultPair->first);
    templateStatusArray = std::move(resultPair->second);
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::RegisterDeviceSelectCallback(
    const sptr<IIpcDeviceSelectCallback> &deviceSelectCallback, int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<BaseServiceCore> inner;
    {
        std::lock_guard<std::mutex> lock(innerMutex_);
        inner = inner_;
    }
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    uint32_t tokenId = GetAccessTokenKitAdapter().GetAccessTokenId(*this);
    ENSURE_OR_RETURN_VAL(tokenId != 0, ResultCode::GENERAL_ERROR);
    auto resultOpt = RunOnResidentSync([inner, deviceSelectCallback, tokenId]() {
        return inner->RegisterDeviceSelectCallback(tokenId, deviceSelectCallback);
    });
    if (!resultOpt.has_value()) {
        IAM_LOGE("RegisterDeviceSelectCallback timeout");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::TIMEOUT);
        return ERR_OK;
    }
    companionDeviceAuthResult = static_cast<int32_t>(resultOpt.value());
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::UnregisterDeviceSelectCallback(int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<BaseServiceCore> inner;
    {
        std::lock_guard<std::mutex> lock(innerMutex_);
        inner = inner_;
    }
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    uint32_t tokenId = GetAccessTokenKitAdapter().GetAccessTokenId(*this);
    ENSURE_OR_RETURN_VAL(tokenId != 0, ResultCode::GENERAL_ERROR);
    auto resultOpt = RunOnResidentSync([inner, tokenId]() { return inner->UnregisterDeviceSelectCallback(tokenId); });
    if (!resultOpt.has_value()) {
        IAM_LOGE("UnregisterDeviceSelectCallback timeout");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::TIMEOUT);
        return ERR_OK;
    }
    companionDeviceAuthResult = static_cast<int32_t>(resultOpt.value());
    return ERR_OK;
}

ErrCode CompanionDeviceAuthService::CheckLocalUserIdValid(int32_t localUserId, bool &isUserIdValid,
    int32_t &companionDeviceAuthResult)
{
    IAM_LOGI("Start");
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
    if (!CheckPermission(companionDeviceAuthResult)) {
        return ERR_OK;
    }
    std::shared_ptr<BaseServiceCore> inner;
    {
        std::lock_guard<std::mutex> lock(innerMutex_);
        inner = inner_;
    }
    ENSURE_OR_RETURN_VAL(inner != nullptr, ERR_INVALID_VALUE);
    auto resultOpt = RunOnResidentSync([inner, localUserId]() { return inner->CheckLocalUserIdValid(localUserId); });
    if (!resultOpt.has_value()) {
        IAM_LOGE("CheckLocalUserIdValid timeout");
        companionDeviceAuthResult = static_cast<int32_t>(ResultCode::TIMEOUT);
        return ERR_OK;
    }
    companionDeviceAuthResult = static_cast<int32_t>(ResultCode::SUCCESS);
    isUserIdValid = resultOpt.value();
    IAM_LOGI("End");
    return ERR_OK;
}

int32_t CompanionDeviceAuthService::CallbackEnter(uint32_t code)
{
    IAM_LOGI("CallbackEnter, code:%{public}u", code);
    return 0;
}

int32_t CompanionDeviceAuthService::CallbackExit(uint32_t code, int32_t result)
{
    IAM_LOGI("CallbackExit, code:%{public}u, result:%{public}d", code, result);
    return 0;
}

template <typename Func>
std::optional<typename std::invoke_result<Func>::type> CompanionDeviceAuthService::RunOnResidentSync(Func &&func,
    uint32_t timeoutSec)
{
    using Ret = typename std::invoke_result<Func>::type;

    if (TaskRunnerManager::GetInstance().RunningOnDefaultTaskRunner()) {
        IAM_LOGI("running on resident task runner");
        return func();
    }

    auto promise = std::make_shared<std::promise<Ret>>();
    ENSURE_OR_RETURN_VAL(promise != nullptr, std::nullopt);
    auto future = promise->get_future();

    TaskRunnerManager::GetInstance().PostTaskOnResident([task = std::forward<Func>(func), promise]() mutable {
        try {
            promise->set_value(task());
        } catch (...) {
            IAM_LOGE("RunOnResidentSync task exception");
        }
    });

    if (future.wait_for(std::chrono::seconds(timeoutSec)) != std::future_status::ready) {
        IAM_LOGE("RunOnResidentSync timeout - task not completed in %{public}u second", timeoutSec);
        return std::nullopt;
    }

    return future.get();
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
