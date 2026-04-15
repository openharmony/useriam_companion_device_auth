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

#ifndef COMPANION_DEVICE_AUTH_PENDING_ISSUE_TOKEN_MANAGER_H
#define COMPANION_DEVICE_AUTH_PENDING_ISSUE_TOKEN_MANAGER_H

#include <cstdint>
#include <map>
#include <memory>
#include <vector>

#include "nocopyable.h"

#include "service_common.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

struct FreezeCommand {
    uint32_t authTypeValue = 0;
    uint32_t lockStateAuthTypeValue = 0;
    int32_t userId = 0;
    std::vector<uint64_t> templateIdList;
};

struct PendingEntry {
    int32_t userId { 0 };
    uint32_t lockStateAuthTypeValue { 0 };
    std::vector<uint8_t> fwkMsg;
    SteadyTimeMs createTimeMs { 0 };
};

class PendingIssueTokenManager : public NoCopyable, public std::enable_shared_from_this<PendingIssueTokenManager> {
public:
    PendingIssueTokenManager() = default;
    ~PendingIssueTokenManager() = default;

    void Defer(const FreezeCommand &freezeCommand, const std::vector<uint8_t> &extraInfo);
    void CancelByUserId(int32_t userId);

private:
    void OnCompanionStatusChange(const std::vector<CompanionStatus> &companionStatusList);
    void HandleTimeoutCheck();
    void EnsureSubscription();

    std::map<TemplateId, PendingEntry> pendingEntries_;
    std::unique_ptr<Subscription> companionStatusSubscription_;
    std::unique_ptr<Subscription> timeoutCheckTimer_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_PENDING_ISSUE_TOKEN_MANAGER_H
