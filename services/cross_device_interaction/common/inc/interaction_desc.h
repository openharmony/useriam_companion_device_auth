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

#ifndef COMPANION_DEVICE_AUTH_INTERACTION_DESC_H
#define COMPANION_DEVICE_AUTH_INTERACTION_DESC_H

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
inline constexpr const char *HANDLER_PREFIX = "CdaH";
inline constexpr const char *REQUEST_PREFIX = "CdaR";

class InteractionDesc {
public:
    InteractionDesc() = default;
    InteractionDesc(const char *prefix, const char *type);
    ~InteractionDesc() = default;

    void SetConnectionName(const std::string &connName);
    void SetRequestId(RequestId requestId);
    void SetBindingId(BindingId bindingId);
    void SetTemplateId(TemplateId templateId);
    void SetTemplateIdList(const std::vector<TemplateId> &templateIdList);

    const char *GetCStr() const;

private:
    void Rebuild();

    std::string prefix_;
    std::string type_;
    std::string connectionName_;
    std::optional<RequestId> requestId_;
    std::optional<BindingId> bindingId_;
    std::optional<TemplateId> templateId_;
    std::vector<TemplateId> templateIdList_;
    std::string description_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_INTERACTION_DESC_H
