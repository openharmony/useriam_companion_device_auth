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

#include <cstdint>
#include <memory>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"
#include "interaction_desc.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using InteractionDescFuzzFunction = void (*)(InteractionDesc &desc, FuzzedDataProvider &fuzzData);

static void FuzzDefaultConstructor(FuzzedDataProvider &fuzzData)
{
    InteractionDesc desc;
    (void)desc.GetCStr();
    (void)fuzzData;
}

static void FuzzPrefixTypeConstructor(FuzzedDataProvider &fuzzData)
{
    std::string prefix = GenerateFuzzString(fuzzData, 16);
    std::string type = GenerateFuzzString(fuzzData, 16);
    InteractionDesc desc(prefix.c_str(), type.c_str());
    (void)desc.GetCStr();
}

static void FuzzSetConnectionName(InteractionDesc &desc, FuzzedDataProvider &fuzzData)
{
    std::string connName = GenerateFuzzString(fuzzData, 64);
    desc.SetConnectionName(connName);
}

static void FuzzSetRequestId(InteractionDesc &desc, FuzzedDataProvider &fuzzData)
{
    RequestId requestId = fuzzData.ConsumeIntegral<RequestId>();
    desc.SetRequestId(requestId);
}

static void FuzzSetBindingId(InteractionDesc &desc, FuzzedDataProvider &fuzzData)
{
    BindingId bindingId = fuzzData.ConsumeIntegral<BindingId>();
    desc.SetBindingId(bindingId);
}

static void FuzzSetTemplateId(InteractionDesc &desc, FuzzedDataProvider &fuzzData)
{
    TemplateId templateId = fuzzData.ConsumeIntegral<TemplateId>();
    desc.SetTemplateId(templateId);
}

static void FuzzSetTemplateIdList(InteractionDesc &desc, FuzzedDataProvider &fuzzData)
{
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 16);
    std::vector<TemplateId> list;
    list.reserve(count);
    for (uint8_t i = 0; i < count; ++i) {
        list.push_back(fuzzData.ConsumeIntegral<TemplateId>());
    }
    desc.SetTemplateIdList(list);
}

static void FuzzGetCStr(InteractionDesc &desc, FuzzedDataProvider &fuzzData)
{
    const char *str = desc.GetCStr();
    (void)str;
    (void)fuzzData;
}

static void FuzzTemplateIdListToggle(InteractionDesc &desc, FuzzedDataProvider &fuzzData)
{
    desc.SetTemplateId(fuzzData.ConsumeIntegral<TemplateId>());
    (void)desc.GetCStr();

    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 8);
    std::vector<TemplateId> list;
    for (uint8_t i = 0; i < count; ++i) {
        list.push_back(fuzzData.ConsumeIntegral<TemplateId>());
    }
    desc.SetTemplateIdList(list);
    (void)desc.GetCStr();

    desc.SetTemplateId(fuzzData.ConsumeIntegral<TemplateId>());
    (void)desc.GetCStr();
}

static const InteractionDescFuzzFunction g_fuzzFuncs[] = {
    nullptr, // placeholder for prefix+type constructor
    FuzzSetConnectionName,
    FuzzSetRequestId,
    FuzzSetBindingId,
    FuzzSetTemplateId,
    FuzzSetTemplateIdList,
    FuzzGetCStr,
    FuzzTemplateIdListToggle,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(InteractionDescFuzzFunction);

void FuzzInteractionDesc(FuzzedDataProvider &fuzzData)
{
    // Test default constructor
    FuzzDefaultConstructor(fuzzData);
    if (!fuzzData.remaining_bytes()) {
        return;
    }

    // Test prefix+type constructor
    FuzzPrefixTypeConstructor(fuzzData);
    if (!fuzzData.remaining_bytes()) {
        return;
    }

    // Create a desc for sequential operations
    std::string prefix = GenerateFuzzString(fuzzData, 8);
    std::string type = GenerateFuzzString(fuzzData, 8);
    InteractionDesc desc(prefix.c_str(), type.c_str());

    for (size_t i = 1; i < NUM_FUZZ_OPERATIONS; ++i) { // skip index 0 (null placeholder)
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](desc, fuzzData);
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + (NUM_FUZZ_OPERATIONS - 1) * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }
        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(1, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](desc, fuzzData);
    }
}

FUZZ_REGISTER(FuzzInteractionDesc)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
