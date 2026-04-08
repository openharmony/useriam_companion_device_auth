/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

// Fake implementation of RelativeTimer for unit tests

#include "relative_timer.h"

#include <atomic>
#include <functional>
#include <map>
#include <memory>

#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
struct TimerEntry {
    RelativeTimer::TimerCallback callback;
    uint64_t deadlineMs { 0 }; // absolute deadline from time provider
};

auto g_pendingTasks = std::make_shared<std::map<uint64_t, TimerEntry>>();
auto g_nextTaskId = std::make_shared<std::atomic<uint64_t>>(0);
std::function<uint64_t()> g_timeProvider = []() { return 0; };
} // namespace

RelativeTimer::RelativeTimer()
{
}

RelativeTimer::~RelativeTimer() = default;

std::unique_ptr<Subscription> RelativeTimer::Register(TimerCallback &&callback, uint32_t ms)
{
    uint64_t taskId = (*g_nextTaskId)++;
    auto &entry = (*g_pendingTasks)[taskId];
    entry.callback = std::move(callback);
    entry.deadlineMs = g_timeProvider() + ms;
    return std::make_unique<Subscription>([taskId]() { g_pendingTasks->erase(taskId); });
}

std::unique_ptr<Subscription> RelativeTimer::RegisterPeriodic(TimerCallback &&callback, uint32_t ms)
{
    return Register(std::move(callback), ms);
}

void RelativeTimer::PostTask(TimerCallback &&callback, uint32_t ms)
{
    uint64_t taskId = (*g_nextTaskId)++;
    auto &entry = (*g_pendingTasks)[taskId];
    entry.callback = std::move(callback);
    entry.deadlineMs = g_timeProvider() + ms;
}

void RelativeTimer::ExecuteAll()
{
    auto tasks = std::move(*g_pendingTasks);
    g_pendingTasks->clear();
    for (auto &entry : tasks) {
        if (entry.second.callback) {
            entry.second.callback();
        }
    }
}

void RelativeTimer::EnsureAllTaskExecuted()
{
    const int maxAttempts = 100;
    for (int i = 0; i < maxAttempts; ++i) {
        ExecuteAll();
        if (g_pendingTasks->empty()) {
            return;
        }
    }
}

void RelativeTimer::DrainExpiredTasks()
{
    const int maxAttempts = 100;
    for (int i = 0; i < maxAttempts; ++i) {
        auto tasks = std::move(*g_pendingTasks);
        g_pendingTasks->clear();
        uint64_t now = g_timeProvider();
        bool anyExecuted = false;
        for (auto &entry : tasks) {
            if (entry.second.callback && now >= entry.second.deadlineMs) {
                entry.second.callback();
                anyExecuted = true;
            } else if (entry.second.callback) {
                (*g_pendingTasks)[entry.first] = std::move(entry.second);
            }
        }
        if (g_pendingTasks->empty() || !anyExecuted) {
            return;
        }
    }
}

void RelativeTimer::SetTimeProvider(std::function<uint64_t()> provider)
{
    g_timeProvider = std::move(provider);
    // Clear stale timer entries from previous tests.
    // Old deadlines were computed against the previous time source and are invalid.
    g_pendingTasks->clear();
    g_nextTaskId->store(0);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
