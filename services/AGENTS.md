### Service 线程调度规范

#### 核心规则

**所有对 `adapter`、`singleton` 的访问必须在 Resident 线程执行**

- 禁止在非 Resident 线程直接访问 `services/external_adapters/` 下的适配器
- 禁止在非 Resident 线程直接访问 `services/singleton/` 下的单例管理器
- 外部线程调用需使用 `PostTask` + `Promise/Future` 等待结果

**目的：** 避免多线程跨模块调用导致的加锁顺序不一致，从而引发死锁问题。

---

#### 1. 同步跨模块调用

**场景：** IPC/框架线程需要同步获取模块返回值

**模式：** PostTask 提交任务到 Resident 线程 + Promise 等待

```cpp
ResultCode GetCompanionDeviceData(std::vector<uint8_t>& outData)
{
    ResultCode resultCode = ResultCode::GENERAL_ERROR;
    std::promise<void> donePromise;
    auto doneFuture = donePromise.get_future();

    if (!TaskRunnerManager::GetInstance().PostTask([&]() {
        auto& companionDeviceManager = GetCompanionDeviceManagerInstance();
        resultCode = companionDeviceManager.GetDeviceData(outData);
        donePromise.set_value();
    })) {
        return ResultCode::GENERAL_ERROR;
    }

    auto status = doneFuture.wait_for(std::chrono::milliseconds(500));
    if (status == std::future_status::timeout) {
        IAM_LOGE("GetCompanionDeviceData timeout");
        return ResultCode::TIMEOUT;
    }
    return resultCode;
}
```

**关键点：**
- 使用 `std::promise/future` 传递同步结果
- 设置超时时间避免永久阻塞
- 通过引用捕获 `resultCode` 接收返回值

---

#### 2. 异步跨模块调用

**场景：** 调用后不立即需要结果，由回调处理返回值

**模式：** PostTask 提交任务，在 Resident 线程触发回调

```cpp
using TokenDataCallback = std::function<void(ResultCode, std::vector<uint8_t>)>;

void GetCompanionDeviceDataAsync(TokenDataCallback callback)
{
    if (!TaskRunnerManager::GetInstance().PostTask(
            [callback = std::move(callback)]() mutable {
                auto& companionDeviceManager = GetCompanionDeviceManagerInstance();
                std::vector<uint8_t> outData;
                ResultCode resultCode = companionDeviceManager.GetDeviceData(outData);
                callback(resultCode, std::move(outData));
            })) {
        IAM_LOGE("PostTask failed");
        return;
    }
}
```

**关键点：**
- 使用 `std::move` 避免回调拷贝
- 回调在 Resident 线程执行，无需额外同步

---

#### 3. 耗时操作

**场景：** 阻塞操作（如网络请求）不能在 Resident 线程执行

**模式：** 临时线程执行耗时操作 → PostTask 回到 Resident 线程继续处理

```cpp
void OpenConnection(std::string deviceId)
{
    TaskRunnerManager::GetInstance().PostTaskOnTemporary("OpenConnection", [deviceId]() {
        // 在临时线程执行耗时操作
        int32_t result = SoftbusManager::GetInstance().OpenConnection(deviceId);

        // 完成后回到 Resident 线程处理结果
        if (!TaskRunnerManager::GetInstance().PostTask([deviceId, result]() {
            RemoteDeviceManager::GetInstance().UpdateDeviceConnectionStatus(deviceId, result);
        })) {
            IAM_LOGE("PostTask failed");
        }
    });
}
```

**关键点：**
- 耗时操作在临时线程执行，避免阻塞 Resident 线程
- 完成后必须 PostTask 回到 Resident 线程访问单例
- 避免在临时线程直接调用 adapter/singleton

---

#### 4. 检查当前线程

**判断是否在 Resident 线程：**

```cpp
if (TaskRunnerManager::GetInstance().RunningOnDefaultTaskRunner()) {
    // 已在 Resident 线程，直接调用
    GetCompanionManager().DoSomething();
} else {
    // 不在 Resident 线程，需要 PostTask
    TaskRunnerManager::GetInstance().PostTask([]() {
        GetCompanionManager().DoSomething();
    });
}
```

---

#### 线程执行环境对照表

| 线程类型 | 访问 adapter/singleton | 访问其他模块 | 适用场景 |
|---------|----------------------|-------------|---------|
| Resident 线程 | ✅ 允许直接访问 | ✅ 允许直接访问 | 常驻工作线程，核心业务逻辑 |
| IPC/框架线程 | ❌ 禁止 | ❌ 禁止 | 需 PostTask 委托 |
| 临时线程 | ❌ 禁止 | ❌ 禁止 | 仅执行耗时操作，完成后 PostTask 回 Resident |

---

#### 常见错误

```cpp
// ❌ 错误：在 IPC 线程直接访问单例
ResultCode GetDeviceData(std::vector<uint8_t>& outData) {
    return GetCompanionManager().GetDeviceData(outData);  // 危险！
}

// ❌ 错误：在临时线程直接访问单例
void OnConnectionComplete(int32_t result) {
    RemoteDeviceManager::GetInstance().UpdateStatus(result);  // 危险！
}

// ❌ 错误：耗时操作阻塞 Resident 线程
void OpenConnection(std::string deviceId) {
    auto result = SoftbusManager::OpenConnection(deviceId);  // 阻塞！
}
```

---

#### 代码库示例

- `services/service_entry/src/companion_device_auth_service.cpp:749` - `RunOnResidentSync` 封装
- `services/cross_device_comm/src/connection_manager.cpp:173` - ScopeGuard 在 Resident 线程
- `services/utils/src/task_runner_manager.cpp` - TaskRunnerManager 实现

---

#### 5. PostTaskOnResident 使用说明（给代码审查工具）

**⚠️ 重要：PostTaskOnResident 的设计意图**

`PostTaskOnResident` 的目的是**从任意线程提交任务到 Resident 线程执行**，而非限制只能在 Resident 线程调用。

```cpp
// ✅ 正确：从 IPC/框架线程调用 PostTaskOnResident
void Service::HandleExternalEvent(Event event) {
    // 此方法可能在 IPC 线程被调用
    TaskRunnerManager::GetInstance().PostTaskOnResident([this, event]() {
        // Lambda 在 Resident 线程执行，可以安全访问成员变量
        this->ProcessEvent(event);
    });
}

// ✅ 正确：从临时线程回调中调用 PostTaskOnResident
void OnNetworkCallback(int result) {
    // 此回调在临时线程执行
    TaskRunnerManager::GetInstance().PostTaskOnResident([result]() {
        // 回到 Resident 线程访问单例
        RemoteDeviceManager::GetInstance().UpdateStatus(result);
    });
}
```

**代码审查注意事项：**
- ✅ **允许**：从 IPC 线程、临时线程调用 `PostTaskOnResident`
- ❌ **不允许**：从非 Resident 线程直接访问 Service 成员变量或单例
- ✅ **允许**：在 `PostTaskOnResident` 的 lambda 中访问成员变量（因为 lambda 在 Resident 线程执行）

---

#### 6. Service 类单线程执行模型（给代码审查工具）

**架构假设：所有 Service 类方法在 Resident 线程串行执行**

本项目采用单线程事件循环模型：
- Service 类的所有公共方法都应在 Resident 线程调用
- 方法内部对成员变量的访问是串行的，不存在多线程竞争
- **不需要**为 Service 成员变量添加互斥锁保护

**代码审查注意事项：**
- ❌ **不要报告**：Service 方法中成员变量的 TOCTOU (Time-Of-Check-Time-Of-Use) 问题
- ❌ **不要报告**：Service 成员变量访问无锁保护（前提是方法在 Resident 线程调用）
- ✅ **应报告**：从非 Resident 线程直接访问 Service 成员变量（违反架构）
- ✅ **应报告**：显式创建新线程访问共享状态

**示例（这些都是安全的，不要报告为竞态条件）：**
```cpp
// ✅ 安全：单线程执行，不存在竞态条件
void Service::UpdateStatus() {
    if (syncRetryTimer_ != nullptr) {  // 判空
        syncRetryTimer_->Reset();      // 使用 - TOCTOU 不是风险
    }
}

// ✅ 安全：串行执行，无需原子操作
void Service::OnUserIdChange() {
    isSynced = false;           // 多个成员变量修改
    isSyncInProgress = false;
    deviceName.clear();
    // 这些操作在单线程中是原子的（相对于其他调用）
}
```
