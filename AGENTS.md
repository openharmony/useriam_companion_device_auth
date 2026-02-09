### 代码规范 (Code Style & Guidelines)

#### 1. 内存管理规范

**原则：必须判空，使用智能指针**

- 使用 `new` / `std::make_shared<T>()` / `std::make_unique<T>` 创建对象，必须判空
- 动态分配后**必须**使用 `ENSURE_OR_RETURN_VAL` 进行空指针检查

**示例模式：**

```cpp
// ✅ 正确：make_shared + 判空
auto ptr = std::make_shared<T>();
ENSURE_OR_RETURN_VAL(ptr != nullptr, false);

// ✅ 正确：make_unique + 判空
auto ptr = std::make_unique<T>();
ENSURE_OR_RETURN_VAL(ptr != nullptr, false);

// ✅ 正确：new (std::nothrow) + 判空
auto ptr = new (std::nothrow) T();
ENSURE_OR_RETURN_VAL(ptr != nullptr, false);

// ✅ 正确：工厂方法返回值判空
auto obj = T::Create();
ENSURE_OR_RETURN_VAL(obj != nullptr, nullptr);

// ❌ 错误：未判空
auto ptr = std::make_shared<T>();
return ptr;  // 如果分配失败会返回空指针

// ❌ 错误：使用 new 而非智能指针
auto ptr = new T();  // 应使用智能指针管理
```

#### 2. 指针使用规范

**原则：除栈对象（如 ScopeGuard）等生命周期明确的情况外，避免传递裸指针**

**适用场景对比：**

| 场景 | 允许使用裸指针 | 要求 |
|------|---------------|------|
| 栈对象（ScopeGuard、回调清理） | ✅ 是 | 对象生命周期明确 |
| Lambda 捕获 this | ❌ 否 | 必须使用 weak_from_this |
| 成员变量存储 | ❌ 否 | 使用 std::shared_ptr |
| 函数参数传递 | ❌ 否 | 使用 const std::shared_ptr& |
| 异步回调捕获 | ❌ 否 | 使用 weak_from_this |

**示例模式：**

```cpp
// ✅ 正确：栈对象可以使用裸指针 this
void ProcessData() {
    ScopeGuard guard([this]() {
        this->CleanUp();  // 安全：guard 与 this 同生命周期
    });
    // ... 处理逻辑
}

// ✅ 正确：异步回调使用 weak_from_this
class MyClass : public std::enable_shared_from_this<MyClass> {
public:
    void StartAsyncOperation() {
        auto callback = [weakSelf = weak_from_this()](Result result) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);  // 对象已销毁则返回
            self->HandleResult(result);
        };
        SomeAsyncApi(callback);
    }
};

// ❌ 错误：异步回调直接捕获 this
void StartAsyncOperation() {
    auto callback = [this](Result result) {
        this->HandleResult(result);  // 危险：对象可能已销毁
    };
    SomeAsyncApi(callback);
}

// ❌ 错误：捕获 shared_from_this() 导致内存泄漏
void StartAsyncOperation() {
    auto callback = [self = shared_from_this()](Result result) {
        self->HandleResult(result);  // 会延长对象生命周期
    };
    SomeAsyncApi(callback);
}

// ❌ 错误：成员变量使用裸指针
class MyClass {
    T* ptr_;  // 应使用 std::shared_ptr<T> ptr_
};
```

**关键要点：**
- `weak_from_this()` 不增加引用计数，允许对象正常销毁
- `lock()` 返回空 `shared_ptr` 表示对象已销毁，必须判空
- 栈对象（如 ScopeGuard）与当前函数同生命周期，可安全使用 `this`

#### 3. 指针使用前必须判空（防御性编程）

**原则：跨函数调用必须判空，同方法内已判空可复用**

- **成员变量**：不同方法使用成员变量前，需在各自方法内判空
- **函数参数**：被调用函数内部必须对参数判空，不依赖调用方
- **同方法内**：方法开头已判空的成员变量，后续使用无需重复判空
- **跨方法调用**：即使调用方已判空，被调用方法仍需重新判空

**原因：**
- 代码维护过程中，初始化逻辑可能被修改，导致判空失效
- 多线程环境下，指针状态可能在两次判空之间发生变化
- 防御性编程原则，提高代码健壮性

**示例模式：**

```cpp
// ✅ 正确：方法开头判空，后续使用无需重复判空
class MyClass {
    std::shared_ptr<SomeType> member_;
    void UseMember() {
        ENSURE_OR_RETURN(member_ != nullptr);  // 开头判空
        member_->DoSomething();                 // ✅ 后续直接使用，无需重复判空
        member_->DoAnotherThing();              // ✅ 无需重复判空
    }
};

// ❌ 错误：同方法内重复判空
void UseMember() {
    ENSURE_OR_RETURN(member_ != nullptr);
    member_->DoSomething();
    ENSURE_OR_RETURN(member_ != nullptr);  // ❌ 不必要，已判空
    member_->DoAnotherThing();
}

// ✅ 正确：不同方法各自判空
class MyClass {
    std::shared_ptr<SomeType> member_;
    void Method1() {
        ENSURE_OR_RETURN(member_ != nullptr);  // Method1 需要判空
        member_->DoSomething();
    }
    void Method2() {
        ENSURE_OR_RETURN(member_ != nullptr);  // Method2 需要重新判空
        member_->DoAnotherThing();
    }
};

// ✅ 正确：函数参数即使调用方已判空，内部仍需判空
void OuterFunction() {
    auto ptr = std::make_shared<T>();
    ENSURE_OR_RETURN(ptr != nullptr);
    InnerFunction(ptr);  // 调用方已判空
}

void InnerFunction(const std::shared_ptr<T> &ptr) {
    ENSURE_OR_RETURN_VAL(ptr != nullptr, false);  // 仍需判空
    ptr->DoSomething();
}

// ❌ 错误：依赖外层函数的判空，内部未判空
void InnerFunction(const std::shared_ptr<T> &ptr) {
    ptr->DoSomething();  // 危险：假设 ptr 非空，但可能被修改为空
}

// ❌ 错误：成员变量使用时未判空
class MyClass {
    std::shared_ptr<SomeType> member_;
    void UseMember() {
        member_->DoSomething();  // 危险：假设 member_ 非空，但可能为空
    }
};
```

**特殊情况（例外）：**
- **栈对象的裸指针**：如 `ScopeGuard` 中的 `this` 指针，因生命周期明确可免判空
- **私有内部函数**：如果确保调用路径完全可控，可经代码审查后豁免

**代码审查检查点：**
- [ ] 所有 `std::shared_ptr`/`std::unique_ptr` 成员变量使用前是否有 `ENSURE_OR_RETURN`
- [ ] 所有智能指针参数在函数入口处是否有判空检查
- [ ] 是否存在直接使用 `ptr->Method()` 而未先判空的情况

**代码库示例：**
- `services/cross_device_comm/src/device_status_manager.cpp:299` - weak_from_this
- `services/cross_device_interaction/delegate_auth/src/companion_delegate_auth_request.cpp:80` - weak_from_this
- `services/cross_device_comm/src/connection_manager.cpp:173` - ScopeGuard 使用 this
