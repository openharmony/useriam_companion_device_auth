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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "mock_companion_manager.h"
#include "mock_event_manager_adapter.h"
#include "mock_misc_manager.h"
#include "mock_request_factory.h"
#include "mock_request_manager.h"
#include "mock_time_keeper.h"
#include "mock_user_id_manager.h"

#include "adapter_manager.h"
#include "host_mix_auth_request.h"
#include "host_single_mix_auth_request.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

// 测试数据常量
constexpr ScheduleId SCHEDULE_ID = 1;
const std::vector<uint8_t> FWK_MSG = { 1, 2, 3, 4 };
constexpr UserId HOST_USER_ID = 100;
constexpr TemplateId TEMPLATE_ID = 12345;
const std::vector<uint8_t> EXTRA_INFO = { 5, 6, 7, 8 };
const int32_t AUTH_INTENTION = 1;
const DeviceKey COMPANION_DEVICE_KEY = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
    .deviceId = "companion_device_id",
    .deviceUserId = 200 };

class HostSingleMixAuthRequestTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto companionMgr = std::shared_ptr<ICompanionManager>(&mockCompanionManager_, [](ICompanionManager *) {});
        SingletonManager::GetInstance().SetCompanionManager(companionMgr);

        auto requestFactory = std::shared_ptr<IRequestFactory>(&mockRequestFactory_, [](IRequestFactory *) {});
        SingletonManager::GetInstance().SetRequestFactory(requestFactory);

        auto requestMgr = std::shared_ptr<IRequestManager>(&mockRequestManager_, [](IRequestManager *) {});
        SingletonManager::GetInstance().SetRequestManager(requestMgr);

        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        auto userIdMgr = std::shared_ptr<IUserIdManager>(&mockUserIdManager_, [](IUserIdManager *) {});
        AdapterManager::GetInstance().SetUserIdManager(userIdMgr);

        auto timeKeeper = std::make_shared<MockTimeKeeper>();
        AdapterManager::GetInstance().SetTimeKeeper(timeKeeper);

        auto eventManagerAdapter =
            std::shared_ptr<IEventManagerAdapter>(&mockEventManagerAdapter_, [](IEventManagerAdapter *) {});
        AdapterManager::GetInstance().SetEventManagerAdapter(eventManagerAdapter);

        ON_CALL(mockCompanionManager_, IsCapabilitySupported(_, Capability::TOKEN_AUTH)).WillByDefault(Return(true));
        ON_CALL(mockCompanionManager_, IsCapabilitySupported(_, Capability::DELEGATE_AUTH)).WillByDefault(Return(true));
        ON_CALL(mockRequestFactory_, CreateHostTokenAuthRequest(_, _))
            .WillByDefault(Invoke([this](const AuthRequestParams &params, FwkResultCallback &&requestCallback) {
                return std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(requestCallback));
            }));
        ON_CALL(mockRequestFactory_, CreateHostDelegateAuthRequest(_, _))
            .WillByDefault(Invoke([this](const AuthRequestParams &params, FwkResultCallback &&requestCallback) {
                return std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY,
                    std::move(requestCallback));
            }));
        ON_CALL(mockRequestManager_, Start(_)).WillByDefault(Return(true));
        ON_CALL(mockEventManagerAdapter_, ReportInteractionEvent(_)).WillByDefault(Return());
    }

    void TearDown() override
    {
        RelativeTimer::GetInstance().ExecuteAll();
        TaskRunnerManager::GetInstance().ExecuteAll();
        RelativeTimer::GetInstance().ExecuteAll();
        TaskRunnerManager::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
        AdapterManager::GetInstance().Reset();
    }

protected:
    NiceMock<MockCompanionManager> mockCompanionManager_;
    NiceMock<MockRequestFactory> mockRequestFactory_;
    NiceMock<MockRequestManager> mockRequestManager_;
    NiceMock<MockMiscManager> mockMiscManager_;
    NiceMock<MockUserIdManager> mockUserIdManager_;
    NiceMock<MockEventManagerAdapter> mockEventManagerAdapter_;
};

HWTEST_F(HostSingleMixAuthRequestTest, Start_001, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    request->requestCallback_ = [callbackCalled](ResultCode, const std::vector<uint8_t> &) { *callbackCalled = true; };

    EXPECT_CALL(mockRequestFactory_, CreateHostTokenAuthRequest(_, _))
        .WillOnce(Invoke([this](const AuthRequestParams &params, FwkResultCallback &&requestCallback) {
            return std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(requestCallback));
        }));
    // HostTokenAuthRequest Start will be called first
    // If it fails, HostDelegateAuthRequest Start may be called, so allow up to 2 Start calls
    EXPECT_CALL(mockRequestManager_, Start(_)).Times(AtMost(2)).WillRepeatedly(Return(true));

    request->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(*callbackCalled);
}

HWTEST_F(HostSingleMixAuthRequestTest, Start_002, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    EXPECT_CALL(mockRequestFactory_, CreateHostTokenAuthRequest(_, _)).WillOnce(Return(nullptr));

    request->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostSingleMixAuthRequestTest, Start_003, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    EXPECT_CALL(mockRequestFactory_, CreateHostTokenAuthRequest(_, _))
        .WillOnce(Invoke([this](const AuthRequestParams &params, FwkResultCallback &&requestCallback) {
            return std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(requestCallback));
        }));
    // Allow multiple calls during cleanup - return false for the first call, then true for any additional calls
    EXPECT_CALL(mockRequestManager_, Start(_)).WillOnce(Return(false)).WillRepeatedly(Return(true));

    request->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostSingleMixAuthRequestTest, Cancel_001, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    bool result = request->Cancel(ResultCode::CANCELED);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(result);
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::CANCELED);
}

HWTEST_F(HostSingleMixAuthRequestTest, Cancel_002, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    request->cancelled_ = true;

    bool result = request->Cancel(ResultCode::CANCELED);

    EXPECT_TRUE(result);
}

HWTEST_F(HostSingleMixAuthRequestTest, Cancel_003, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    request->Start();
    bool result = request->Cancel(ResultCode::CANCELED);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(result);
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::CANCELED);
}

HWTEST_F(HostSingleMixAuthRequestTest, Cancel_004, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    request->Start();
    request->HandleTokenAuthResult(ResultCode::GENERAL_ERROR, EXTRA_INFO);
    bool result = request->Cancel(ResultCode::CANCELED);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(result);
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::CANCELED);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleTokenAuthResult_001, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::GENERAL_ERROR);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    request->Start();
    request->HandleTokenAuthResult(ResultCode::SUCCESS, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::SUCCESS);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleTokenAuthResult_002, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    request->requestCallback_ = [callbackCalled](ResultCode, const std::vector<uint8_t> &) { *callbackCalled = true; };

    EXPECT_CALL(mockRequestFactory_, CreateHostDelegateAuthRequest(_, _))
        .WillOnce(Invoke([this](const AuthRequestParams &params, FwkResultCallback &&requestCallback) {
            return std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(requestCallback));
        }));
    EXPECT_CALL(mockRequestManager_, Start(_)).WillOnce(Return(true)).WillOnce(Return(true));

    request->Start();
    request->HandleTokenAuthResult(ResultCode::GENERAL_ERROR, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(*callbackCalled);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleTokenAuthResult_003, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    request->requestCallback_ = [callbackCalled](ResultCode, const std::vector<uint8_t> &) { *callbackCalled = true; };

    request->tokenAuthRequest_ = nullptr;
    request->HandleTokenAuthResult(ResultCode::SUCCESS, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(*callbackCalled);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleTokenAuthResult_004, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    EXPECT_CALL(mockRequestFactory_, CreateHostDelegateAuthRequest(_, _)).WillOnce(Return(nullptr));

    request->Start();
    request->HandleTokenAuthResult(ResultCode::GENERAL_ERROR, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleTokenAuthResult_005, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    EXPECT_CALL(mockRequestFactory_, CreateHostDelegateAuthRequest(_, _))
        .WillOnce(Invoke([this](const AuthRequestParams &params, FwkResultCallback &&requestCallback) {
            return std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(requestCallback));
        }));
    EXPECT_CALL(mockRequestManager_, Start(_)).WillOnce(Return(true)).WillOnce(Return(false));

    request->Start();
    request->HandleTokenAuthResult(ResultCode::GENERAL_ERROR, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleDelegateAuthResult_001, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::GENERAL_ERROR);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    request->Start();
    request->HandleTokenAuthResult(ResultCode::GENERAL_ERROR, EXTRA_INFO);
    request->HandleDelegateAuthResult(ResultCode::SUCCESS, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::SUCCESS);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleDelegateAuthResult_002, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    request->Start();
    request->HandleTokenAuthResult(ResultCode::GENERAL_ERROR, EXTRA_INFO);
    request->HandleDelegateAuthResult(ResultCode::GENERAL_ERROR, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleDelegateAuthResult_003, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    request->requestCallback_ = [callbackCalled](ResultCode, const std::vector<uint8_t> &) { *callbackCalled = true; };

    request->delegateAuthRequest_ = nullptr;
    request->HandleDelegateAuthResult(ResultCode::SUCCESS, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(*callbackCalled);
}

HWTEST_F(HostSingleMixAuthRequestTest, InvokeCallback_001, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    request->requestCallback_ = [callbackCalled](ResultCode, const std::vector<uint8_t> &) { *callbackCalled = true; };

    request->requestCallback_ = nullptr;
    request->InvokeCallback(ResultCode::SUCCESS, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(*callbackCalled);
}

HWTEST_F(HostSingleMixAuthRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    EXPECT_EQ(request->GetMaxConcurrency(), 10);
}

HWTEST_F(HostSingleMixAuthRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    bool result = request->ShouldCancelOnNewRequest(RequestType::HOST_MIX_AUTH_REQUEST, std::nullopt, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(HostSingleMixAuthRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    bool result = request->ShouldCancelOnNewRequest(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST, std::nullopt, 0);
    EXPECT_FALSE(result);
}

HWTEST_F(HostSingleMixAuthRequestTest, ShouldCancelOnNewRequest_003, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    bool result = request->ShouldCancelOnNewRequest(RequestType::HOST_ADD_COMPANION_REQUEST, std::nullopt, 0);
    EXPECT_FALSE(result);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
