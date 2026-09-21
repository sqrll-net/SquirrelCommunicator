// Created by https://www.linkedin.com/in/przemek2122/ 2026

#include "Managers/EmailVerificationManager.h"

#include "ThreadCompat.h"

#include <random>

FEmailVerificationManager::FEmailVerificationManager(int32 InCodeAliveTimeMins)
    : CodeAliveTimeMins(InCodeAliveTimeMins)
    , AsyncWorkLastTime(0)
{
}

void FEmailVerificationManager::Init()
{
    AsyncWorkLastTime = FUtil::GetSeconds();

    WorkerThread = std::jthread([this](std::stop_token stoken)
    {
        constexpr Uint64 TimeToWaitBetweenRuns = 60; // Time to wait (in seconds)

        while (!stoken.stop_requested())
        {
            const Uint64 CurrentTime = FUtil::GetSeconds();

            if (CurrentTime > (AsyncWorkLastTime + TimeToWaitBetweenRuns))
            {
                AsyncCleanupExpired();
                AsyncWorkLastTime = FUtil::GetSeconds();
            }

            // Sleep 1 second between checks
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });
}

FPendingRegistration FEmailVerificationManager::GenerateVerificationCode(const std::string& UserMail, const std::string& UserName, const std::string& PasswordHash)
{
    // Verification code must be unpredictable.
    std::random_device RandomDevice;
    std::uniform_int_distribution<int32> Distribution(0, 9);

    std::string Code;
    Code.reserve(6);
    for (int32 i = 0; i < 6; ++i)
    {
        Code.push_back(static_cast<char>('0' + Distribution(RandomDevice)));
    }

    FPendingRegistration Pending;
    Pending.UserMail = UserMail;
    Pending.UserName = UserName;
    Pending.PasswordHash = PasswordHash;
    Pending.VerificationCode = Code;
    Pending.ExpirationTime = std::chrono::system_clock::now() + std::chrono::minutes(CodeAliveTimeMins);

    std::unique_lock<std::shared_mutex> Lock(PendingMutex);
    MailToPendingRegistration[UserMail] = Pending;

    return Pending;
}

FPendingRegistration FEmailVerificationManager::ValidateCode(const std::string& UserMail, const std::string& Code)
{
    FPendingRegistration Out;

    std::shared_lock<std::shared_mutex> Lock(PendingMutex);
    const auto It = MailToPendingRegistration.find(UserMail);
    if (It != MailToPendingRegistration.end())
    {
        const FPendingRegistration& Pending = It->second;
        if (Pending.VerificationCode == Code && Pending.ExpirationTime > std::chrono::system_clock::now())
        {
            Out = Pending;
        }
    }

    return Out;
}

void FEmailVerificationManager::ConsumeCode(const std::string& UserMail, const std::string& Code)
{
    std::unique_lock<std::shared_mutex> Lock(PendingMutex);

    const auto It = MailToPendingRegistration.find(UserMail);
    if (It != MailToPendingRegistration.end() && It->second.VerificationCode == Code)
    {
        MailToPendingRegistration.erase(It);
    }
}

void FEmailVerificationManager::AsyncCleanupExpired()
{
    std::unique_lock<std::shared_mutex> Lock(PendingMutex);

    for (auto It = MailToPendingRegistration.begin(); It != MailToPendingRegistration.end();)
    {
        if (It->second.ExpirationTime < std::chrono::system_clock::now())
        {
            It = MailToPendingRegistration.erase(It);
        }
        else
        {
            ++It;
        }
    }
}
