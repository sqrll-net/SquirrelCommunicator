// Created by https://www.linkedin.com/in/przemek2122/ 2026 https://github.com/Przemek2122/Engine

#include "Managers/PasswordResetManager.h"

#include "ProjectEngine.h"
#include "Auth/UserManager.h"
#include "ThreadCompat.h"

#include "SQRLLEncryption.h"

FPasswordResetManager::FPasswordResetManager(int32 InTimeInMinsForTokenToBeAlive)
    : TimeInMinsForTokenToBeAlive(InTimeInMinsForTokenToBeAlive)
    , AsyncWorkLastTime(0)
{
}

void FPasswordResetManager::Init()
{
    // Initially skip, there is no chance we will somehow get tokens
    AsyncWorkLastTime = FUtil::GetSeconds();

    WorkerThread = std::jthread([this](std::stop_token stoken)
    {
        constexpr Uint64 TimeToWaitBetweenRuns = 60; // Time to wait (in seconds)

        while (!stoken.stop_requested())
        {
            const Uint64 CurrentTime = FUtil::GetSeconds();

            if (CurrentTime > (AsyncWorkLastTime + TimeToWaitBetweenRuns))
            {
                AsyncCleanupTokens();
                AsyncWorkLastTime = FUtil::GetSeconds();
            }

            // Sleep 1 second between checks
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });
}

FPasswordResetStruct FPasswordResetManager::GenerateResetToken(const std::string& UserMail)
{
    // SECURITY: generate the reset token with a CSPRNG of at least 128 bits of
    // entropy. The previous 6-hex-char token had only 24 bits (~16.7M options),
    // which is realistically brute-forceable. std::mt19937 (Mersenne Twister) is
    // also deterministic and its state can be recovered after observing enough
    // outputs, so it must never be used for security tokens.
    const std::string RawToken = FEncryptionUtil::GenerateSecureSalt(16); // 16 bytes = 128 bits

    // Hex-encode the raw bytes into a printable token (32 hex characters).
    static constexpr char HexDigits[] = "0123456789ABCDEF";
    std::string TokenString;
    TokenString.reserve(RawToken.size() * 2);
    for (const unsigned char Byte : RawToken)
    {
        TokenString.push_back(HexDigits[Byte >> 4]);
        TokenString.push_back(HexDigits[Byte & 0x0F]);
    }

    // Make struct
    FPasswordResetStruct ResetStruct = { UserMail, TokenString };
    ResetStruct.TokenExpirationTime = std::chrono::system_clock::now() + std::chrono::minutes(TimeInMinsForTokenToBeAlive);

    // Mutex unique lock
    std::unique_lock<std::shared_mutex> Lock(TokenToStructureMapMutex);

    // Add token to map
    TokenToStructureMap[TokenString] = ResetStruct;

    return ResetStruct;
}

bool FPasswordResetManager::ValidateResetToken(const std::string& UserMail, const std::string& ResetToken)
{
    // Mutex shared lock
    std::shared_lock<std::shared_mutex> Lock(TokenToStructureMapMutex);

    const auto It = TokenToStructureMap.find(ResetToken);
    if (It == TokenToStructureMap.end() || It->second.UserMailForReset != UserMail)
    {
        return false;
    }

    if (It->second.TokenExpirationTime < std::chrono::system_clock::now())
    {
        return false;
    }

    return true;
}

bool FPasswordResetManager::UpdatePassword(const std::string& UserMail, const std::string& NewPassword)
{
    FProjectEngine* ProjectEngine = dynamic_cast<FProjectEngine*>(FGlobalDefines::GEngine);
    if (ProjectEngine != nullptr)
    {
        FUserManager* UserManager = ProjectEngine->GetUserManager();

        std::shared_ptr<FUser> User = UserManager->FindUserByMail(UserMail);

        if (User != nullptr)
        {
            const EUpdateUserPasswordStatus Result = UserManager->OverrideUserPassword(User->GetUserId(), NewPassword);

            return Result == EUpdateUserPasswordStatus::Successful;
        }
    }

    return false;
}

void FPasswordResetManager::InvalidateToken(const std::string& ResetToken)
{
    // Mutex unique lock
    std::unique_lock<std::shared_mutex> Lock(TokenToStructureMapMutex);

    TokenToStructureMap.erase(ResetToken);
}

void FPasswordResetManager::AsyncCleanupTokens()
{
    // Mutex unique lock
    std::unique_lock<std::shared_mutex> Lock(TokenToStructureMapMutex);

    // Iterate map to find and remove outdated tokens
    for (auto It = TokenToStructureMap.begin(); It != TokenToStructureMap.end();)
    {
        // Check if expired
        if (It->second.TokenExpirationTime < std::chrono::system_clock::now())
        {
            TokenToStructureMap.erase(It++);
            continue;
        }

        ++It;
    }
}
