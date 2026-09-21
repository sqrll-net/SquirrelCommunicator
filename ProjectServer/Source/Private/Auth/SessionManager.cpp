// Created by https://www.linkedin.com/in/przemek2122/ 2026

#include "Logger/Logger.h"
#include "Auth/SessionManager.h"

#include "SQRLLEncryption.h"
#include "ThreadCompat.h"

FUserSessionData::FUserSessionData()
	: UserId(0)
	, SessionTime(0)
{
}

FUserSessionData::FUserSessionData(const Uint64 InUserId, const Uint64 InSessionTime)
	: UserId(InUserId)
	, SessionTime(InSessionTime)
{
}

FUserSessionData::FUserSessionData(const FUserSessionData& UserSessionData)
	: UserId(UserSessionData.UserId)
	, SessionTime(UserSessionData.SessionTime)
{
}

FUserSessionData::FUserSessionData(FUserSessionData&& UserSessionData) noexcept
	: UserId(UserSessionData.UserId)
	, SessionTime(UserSessionData.SessionTime)
{
}

bool FUserSessionData::IsValid() const
{
	return (UserId != 0 && SessionTime != 0);
}

void FUserSessionData::SetSessionTimeLeft(const Uint64 InSessionTime)
{
	std::unique_lock MutexScopeLock(SessionUpdateMutex);

	SessionTime = InSessionTime;
}

Uint64 FUserSessionData::GetSessionTime() const
{
	return SessionTime;
}

FSessionManager::FSessionManager(const Uint64 InSessionExpirationTime)
	: AsyncWorkLastTime(0)
	, CurrentTimeCached(0)
	, SessionExpirationTime(InSessionExpirationTime)
{
}

void FSessionManager::Init()
{
	CurrentTimeCached = FUtil::GetSeconds();

	WorkerThread = std::jthread([this](std::stop_token stoken)
	{
		constexpr Uint64 TimeBetweenRuns = 3 * 60; // Time in seconds

		while (!stoken.stop_requested())
		{
			const Uint64 CurrentTime = CurrentTimeCached;

			if (AsyncWorkLastTime + TimeBetweenRuns <= CurrentTime)
			{
				AsyncWorkLastTime = CurrentTime;
				AsyncCheckForDeadSessions();
			}

			// Sleep 1 second between checks — no busy-wait
			std::this_thread::sleep_for(std::chrono::seconds(1));
		}
	});
}

void FSessionManager::PostSecondTick()
{
	CurrentTimeCached = FUtil::GetSeconds();
}

void FSessionManager::AsyncCheckForDeadSessions()
{
	// @TODO: In future it would be smart to implement priority_queue as it would be O(1)

	std::vector<std::string> SessionIds;

	// Make copy
	{
		std::shared_lock ReadLock(SessionIdToUserIdMapMutex);

		SessionIds.reserve(SessionIdToUserIdMap.Size());

		for (std::pair<const std::string, FUserSessionData>& Session : SessionIdToUserIdMap)
		{
			SessionIds.push_back(Session.first);
		}
	}

	for (const std::string& SessionId : SessionIds)
	{
		if (!IsSessionTokenAlive(SessionId))
		{
			DeactivateSession(SessionId);
		}
	}
}

std::string FSessionManager::CreateSession(const Uint64 InUserId)
{
	const std::string SessionToken = CreateTokenFromId(InUserId);
	FUserSessionData UserSessionData(InUserId, CurrentTimeCached + SessionExpirationTime);

	std::lock_guard<std::shared_mutex> MutexScopeLock(SessionIdToUserIdMapMutex);
	SessionIdToUserIdMap.Emplace(SessionToken, UserSessionData);
	UserIdToSessionTokenMap[InUserId].insert(SessionToken);

	return SessionToken;
}

Uint64 FSessionManager::GetUserIdFromSessionId(const std::string& InSessionToken)
{
	Uint64 OutId = 0;

	if (IsSessionTokenAlive(InSessionToken))
	{
		std::shared_lock<std::shared_mutex> ReadLock(SessionIdToUserIdMapMutex);

		FUserSessionData SessionData = SessionIdToUserIdMap[InSessionToken];

		OutId = SessionData.UserId;
	}

	return OutId;
}

bool FSessionManager::RefreshSessionToken(const std::string& InSessionToken)
{
	bool bIsAlive = false;

	if (IsSessionTokenAlive(InSessionToken))
	{
		std::lock_guard<std::shared_mutex> MutexScopeLock(SessionIdToUserIdMapMutex);
		FUserSessionData& SessionData = SessionIdToUserIdMap[InSessionToken];
		SessionData.SetSessionTimeLeft(CurrentTimeCached + SessionExpirationTime);

		bIsAlive = true;
	}

	return bIsAlive;
}

bool FSessionManager::DoesUserHaveSession(const Uint64 InUserId)
{
	std::shared_lock<std::shared_mutex> ReadLock(SessionIdToUserIdMapMutex);

	const auto Iter = UserIdToSessionTokenMap.find(InUserId);
	return (Iter != UserIdToSessionTokenMap.end() && !Iter->second.empty());
}

bool FSessionManager::DeactivateSession(const std::string& InSessionToken)
{
	Uint64 UserId = 0;
	bool bDeactivatedSession = false;

	{
		std::unique_lock<std::shared_mutex> WriteLock(SessionIdToUserIdMapMutex);

		const auto SessionIter = SessionIdToUserIdMap.find(InSessionToken);
		if (SessionIter != SessionIdToUserIdMap.end())
		{
			UserId = SessionIter->second.UserId;
			SessionIdToUserIdMap.erase(SessionIter);

			const auto UserSessionsIter = UserIdToSessionTokenMap.find(UserId);
			if (UserSessionsIter != UserIdToSessionTokenMap.end())
			{
				UserSessionsIter->second.erase(InSessionToken);
				if (UserSessionsIter->second.empty())
				{
					UserIdToSessionTokenMap.erase(UserSessionsIter);
				}
			}

			bDeactivatedSession = true;
		}
	}

	// Notify after releasing the lock to avoid re-entrancy/deadlock.
	if (bDeactivatedSession && OnSessionDeactivatedCallback)
	{
		OnSessionDeactivatedCallback(InSessionToken);
	}

	return bDeactivatedSession;
}

void FSessionManager::DeactivateAllSessionsForUser(const Uint64 InUserId)
{
	// Security: called after a password change/reset. Without this, an attacker
	// who holds a session token obtained before the credential change would keep
	// a valid session indefinitely. Revoke every session so the user is forced
	// to re-authenticate with the new credential on all devices.
	std::vector<std::string> SessionTokens;

	{
		std::unique_lock<std::shared_mutex> WriteLock(SessionIdToUserIdMapMutex);

		const auto UserSessionsIter = UserIdToSessionTokenMap.find(InUserId);
		if (UserSessionsIter != UserIdToSessionTokenMap.end())
		{
			SessionTokens.assign(UserSessionsIter->second.begin(), UserSessionsIter->second.end());

			// Remove each token from the primary token->session map.
			for (const std::string& SessionToken : SessionTokens)
			{
				SessionIdToUserIdMap.erase(SessionToken);
			}

			// Remove the user->tokens entry entirely.
			UserIdToSessionTokenMap.erase(UserSessionsIter);
		}
	}

	// Notify AFTER releasing the lock to avoid re-entrancy/deadlock. The
	// callback revokes the per-session image service key for each token.
	if (OnSessionDeactivatedCallback)
	{
		for (const std::string& SessionToken : SessionTokens)
		{
			OnSessionDeactivatedCallback(SessionToken);
		}
	}
}

bool FSessionManager::IsSessionTokenAlive(const std::string& InSessionToken)
{
	bool bIsSessionTokenAlive = false;

	std::shared_lock ReadLock(SessionIdToUserIdMapMutex);

	if (SessionIdToUserIdMap.ContainsKey(InSessionToken))
	{
		const std::optional<FUserSessionData> UserSessionData = SessionIdToUserIdMap.FindValueByKey(InSessionToken);
		if (UserSessionData.has_value())
		{
			const Uint64 CurrentSessionExpirationTime = UserSessionData->GetSessionTime();
			bIsSessionTokenAlive = CurrentTimeCached < CurrentSessionExpirationTime;
		}
	}

	return bIsSessionTokenAlive;
}

void FSessionManager::SetOnSessionDeactivatedCallback(std::function<void(const std::string&)> InCallback)
{
	OnSessionDeactivatedCallback = std::move(InCallback);
}

std::string FSessionManager::CreateTokenFromId(const Uint64 InUserId) const
{
	// Bit-flip input ID - Does not need to be safe, user knows his Id anyway
	static constexpr uint64_t SessionFlipMask = 0x9E3779B97F4A7C15ULL;
	const Uint64 FlippedNumber = FBitFlipping::FlipBits(InUserId, SessionFlipMask);

	// Prepare buffer with exact capacity: salt (32) + flipped ID (8) + salt (32)
	std::string RawPayload;
	RawPayload.reserve(32 + sizeof(Uint64) + 32);

	// Append salt 1, flipped ID bytes, salt 2
	RawPayload.append(FEncryptionUtil::GenerateSecureSalt(32));
	RawPayload.append(reinterpret_cast<const char*>(&FlippedNumber), sizeof(FlippedNumber));
	RawPayload.append(FEncryptionUtil::GenerateSecureSalt(32));

	// Encrypt & Encode
	return FEncryptionUtil::ToBaseN_Irreversible(RawPayload, FPredefinedCharsets::BASE62);
}
