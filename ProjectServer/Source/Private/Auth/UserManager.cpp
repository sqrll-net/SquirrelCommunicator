// Created by https://www.linkedin.com/in/przemek2122/ 2026

#include "Logger/Logger.h"
#include "Auth/UserManager.h"
#include "Managers/ImageServiceManager.h"

#include <nlohmann/json.hpp>

#include "DataBase/DataBaseConnect.h"
#include "Encryption/EncryptionCompat.h"
#include "SQRLLEncryption.h"
#include "WebUtils/StringHelpers.h"

namespace
{
	// Whitelist for user-chosen usernames (registration and change_name).
	// Deliberately narrow: letters, digits, space and a few common separators.
	// This blocks control characters and HTML/JSON-significant characters
	// (<, >, ", ', /, \, etc.), which are the usual stored-XSS vectors when a
	// name is rendered by a client. Non-ASCII is intentionally excluded
	constexpr std::string_view USERNAME_ALLOWED_CHARSET =
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ._-";

	// Strips C0 control bytes (0x00-0x1F), the DEL byte (0x7F) and C1 control
	// bytes (0x80-0x9F). Used for OAuth-provided display names (Google/Microsoft)
	// which may legitimately contain non-ASCII characters (e.g. accented or non-Latin names)
	// but must never contain control bytes that could break a client renderer.
	std::string StripControlCharacters(const std::string& InName)
	{
		std::string Out;
		Out.reserve(InName.size());
		for (const unsigned char Ch : InName)
		{
			if (Ch >= 0x20 && Ch != 0x7F && (Ch < 0x80 || Ch > 0x9F))
			{
				Out.push_back(static_cast<char>(Ch));
			}
		}
		return Out;
	}
}

FUserManager::FUserManager(Uint64 InSessionExpirationTime)
	: NextAvailableIndex(0)
	, CurrentTimeCached(0)
{
	SessionManager = std::make_unique<FSessionManager>(InSessionExpirationTime);
}

FUserManager::~FUserManager()
{
}

void FUserManager::Init()
{
	CachedArgonSettings = GetArgonSettings();

	// Image service: issues/revokes a per-session upload key on login/logout.
	ImageServiceManager = std::make_unique<FImageServiceManager>();

	// When a session dies (explicit logout OR natural expiry), withdraw its key.
	SessionManager->SetOnSessionDeactivatedCallback([this](const std::string& SessionToken)
	{
		if (ImageServiceManager)
		{
			ImageServiceManager->RevokeKey(SessionToken);
		}
	});

	SessionManager->Init();
}

void FUserManager::PostSecondTick()
{
	CurrentTimeCached = FUtil::GetSeconds();

	SessionManager->PostSecondTick();
}

ERegisterUserStatus FUserManager::RegisterUser(const std::string& InUserName, const std::string& InUserPassword, const std::string& InUserEMail)
{
	std::string OutPasswordHash;
	ERegisterUserStatus RegisterUserStatus = PrepareRegistration(InUserName, InUserPassword, InUserEMail, OutPasswordHash);

	if (RegisterUserStatus == ERegisterUserStatus::Unknown)
	{
		RegisterUserStatus = CompleteRegistration(InUserName, OutPasswordHash, InUserEMail);
	}

	return RegisterUserStatus;
}

ERegisterUserStatus FUserManager::PrepareRegistration(const std::string& InUserName, const std::string& InUserPassword, const std::string& InUserEMail, std::string& OutPasswordHash)
{
	ERegisterUserStatus RegisterUserStatus = ERegisterUserStatus::Unknown;

	// Check password
	if (!ValidatePasswordLength(InUserPassword))
	{
		RegisterUserStatus = ERegisterUserStatus::PasswordLengthIncorrect;
	}

	// Check mail
	if (!ValidateEMailLength(InUserEMail))
	{
		RegisterUserStatus = ERegisterUserStatus::MailLengthIncorrect;
	}

	// Check User name (length + allowed character set)
	if (!ValidateUserName(InUserName))
	{
		RegisterUserStatus = ERegisterUserStatus::UserNameLengthIncorrect;
	}

	// Check mail format
	if (!FStringHelpers::ValidateMail(InUserEMail))
	{
		RegisterUserStatus = ERegisterUserStatus::MailIncorrect;
	}

	if (RegisterUserStatus == ERegisterUserStatus::Unknown)
	{
		OutPasswordHash = HashUserPassword(InUserPassword);
	}

	return RegisterUserStatus;
}

ERegisterUserStatus FUserManager::CompleteRegistration(const std::string& InUserName, const std::string& InUserPasswordHash, const std::string& InUserEMail)
{
	ERegisterUserStatus RegisterUserStatus = ERegisterUserStatus::Unknown;

	// Check if mail is taken
	bool bUserExists = false;
	const EDatabaseOperationResult DBOpResult = DoesUserWithMailExists(InUserEMail, bUserExists);

	if (DBOpResult == EDatabaseOperationResult::Success && !bUserExists)
	{
		Uint64 Id = 0;
		UploadUserToDataBase(InUserName, InUserPasswordHash, InUserEMail, Id);

		if (Id > 0)
		{
			const std::shared_ptr<FUser> UserPtr = std::make_shared<FUser>(this);
			FUser* User = UserPtr.get();
			User->SetUserName(InUserName);
			User->SetPassword(InUserPasswordHash);
			User->SetUserEMail(InUserEMail);
			User->SetUserId(Id);
			User->UpdateLastActiveTime();

			OnRegisterSuccessful(UserPtr);

			RegisterUserStatus = ERegisterUserStatus::Successful;
		}
		else
		{
			RegisterUserStatus = ERegisterUserStatus::DataBaseInsertFailed;
		}
	}
	else if (DBOpResult != EDatabaseOperationResult::Success)
	{
		RegisterUserStatus = ERegisterUserStatus::DataBaseConnectionFailed;
	}
	else
	{
		RegisterUserStatus = ERegisterUserStatus::MailTaken;
	}

	return RegisterUserStatus;
}

ERegisterUserStatus FUserManager::RegisterIntegration(const std::string& InUserName, const std::string& InUserEMail)
{
	ERegisterUserStatus RegisterUserStatus = ERegisterUserStatus::Unknown;

	// Check mail
	if (!ValidateEMailLength(InUserEMail))
	{
		RegisterUserStatus = ERegisterUserStatus::MailLengthIncorrect;
	}

	// Check User name
	if (!ValidateUserNameLength(InUserName))
	{
		RegisterUserStatus = ERegisterUserStatus::UserNameLengthIncorrect;
	}

	if (RegisterUserStatus == ERegisterUserStatus::Unknown)
	{
		bool bUserExists;
		EDatabaseOperationResult CheckOpResult = DoesUserWithMailExists(InUserEMail, bUserExists);
		if (CheckOpResult == EDatabaseOperationResult::Success && !bUserExists)
		{
			// SECURITY: OAuth display names can contain Unicode and are not subject
			// to the strict username whitelist, but they must never contain control
			// characters. Strip them before persisting.
			const std::string SanitizedUserName = StripControlCharacters(InUserName);

			// SECURITY (defense-in-depth): an integration account must never
			// authenticate with a password. Storing an empty hash would let a
			// hypothetical password-login path trivially match an empty input.
			// Instead, hash a random secret so the stored value can never be
			// verified against any real password.
			const std::string UnusablePasswordHash = HashUserPassword(FEncryptionUtil::GenerateSecureSalt(32));

			const std::shared_ptr<FUser> UserPtr = std::make_shared<FUser>(this);
			FUser* User = UserPtr.get();
			User->SetUserName(SanitizedUserName);
			User->SetPassword(UnusablePasswordHash);
			User->SetUserEMail(InUserEMail);
			User->UpdateLastActiveTime();

			Uint64 Id = 0;
			EDatabaseOperationResult UploadOpResult = UploadUserToDataBase(SanitizedUserName, UnusablePasswordHash, InUserEMail, Id);
			if (UploadOpResult == EDatabaseOperationResult::Success && Id > 0)
			{
				User->SetUserId(Id);
				OnRegisterSuccessful(UserPtr);

				RegisterUserStatus = ERegisterUserStatus::Successful;
			}
			else
			{
				RegisterUserStatus = ERegisterUserStatus::DataBaseInsertFailed;
			}
		}
		else if (CheckOpResult != EDatabaseOperationResult::Success)
		{
			RegisterUserStatus = ERegisterUserStatus::DataBaseConnectionFailed;
		}
		else if (bUserExists)
		{
			RegisterUserStatus = ERegisterUserStatus::MailTaken;
		}
	}

	return RegisterUserStatus;
}

ELoginStatus FUserManager::LoginUser(const std::string& InUserEmail, const std::string& InUserPassword, std::string& OutSessionToken)
{
	ELoginStatus LoginStatus = ELoginStatus::IncorrectCredentialsOrUserDoesNotExist;

	// Basic email check
	if (!ValidateEMailLength(InUserEmail))
	{
		return ELoginStatus::IncorrectInputLength;
	}

	// Basic password check
	if (!ValidatePasswordLength(InUserPassword))
	{
		return ELoginStatus::IncorrectInputLength;
	}

	std::shared_ptr<FUser> UserPtr = nullptr;
	bool bWereDownloadedFromDB = false;

	{
		const std::shared_lock ScopeLock(UserDataBaseMutex);
		for (const std::pair<const Uint64, std::shared_ptr<FUser>>& UserPair : UserDataBaseCache)
		{
			if (UserPair.second->IsUserMailCorrect(InUserEmail))
			{
				UserPtr = UserPair.second;
			}
		}
	}

	// User missing check db
	if (UserPtr == nullptr)
	{
		const EDatabaseOperationResult Result = DownloadUserFromDBByMail(InUserEmail, UserPtr);
		if (Result == EDatabaseOperationResult::Success)
		{
			bWereDownloadedFromDB = true;
		}
	}

	if (UserPtr != nullptr)
	{
		// @TODO: Should we support BAN?

		if (VerifyPasswords(UserPtr->GetUserPasswordHash(), InUserPassword))
		{
			const Uint64 Id = UserPtr->GetUserId();

			UpdateUserActivity(Id);

			OnLoginSuccessful(UserPtr, bWereDownloadedFromDB);

			OutSessionToken = SessionManager->CreateSession(Id);

			// Best effort: issue a per-session image API key (delivered to the client over the WebSocket).
			if (ImageServiceManager)
			{
				ImageServiceManager->RegisterKey(OutSessionToken);
			}

			LoginStatus = ELoginStatus::Successful;
		}
	}

	return LoginStatus;
}

ELoginStatus FUserManager::LoginIntegration(const std::string& InUserEmail, std::string& OutSessionToken)
{
	ELoginStatus LoginStatus = ELoginStatus::IncorrectCredentialsOrUserDoesNotExist;

	// Basic email check
	if (!ValidateEMailLength(InUserEmail))
	{
		return ELoginStatus::IncorrectInputLength;
	}

	bool bHasEMail;
	Uint64 Id = 0;
	{
		// Shared Lock for map
		const std::shared_lock<std::shared_mutex> UserMailMapMutexScopeLock(UserMailMapMutex);
		bHasEMail = UserMailToUserIdMap.ContainsKey(InUserEmail);
		if (bHasEMail)
		{
			Id = UserMailToUserIdMap[InUserEmail];
		}
	}

	if (bHasEMail)
	{
		std::shared_ptr<FUser> UserPtr;
		{
			// Shared Lock for map
			const std::shared_lock<std::shared_mutex> UserDataBaseMutexScopeLock(UserDataBaseMutex);
			UserPtr = UserDataBaseCache[Id];
		}

		OnLoginSuccessful(UserPtr, false);

		OutSessionToken = SessionManager->CreateSession(Id);

		if (ImageServiceManager)
		{
			ImageServiceManager->RegisterKey(OutSessionToken);
		}

		LoginStatus = ELoginStatus::Successful;
	}

	return LoginStatus;
}

ELoginStatus FUserManager::LoginFromId(const Uint64 Id, std::string& OutSessionToken)
{
	ELoginStatus LoginStatus = ELoginStatus::IncorrectCredentialsOrUserDoesNotExist;

	// SECURITY: GetUserById() returns nullptr when the ID does not resolve to a
	// user (e.g. a transfer token referencing a since-deleted account). The
	// previous code called UserPtr->IsValid() unconditionally, dereferencing a
	// null shared_ptr and crashing the server (a remote-triggerable DoS).
	const std::shared_ptr<FUser> UserPtr = GetUserById(Id);
	if (UserPtr != nullptr && UserPtr->IsValid())
	{
		OnLoginSuccessful(UserPtr, false);

		OutSessionToken = SessionManager->CreateSession(Id);

		if (ImageServiceManager)
		{
			ImageServiceManager->RegisterKey(OutSessionToken);
		}

		LoginStatus = ELoginStatus::Successful;
	}
	else
	{
		LOG_DEBUG("User with ID: " << Id << " does not exist or is invalid");
	}

	return LoginStatus;
}

bool FUserManager::Logout(const std::string& InSessionToken)
{
	return SessionManager->DeactivateSession(InSessionToken);
}

void FUserManager::InvalidateAllSessionsForUser(const Uint64 InUserId)
{
	SessionManager->DeactivateAllSessionsForUser(InUserId);
}

bool FUserManager::VerifyToken(const std::string& InToken) const
{
	const Uint64 Id = SessionManager->GetUserIdFromSessionId(InToken);
	return (Id > 0);
}

bool FUserManager::RefreshSessionToken(const std::string& InToken) const
{
	return SessionManager->IsSessionTokenAlive(InToken);
}

void FUserManager::UpdateUserActivity(const Uint64 UsedId)
{
	try
	{
		FDataBaseConnect Connect;
		if (Connect.IsConnected())
		{
			// Get database connection session
			soci::session& DataBaseSession = Connect.GetSession();

			// Update activity time
			DataBaseSession << "UPDATE users SET LastActive = NOW() WHERE id = :id",
				soci::use(UsedId, "id");

			// Update cache
			std::vector<std::shared_ptr<FUser>> Users;
			const bool bGetUsers = GetUsersByIds({ UsedId }, Users);
			if (bGetUsers)
			{
				std::shared_ptr<FUser>& FirstUser = Users[0];
				FirstUser->UpdateLastActiveTime();
			}
		}
	}
	catch (const std::exception& e)
	{
		LOG_ERROR("Database error: " << e.what());
	}
}

EUpdateUserNameStatus FUserManager::UpdateUserName(const Uint64 UsedId, const std::string& NewUserName)
{
	if (!ValidateUserNameLength(NewUserName))
	{
		return EUpdateUserNameStatus::UserNameLengthIncorrect;
	}

	// SECURITY: usernames (display names) are echoed to every other client, so
	// they must be constrained to a safe character set. The length check alone
	// still allowed control characters, HTML brackets, quotes, etc. - all
	// stored-XSS / control-injection vectors if a client renders a name without
	// escaping.
	if (!FStringHelpers::ValidateString(NewUserName, USERNAME_ALLOWED_CHARSET))
	{
		return EUpdateUserNameStatus::UserNameIncorrect;
	}

	EUpdateUserNameStatus OutStatus = EUpdateUserNameStatus::Unknown;

	try
	{
		FDataBaseConnect Connect;
		if (Connect.IsConnected())
		{
			// Get database connection session
			soci::session& DataBaseSession = Connect.GetSession();

			// Update activity time
			DataBaseSession << "UPDATE users SET UserName = :username WHERE id = :id",
				soci::use(UsedId, "id"),
				soci::use(NewUserName, "username");

			// Update cache
			std::vector<std::shared_ptr<FUser>> Users;
			const bool bGetUsers = GetUsersByIds({ UsedId }, Users);
			if (bGetUsers)
			{
				const std::shared_ptr<FUser>& FirstUser = Users[0];
				FirstUser->SetUserName(NewUserName);

				OutStatus = EUpdateUserNameStatus::Successful;
			}
		}
	}
	catch (const std::exception& e)
	{
		LOG_ERROR("Database error: " << e.what());
	}

	return OutStatus;
}

EUpdateUserPasswordStatus FUserManager::UpdateUserPassword(const Uint64 InUserId, const std::string& OldPassword, const std::string& NewPassword)
{
	if (OldPassword.empty() || !ValidatePasswordLength(NewPassword))
	{
		return EUpdateUserPasswordStatus::PasswordLengthIncorrect;
	}

	if (!FStringHelpers::ValidateString(NewPassword, FPredefinedCharsets::BASE_SIMPLE_PASSWORD))
	{
		return EUpdateUserPasswordStatus::PasswordIncorrect;
	}

	const EUpdateUserPasswordStatus OutStatus = EUpdateUserPasswordStatus::Successful;
	const std::string UserPasswordHash = HashUserPassword(NewPassword);

	const std::shared_ptr<FUser> UserPtr = GetUserById(InUserId);
	if (UserPtr == nullptr)
	{
		return EUpdateUserPasswordStatus::UserNotFound;
	}

	if (!VerifyPasswords(UserPtr->GetUserPasswordHash(), OldPassword))
	{
		return EUpdateUserPasswordStatus::OldPasswordIncorrect;
	}

	UpdateUserPasswordInDataBase(InUserId, UserPasswordHash);

	// Password change must invalidate every existing session for
	// this user. Otherwise an attacker who logged in before the change keeps a
	// valid session even after the victim resets their credential.
	InvalidateAllSessionsForUser(InUserId);

	return OutStatus;
}

EUpdateUserPasswordStatus FUserManager::OverrideUserPassword(Uint64 InUserId, const std::string& NewPassword)
{
	if (!ValidatePasswordLength(NewPassword))
	{
		return EUpdateUserPasswordStatus::PasswordLengthIncorrect;
	}

	if (!FStringHelpers::ValidateString(NewPassword, FPredefinedCharsets::BASE_SIMPLE_PASSWORD))
	{
		return EUpdateUserPasswordStatus::PasswordIncorrect;
	}

	EUpdateUserPasswordStatus OutStatus = EUpdateUserPasswordStatus::Successful;
	const std::string UserPasswordHash = HashUserPassword(NewPassword);

	const EDatabaseOperationResult DatabaseOpResult = UpdateUserPasswordInDataBase(InUserId, UserPasswordHash);
	if (DatabaseOpResult != EDatabaseOperationResult::Success)
	{
		OutStatus = EUpdateUserPasswordStatus::Unknown;
	}
	else
	{
		// SECURITY: a password reset must invalidate every existing session for
		// this user (e.g. sessions held by an attacker before the compromise).
		InvalidateAllSessionsForUser(InUserId);
	}

	return OutStatus;
}

std::shared_ptr<FUser> FUserManager::FindUserByMail(const std::string& InMail)
{
	std::shared_ptr<FUser> Out;
	std::optional<Uint64> TargetUserId;

	// Thread-safe lookup in Mail -> ID map
	{
		const std::shared_lock<std::shared_mutex> MailLock(UserMailMapMutex);
		// Assuming custom container method returning pointer or std::optional
		if (std::optional<unsigned long> OptionalId = UserMailToUserIdMap.FindValueByKey(InMail))
		{
			if (OptionalId.has_value())
			{
				TargetUserId = OptionalId.value();
			}
		}
	}

	// Thread-safe lookup in ID -> User cache
	if (TargetUserId.has_value())
	{
		const std::shared_lock<std::shared_mutex> CacheLock(UserDataBaseMutex);
		const std::optional<std::shared_ptr<FUser>> CacheIter = UserDataBaseCache.FindValueByKey(TargetUserId.value());
		if (CacheIter.has_value())
		{
			Out = CacheIter.value();
		}
	}

	// Fallback to DB query if not present in cache/map
	if (!Out)
	{
		bool bExists = false;
		const EDatabaseOperationResult CheckOpResult = DoesUserWithMailExists(InMail, bExists);
		if (CheckOpResult == EDatabaseOperationResult::Success && bExists)
		{
			DownloadUserFromDBByMail(InMail, Out);
			if (Out)
			{
				AddUserToCache(Out);
			}
		}
	}

	return Out;
}

Uint64 FUserManager::GetIdFromToken(const std::string& InToken) const
{
	const Uint64 Id = SessionManager->GetUserIdFromSessionId(InToken);
	return Id;
}

bool FUserManager::GetUsersByIds(const std::vector<Uint64>& UserIds, std::vector<std::shared_ptr<FUser>>& OutUsers)
{
	return (DownloadUsersFromDBByIds(UserIds, OutUsers, true) == EDatabaseOperationResult::Success);
}

std::shared_ptr<FUser> FUserManager::GetUserById(Uint64 InUserId)
{
	std::vector<std::shared_ptr<FUser>> OutUsers;
	const bool bHasUser = GetUsersByIds({ InUserId }, OutUsers);

	if (bHasUser && !OutUsers.empty())
	{
		return OutUsers[0];
	}

	return nullptr;
}

EDatabaseOperationResult FUserManager::DownloadUserFromDBByMail(const std::string& InUserEmail, std::shared_ptr<FUser>& UserPtr)
{
	EDatabaseOperationResult DownloadResult = EDatabaseOperationResult::Unknown;

	try
	{
		FDataBaseConnect Connect;
		if (Connect.IsConnected())
		{
			// Get database connection session
			soci::session& DataBaseSession = Connect.GetSession();

			try
			{
				// Get user data and hashed password
				std::string Username;
				std::string StoredPasswordHash;
				std::string Mail;
				Uint64 UserId;
				soci::indicator Ind;

				DataBaseSession << "SELECT id, username, password, email FROM users WHERE email = :email",
					soci::use(InUserEmail),
					soci::into(UserId, Ind),
					soci::into(Username),
					soci::into(StoredPasswordHash),
					soci::into(Mail);

				if (Ind == soci::i_ok)
				{
					UserPtr = std::make_shared<FUser>(this);
					FUser* User = UserPtr.get();
					User->SetUserName(Username);
					User->SetPassword(StoredPasswordHash);
					User->SetUserEMail(Mail);
					User->SetUserId(UserId);

					DownloadResult = EDatabaseOperationResult::Success;
				}
				else
				{
					DownloadResult = EDatabaseOperationResult::DataNotFound;
				}
			}
			catch (const std::exception& e)
			{
				LOG_ERROR("Database error: " << e.what());

				DownloadResult = EDatabaseOperationResult::DatabaseFailed;
			}
		}
		else
		{
			DownloadResult = EDatabaseOperationResult::ConnectionFailed;
		}
	}
	catch (const std::exception& e)
	{
		LOG_ERROR("Database error: " << e.what());
	}

	return DownloadResult;
}

EDatabaseOperationResult FUserManager::DownloadUsersFromDBByIds(const std::vector<Uint64>& UserIds, std::vector<std::shared_ptr<FUser>>& OutUsers, const bool bAutoAddToCache)
{
	if (UserIds.empty())
	{
		return EDatabaseOperationResult::DataNotFound;
	}

	// 1. Prepare containers
	OutUsers.clear();
	OutUsers.reserve(UserIds.size());

	std::vector<Uint64> MissingIds;
	MissingIds.reserve(UserIds.size());

	// 2. CACHE PASS: Check what we already have
	for (Uint64 TargetId : UserIds)
	{
		const std::shared_lock ScopeLock(UserDataBaseMutex);
		std::optional<std::shared_ptr<FUser>> ExistingUserCache = UserDataBaseCache.FindValueByKey(TargetId);

		if (ExistingUserCache.has_value())
		{
			OutUsers.push_back(ExistingUserCache.value());
		}
		else
		{
			MissingIds.push_back(TargetId);
		}
	}

	// If we found everyone in the cache, we are done!
	if (MissingIds.empty())
	{
		return EDatabaseOperationResult::Success;
	}

	EDatabaseOperationResult DownloadResult = EDatabaseOperationResult::Unknown;
	try
	{
		// 3. DATABASE PASS: Download only missing IDs
		FDataBaseConnect Connect;

		if (Connect.IsConnected())
		{
			soci::session& DataBaseSession = Connect.GetSession();

			try
			{
				// Build string for SQL "IN" clause: "1, 5, 99"
				std::string IdList;
				for (size_t i = 0; i < MissingIds.size(); ++i) {
					IdList += std::to_string(MissingIds[i]);
					if (i < MissingIds.size() - 1) IdList += ",";
				}

				// Prepare fetch variables
				std::string Username, StoredPasswordHash, Mail;
				Uint64 UserIdVal;
				soci::indicator Ind;

				// Execute Single Query
				soci::statement St = (DataBaseSession.prepare <<
					"SELECT id, username, password, email FROM users WHERE id IN (" + IdList + ")",
					soci::into(UserIdVal, Ind),
					soci::into(Username),
					soci::into(StoredPasswordHash),
					soci::into(Mail)
				);

				St.execute();

				while (St.fetch())
				{
					if (Ind == soci::i_ok)
					{
						// Create User
						std::shared_ptr<FUser> NewUser = std::make_shared<FUser>(this);
						NewUser->SetUserName(Username);
						NewUser->SetPassword(StoredPasswordHash);
						NewUser->SetUserEMail(Mail);
						NewUser->SetUserId(UserIdVal);

						// Update CACHE
						if (bAutoAddToCache)
						{
							const std::unique_lock ScopeLock(UserDataBaseMutex);
							UserDataBaseCache.Emplace(UserIdVal, NewUser);
						}

						// Add to Output
						OutUsers.push_back(NewUser);
					}
				}

				// If we have any users (from cache OR db), consider it a success
				DownloadResult = (OutUsers.empty()) ? EDatabaseOperationResult::DataNotFound : EDatabaseOperationResult::Success;
			}
			catch (const std::exception& e)
			{
				LOG_ERROR("Database error (Bulk User Resolve): " << e.what());
				DownloadResult = EDatabaseOperationResult::DatabaseFailed;
			}
		}
		else
		{
			DownloadResult = EDatabaseOperationResult::ConnectionFailed;
		}
	}
	catch (const std::exception& e)
	{
		LOG_ERROR("Database error: " << e.what());
	}

	return DownloadResult;
}

EDatabaseOperationResult FUserManager::UploadUserToDataBase(const std::string& InUserName, const std::string& InUserPasswordHash, const std::string& InUserEMail, Uint64& OutId)
{
	EDatabaseOperationResult DatabaseOperationResult = EDatabaseOperationResult::Unknown;

	try
	{
		FDataBaseConnect Connect;
		if (Connect.IsConnected())
		{
			// Get database connection session
			soci::session& DataBaseSession = Connect.GetSession();

			// Create user
			DataBaseSession.once << "INSERT INTO users(username, password, email) VALUES(:un, :ps, :em)",
				soci::use(InUserName, "un"),
				soci::use(InUserPasswordHash, "ps"),
				soci::use(InUserEMail, "em");

			// Get id
			Uint64 Id = 0;
			DataBaseSession.once << "SELECT LAST_INSERT_ID()",
				soci::into(Id);

			OutId = Id;

			DatabaseOperationResult = EDatabaseOperationResult::Success;
		}
		else
		{
			DatabaseOperationResult = EDatabaseOperationResult::ConnectionFailed;
		}
	}
	catch (const std::exception& e)
	{
		LOG_ERROR("Database error: " << e.what());
	}

	return DatabaseOperationResult;
}

EDatabaseOperationResult FUserManager::UpdateUserPasswordInDataBase(Uint64 InUserId, const std::string& InUserPasswordHash)
{
	EDatabaseOperationResult DataBaseOperationResult = EDatabaseOperationResult::Unknown;

	try
	{
		FDataBaseConnect Connect;
		if (Connect.IsConnected())
		{
			// Get database connection session
			soci::session& DataBaseSession = Connect.GetSession();

			// Update activity time
			DataBaseSession << "UPDATE users SET password = :password WHERE id = :id",
				soci::use(InUserId, "id"),
				soci::use(InUserPasswordHash, "password");

			// Update cache
			std::vector<std::shared_ptr<FUser>> Users;
			const bool bGetUsers = GetUsersByIds({ InUserId }, Users);
			if (bGetUsers)
			{
				const std::shared_ptr<FUser>& FirstUser = Users[0];
				FirstUser->SetPassword(InUserPasswordHash);

				DataBaseOperationResult = EDatabaseOperationResult::Success;
			}
		}
		else
		{
			DataBaseOperationResult = EDatabaseOperationResult::ConnectionFailed;
		}
	}
	catch (const std::exception& e)
	{
		LOG_ERROR("Database error: " << e.what());
		DataBaseOperationResult = EDatabaseOperationResult::DatabaseFailed;
	}

	return DataBaseOperationResult;
}

EDatabaseOperationResult FUserManager::DoesUserWithMailExists(const std::string& InUserEmail, bool& bOutExists)
{
	EDatabaseOperationResult DownloadResult = EDatabaseOperationResult::Unknown;
	bOutExists = false;

	try
	{
		FDataBaseConnect Connect;
		if (Connect.IsConnected())
		{
			soci::session& DataBaseSession = Connect.GetSession();

			try
			{
				std::string Username;
				soci::indicator Ind;

				DataBaseSession << "SELECT username FROM users WHERE email = :email",
					soci::use(InUserEmail),
					soci::into(Username, Ind);

				if (Ind == soci::i_ok)
				{
					bOutExists = true;
				}

				DownloadResult = EDatabaseOperationResult::Success;
			}
			catch (const std::exception& e)
			{
				LOG_ERROR("Database error: " << e.what());
				DownloadResult = EDatabaseOperationResult::DatabaseFailed;
			}
		}
		else
		{
			DownloadResult = EDatabaseOperationResult::ConnectionFailed;
		}
	}
	catch (const std::exception& e)
	{
		LOG_ERROR("Database error: " << e.what());
	}

	return DownloadResult;
}

Uint64 FUserManager::GenerateNextAvailableId()
{
	NextAvailableIndex++;

	const std::shared_lock ScopeLock(UserDataBaseMutex);
	if (UserDataBaseCache.ContainsKey(NextAvailableIndex))
	{
		LOG_ERROR("Critical error, NextAvailableIndex already exist and should not!");

		// Find first available index
		while (UserDataBaseCache.ContainsKey(NextAvailableIndex))
		{
			NextAvailableIndex++;
		}
	}

	return NextAvailableIndex;
}

bool FUserManager::VerifyPasswords(const std::string& StringWithHash, const std::string& StringWithoutHash)
{
	const std::unique_ptr<FPasswordEncryptionArgon> Encryptor = FEncryptionManager::CreateEncryptorForPassword<FPasswordEncryptionArgon>();
	return Encryptor->VerifyPassword(StringWithHash, StringWithoutHash);
}

std::string FUserManager::HashUserPassword(const std::string& RawPassword)
{
	const std::unique_ptr<FPasswordEncryptionArgon> Encryptor = FEncryptionManager::CreateEncryptorForPassword<FPasswordEncryptionArgon>();
	return Encryptor->HashPasswordCustom(RawPassword, GetArgonSettings());
}

FArgonSettings FUserManager::GetArgonSettings() const
{
	return FArgonSettings(2, 19 * 1024, 1, 128, 64);
}

void FUserManager::OnLoginSuccessful(const std::shared_ptr<FUser>& UserPtr, const bool bWereDownloadedFromDB)
{
	if (bWereDownloadedFromDB)
	{
		AddUserToCache(UserPtr);

		UpdateUserActivity(UserPtr->GetUserId());
	}
}

void FUserManager::OnRegisterSuccessful(const std::shared_ptr<FUser>& UserPtr)
{
	AddUserToCache(UserPtr);
}

void FUserManager::AddUserToCache(const std::shared_ptr<FUser>& UserPtr)
{
	{
		// Lock as register may come from any thread
		const std::unique_lock UserDataBaseMutexScopeLock(UserDataBaseMutex);

		// Create user
		UserDataBaseCache.Emplace(UserPtr->GetUserId(), UserPtr);
	}

	{
		// Another lock for map
		const std::unique_lock UserMailMapMutexScopeLock(UserMailMapMutex);

		// Add mail to cache
		UserMailToUserIdMap.Emplace(UserPtr->GetUserMail(), UserPtr->GetUserId());
	}
}

bool FUserManager::ValidateUserNameLength(const std::string& InUserName)
{
	return (InUserName.size() > 4 && InUserName.size() < 110);
}

bool FUserManager::ValidateUserName(const std::string& InUserName)
{
	// SECURITY: usernames are echoed to every other client, so they must satisfy
	// both a length bound and a safe character whitelist (see USERNAME_ALLOWED_CHARSET).
	return ValidateUserNameLength(InUserName) &&
	       static_cast<bool>(FStringHelpers::ValidateString(InUserName, USERNAME_ALLOWED_CHARSET));
}

bool FUserManager::ValidatePasswordLength(const std::string& InPassword)
{
	return (InPassword.length() > 7) && (InPassword.size() < 270);
}

bool FUserManager::ValidateEMailLength(const std::string& InEMail)
{
	return InEMail.length() > 4 && (InEMail.size() < 530);
}
