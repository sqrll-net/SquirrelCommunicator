// Created by https://www.linkedin.com/in/przemek2122/ 2026

#pragma once

#include "EngineCompat.h"

#include <shared_mutex>
#include <memory>
#include "SessionManager.h"
#include "User.h"
#include "Encryption/PasswordEncryptionArgon.h"

enum class EDatabaseOperationResult : Uint8;

class FImageServiceManager;

enum class ERegisterUserStatus : Uint8
{
	Unknown,
	Successful,
	MailTaken,
	PasswordLengthIncorrect,
	MailLengthIncorrect,
	UserNameLengthIncorrect,
	UserNameIncorrect,
	MailIncorrect,
	PasswordIncorrect,
	DataBaseInsertFailed,
	DataBaseConnectionFailed
};

enum class ELoginStatus : Uint8
{
	Unknown,
	Successful,
	SessionAlreadyExist,
	IncorrectInputLength,
	IncorrectEMailContent,
	IncorrectCredentialsOrUserDoesNotExist,
	DataBaseFetchFailed,
	DataBaseConnectionFailed
};

enum class EUpdateUserNameStatus : Uint8
{
	Unknown,
	Successful,
	UserNameLengthIncorrect,
	UserNameIncorrect,
};

enum class EUpdateUserPasswordStatus : Uint8
{
	Unknown,
	Successful,
	UserNotFound,
	OldPasswordIncorrect,
	PasswordLengthIncorrect,
	PasswordIncorrect
};

/**
 * Class for managing users
 * ALL downloading and managing users should be done using this class
 */
class FUserManager
{
public:
	FUserManager(Uint64 InSessionExpirationTime);
	~FUserManager();

	void Init();

	/** Updated every second */
	void PostSecondTick();

	/**
	 * Use to register
	 * @return registration status, see enum for details
	 */
	ERegisterUserStatus RegisterUser(const std::string& InUserName, const std::string& InUserPassword, const std::string& InUserEMail);

	/** Validate registration input and produce a password hash. No database write. */
	ERegisterUserStatus PrepareRegistration(const std::string& InUserName, const std::string& InUserPassword, const std::string& InUserEMail, std::string& OutPasswordHash);

	/** Finalize a pending registration by inserting the user into the database and cache. */
	ERegisterUserStatus CompleteRegistration(const std::string& InUserName, const std::string& InUserPasswordHash, const std::string& InUserEMail);

	/** Integration user creation */
	ERegisterUserStatus RegisterIntegration(const std::string& InUserName, const std::string& InUserEMail);

	/**
	 * Use for login
	 * @return Unique session token
	 */
	ELoginStatus LoginUser(const std::string& InUserEmail, const std::string& InUserPassword, std::string& OutSessionToken);

	/** Internal login use - Make sure to check if integration is valid as this just logins without any checks. */
	ELoginStatus LoginIntegration(const std::string& InUserEmail, std::string& OutSessionToken);

	/** Use for login with transfer token */
	ELoginStatus LoginFromId(const Uint64 Id, std::string& OutSessionToken);

	/** @return true if successfully logged out */
	bool Logout(const std::string& InSessionToken);

	/** @return true when valid. Check if provided token is correct. */
	bool VerifyToken(const std::string& InToken) const;

	/** @return true when valid. Will leave old token but with longer time to use. */
	bool RefreshSessionToken(const std::string& InToken) const;

	void UpdateUserActivity(Uint64 UsedId);
	EUpdateUserNameStatus UpdateUserName(Uint64 UsedId, const std::string& NewUserName);
	EUpdateUserPasswordStatus UpdateUserPassword(Uint64 InUserId, const std::string& OldPassword, const std::string& NewPassword);
	EUpdateUserPasswordStatus OverrideUserPassword(Uint64 InUserId, const std::string& NewPassword);

	/**
	 * Force-log-out a user on all devices by revoking every session token.
	 * Called after a password change or reset so a pre-compromise session can
	 * never survive credential remediation (defense-in-depth).
	 */
	void InvalidateAllSessionsForUser(Uint64 InUserId);

	/** Search all users to find this with mail specified */
	std::shared_ptr<FUser> FindUserByMail(const std::string& InMail);

	/** Get user ID from token, 0 means not found */
	Uint64 GetIdFromToken(const std::string& InToken) const;

	/** Cache for time updated every second */
	Uint64 GetCurrentTimeCached() const { return CurrentTimeCached; }

	bool GetUsersByIds(const std::vector<Uint64>& UserIds, std::vector<std::shared_ptr<FUser>>& OutUsers);
	std::shared_ptr<FUser> GetUserById(Uint64 InUserId);

	/** Manager that issues/revokes per-session image service API keys. */
	FImageServiceManager* GetImageServiceManager() const { return ImageServiceManager.get(); }

private:
	EDatabaseOperationResult DownloadUserFromDBByMail(const std::string& InUserEmail, std::shared_ptr<FUser>& UserPtr);
	EDatabaseOperationResult DownloadUsersFromDBByIds(const std::vector<Uint64>& UserIds, std::vector<std::shared_ptr<FUser>>& OutUsers, bool bAutoAddToCache);

	EDatabaseOperationResult UploadUserToDataBase(const std::string& InUserName, const std::string& InUserPasswordHash, const std::string& InUserEMail, Uint64& OutId);
	EDatabaseOperationResult UpdateUserPasswordInDataBase(Uint64 InUserId, const std::string& InUserPasswordHash);

	static EDatabaseOperationResult DoesUserWithMailExists(const std::string& InUserEmail, bool& bOutExists);

	Uint64 GenerateNextAvailableId();
	bool VerifyPasswords(const std::string& StringWithHash, const std::string& StringWithoutHash);
	std::string HashUserPassword(const std::string& RawPassword);
	FArgonSettings GetArgonSettings() const;

	void OnLoginSuccessful(const std::shared_ptr<FUser>& UserPtr, const bool bWereDownloadedFromDB);
	void OnRegisterSuccessful(const std::shared_ptr<FUser>& UserPtr);
	void AddUserToCache(const std::shared_ptr<FUser>& UserPtr);

	bool ValidateUserNameLength(const std::string& InUserName);
	bool ValidateUserName(const std::string& InUserName);
	bool ValidatePasswordLength(const std::string& InPassword);
	bool ValidateEMailLength(const std::string& InEMail);

private:
	/**
	 * Manager for image service (issues/revokes per-session upload keys).
	 * Declared before SessionManager so it is destroyed after the session
	 * manager's worker thread has been joined.
	 */
	std::unique_ptr<FImageServiceManager> ImageServiceManager;

	/** Manager for user sessions */
	std::unique_ptr<FSessionManager> SessionManager;

	/**
	 * Map with all users connected to number,
	 * cached version of users in database, on restart it will be rebuilt from database
	 * @TODO For long runs consider clearing every x time of inactivity
	 */
	CUnorderedMap<Uint64, std::shared_ptr<FUser>, Uint64> UserDataBaseCache;

	/**
	 * Map with all users mails to number,
	 * @TODO For long runs consider clearing every x time of inactivity
	 */
	CUnorderedMap<std::string, Uint64> UserMailToUserIdMap;

	/** Tells us which number is available */
	Uint64 NextAvailableIndex;

	/** Mutex for UserDataBase */
	std::shared_mutex UserDataBaseMutex;

	/** Mutex for UserDataBase */
	std::shared_mutex UserMailMapMutex;

	/** Cache for time, we will use it for each login, message, etc so cache will be faster */
	Uint64 CurrentTimeCached;

	FArgonSettings CachedArgonSettings;

};
