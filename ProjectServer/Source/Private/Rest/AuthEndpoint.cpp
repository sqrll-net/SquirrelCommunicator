#include "Rest/AuthEndpoint.h"
#include "Rest/CrowUtils.h"
#include "PredefinedMessages.h"
#include "ProjectEngine.h"
#include "AbuseProtection/AbuseProtection.h"
#include "Auth/UserManager.h"
#include "WebUtils/CookieHelper.h"
#include "Managers/EmailVerificationManager.h"
#include "Managers/MailSender.h"
#include "nlohmann/json.hpp"

FAuthEndpoint::FAuthEndpoint(FProjectEngine* InProjectEngine)
	: FCrowAppEndpoint(InProjectEngine)
{
}

void FAuthEndpoint::RegisterRoutes(crow::App<FCrowAppMiddleware>& App)
{
	CROW_ROUTE(App, "/api/v1/users/register")
		.methods("POST"_method, "OPTIONS"_method)
		([this](const crow::request& req)
		{
			crow::response OutResponse = FCrowUtils::CreateResponse(400, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Invalid JSON."} });

			// Get IP address
			const std::string& ClientIP = req.remote_ip_address;

			// --- Registration rate limiting (per-IP, default 10/hr) ---
			FAbuseProtection* AbuseProtection = ProjectEngine->GetAbuseProtection();
			if (!AbuseProtection->CanAddressRegisterAccount(ClientIP))
			{
				OutResponse = FCrowUtils::CreateResponse(crow::status::TOO_MANY_REQUESTS, {
					{ FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error },
					{ "message", "Too many registrations. Try again later." }
				});
				return OutResponse;
			}

			const crow::json::rvalue JsonData = crow::json::load(req.body);
			if (JsonData)
			{
				const std::string UserName = JsonData["username"].s();
				const std::string UserPassword = JsonData["password"].s();
				const std::string EMail = JsonData["email"].s();

				FUserManager* UserManager = ProjectEngine->GetUserManager();

				// Step 1: validate input and prepare a password hash. The account is not created yet.
				std::string PasswordHash;
				const ERegisterUserStatus PrepareStatus = UserManager->PrepareRegistration(UserName, UserPassword, EMail, PasswordHash);

				// Count every registration attempt against the hourly limit (success or failure).
				AbuseProtection->AddRegisterAccountAttempt(ClientIP);

				if (PrepareStatus == ERegisterUserStatus::Unknown)
				{
					// SECURITY (anti-enumeration): return an identical response whether or
					// not the email is already registered.
					const bool bAlreadyRegistered = (UserManager->FindUserByMail(EMail) != nullptr);

					if (!bAlreadyRegistered)
					{
						// Generate the verification code and keep the registration pending.
						FEmailVerificationManager* VerificationManager = ProjectEngine->GetEmailVerificationManager();
						const FPendingRegistration Pending = VerificationManager->GenerateVerificationCode(EMail, UserName, PasswordHash);

						// Build the link the user clicks to continue registration.
						// Debug builds point at the local REST server (http://localhost:<port>),
						// release builds point at the production domain.
						const std::string VerifyLink = ProjectEngine->GetPublicBaseUrl() + "/register/verify?code=" + Pending.VerificationCode + "&email=" + EMail;

						// Send the code by email. Database registrations only - integrations never reach this route.
						try
						{
							const nlohmann::json JsonBody = {
								{"to", {{ {"email", EMail} }}},
								{"templateId", 2}, // registration verification template
								{"params", {
									{"TOKEN", Pending.VerificationCode},
									{"USERNAME", UserName},
									{"LINK", VerifyLink}
								}}
							};
							FMailSender::SendMail(JsonBody);
						}
						catch (const std::exception& e)
						{
							LOG_ERROR("Registration verification mail failed: " << e.what());
						}

					}
					// Identical response for both branches - the client cannot distinguish
					// a new registration from an already-registered email.
					OutResponse = FCrowUtils::CreateResponse(crow::status::OK, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Success }, { "message", "If following mail is not registered, you will got email with the verification code."} });
				}
				else
				{
					switch (PrepareStatus)
					{
						case ERegisterUserStatus::PasswordLengthIncorrect:
						{
							OutResponse = FCrowUtils::CreateResponse(crow::status::BAD_REQUEST, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message","Registration failed. Password too weak."} });
							break;
						}
						case ERegisterUserStatus::MailLengthIncorrect:
						case ERegisterUserStatus::UserNameLengthIncorrect:
						case ERegisterUserStatus::MailIncorrect:
						case ERegisterUserStatus::PasswordIncorrect:
						default:
						{
							OutResponse = FCrowUtils::CreateResponse(crow::status::BAD_REQUEST, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message","Registration failed. User may already exist or invalid input."} });
							break;
						}
					}
				}
			}
			else
			{
				OutResponse = FCrowUtils::CreateResponse(429, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message","Too many requests."} });
			}

			return OutResponse;
		});

	CROW_ROUTE(App, "/api/v1/users/register/verify")
		.methods("POST"_method, "OPTIONS"_method)
		([this](const crow::request& req)
		{
			crow::response OutResponse = FCrowUtils::CreateResponse(crow::status::BAD_REQUEST, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Invalid JSON."} });

			// Get IP address
			const std::string& ClientIP = req.remote_ip_address;

			const crow::json::rvalue JsonData = crow::json::load(req.body);
			if (JsonData)
			{
				const std::string EMail = JsonData["email"].s();
				const std::string Code = JsonData["code"].s();

				FEmailVerificationManager* VerificationManager = ProjectEngine->GetEmailVerificationManager();
				const FPendingRegistration Pending = VerificationManager->ValidateCode(EMail, Code);

				if (Pending.IsValid())
				{
					const ERegisterUserStatus CompleteStatus = ProjectEngine->GetUserManager()->CompleteRegistration(Pending.UserName, Pending.PasswordHash, Pending.UserMail);

					if (CompleteStatus == ERegisterUserStatus::Successful)
					{
						VerificationManager->ConsumeCode(EMail, Code);

						OutResponse = FCrowUtils::CreateResponse(crow::status::OK, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Success }, { "message", "Registration completed. You can now log in."} });
					}
					else
					{
						LOG_ERROR("Registration verify failed with status: " << static_cast<int>(CompleteStatus));

						OutResponse = FCrowUtils::CreateResponse(crow::status::INTERNAL_SERVER_ERROR, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Registration failed. Please try again."} });
					}
				}
				else
				{
					// Throttle brute force attempts against the code.
					ProjectEngine->GetAbuseProtection()->AddRateLimitedAttempt(ClientIP);

					OutResponse = FCrowUtils::CreateResponse(crow::status::BAD_REQUEST, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Invalid or expired verification code."} });
				}
			}

			return OutResponse;
		});

	CROW_ROUTE(App, "/api/v1/users/login")
		.methods("POST"_method, "OPTIONS"_method)
		([this](const crow::request& req)
		{
			crow::response OutResponse = FCrowUtils::CreateResponse(crow::status::BAD_REQUEST, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Invalid JSON."} });

			// Get IP address
			const std::string& ClientIP = req.remote_ip_address;

			const crow::json::rvalue JsonData = crow::json::load(req.body);
			if (JsonData)
			{
				const std::string UserEmail = JsonData["email"].s();
				const std::string UserPassword = JsonData["password"].s();

				std::string OutSessionToken;
				const ELoginStatus LoginStatus = ProjectEngine->GetUserManager()->LoginUser(UserEmail, UserPassword, OutSessionToken);

				if (!OutSessionToken.empty() && LoginStatus == ELoginStatus::Successful)
				{
					OutResponse = FCrowUtils::CreateResponse(crow::status::OK, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Success }, { "message", "User login successful!"} });

					// This is overrided by CreateResponse so use after setting OutResponse
					ProjectEngine->AddCookies(OutResponse, OutSessionToken);
				}
				else
				{
					switch (LoginStatus)
					{
						case ELoginStatus::Unknown:
						{
							OutResponse = FCrowUtils::CreateResponse(crow::status::BAD_REQUEST, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Login failed due to an internal error." } });

							break;
						}
						case ELoginStatus::SessionAlreadyExist:
						{
							OutResponse = FCrowUtils::CreateResponse(crow::status::NO_CONTENT, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Session already exists!"} });

							break;
						}
						case ELoginStatus::IncorrectCredentialsOrUserDoesNotExist:
						{
							OutResponse = FCrowUtils::CreateResponse(crow::status::FORBIDDEN, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Wrong credentials!"} });

							ProjectEngine->GetAbuseProtection()->AddRateLimitedAttempt(ClientIP);

							break;
						}
						case ELoginStatus::IncorrectInputLength:
						{
							OutResponse = FCrowUtils::CreateResponse(crow::status::FORBIDDEN, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "IncorrectInputLength"} });

							ProjectEngine->GetAbuseProtection()->AddRateLimitedAttempt(ClientIP);
						}
						default:
						{
							OutResponse = FCrowUtils::CreateResponse(crow::status::INTERNAL_SERVER_ERROR, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Login: INTERNAL_SERVER_ERROR"} });
							LOG_ERROR("LoginStatus unknown value!");
						}
					}

				}
			}

			return OutResponse;
		});

	CROW_ROUTE(App, "/api/v1/users/verify")
		.methods("POST"_method, "OPTIONS"_method)
		([this](const crow::request& req)
		{
			crow::response OutResponse = FCrowUtils::CreateResponse(crow::status::BAD_REQUEST, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Invalid JSON."} });

			const std::string_view CookieHeader = req.get_header_value("Cookie");
			const std::string Token = FCookieHelper::GetCookieValue(CookieHeader, "auth_token");

			// Get IP address
			const std::string& ClientIP = req.remote_ip_address;

			if (ProjectEngine->GetUserManager()->VerifyToken(Token))
			{
				OutResponse = FCrowUtils::CreateResponse(crow::status::OK, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Success }, { "message", "Token correct."} });
			}
			else
			{
				OutResponse = FCrowUtils::CreateResponse(crow::status::UNAUTHORIZED, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Token incorrect."} });

				ProjectEngine->GetAbuseProtection()->AddRateLimitedAttempt(ClientIP);
			}

			return OutResponse;
		});

	CROW_ROUTE(App, "/api/v1/users/refresh")
		.methods("POST"_method, "OPTIONS"_method)
		([this](const crow::request& req)
		{
			crow::response OutResponse = FCrowUtils::CreateResponse(400, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Invalid JSON."} });

			const std::string_view CookieHeader = req.get_header_value("Cookie");
			const std::string Token = FCookieHelper::GetCookieValue(CookieHeader, "auth_token");

			if (!Token.empty())
			{
				if (ProjectEngine->GetUserManager()->RefreshSessionToken(Token))
				{
					OutResponse = FCrowUtils::CreateResponse(crow::status::OK, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Success }, { "message", "Token has new refreshed."} });
				}
				else
				{
					OutResponse = FCrowUtils::CreateResponse(crow::status::UNAUTHORIZED, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Token not found."} });
				}

				// Get IP address
				const std::string& ClientIP = req.remote_ip_address;

				ProjectEngine->GetAbuseProtection()->AddRateLimitedAttempt(ClientIP);
			}

			return OutResponse;
		});

	CROW_ROUTE(App, "/api/v1/users/logout")
		.methods("POST"_method, "OPTIONS"_method)
		([this](const crow::request& req)
		{
			crow::response OutResponse = FCrowUtils::CreateResponse(crow::status::BAD_REQUEST, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Invalid JSON."} });

			const crow::json::rvalue JsonData = crow::json::load(req.body);
			if (JsonData)
			{
				const std::string SessionToken = JsonData["token"].s();

				const bool bSuccessfullyLoggedOut = ProjectEngine->GetUserManager()->Logout(SessionToken);
				if (bSuccessfullyLoggedOut)
				{
					OutResponse = FCrowUtils::CreateResponse(crow::status::OK, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Success }, { "message", "Session terminated!"} });
				}
				else
				{
					OutResponse = FCrowUtils::CreateResponse(crow::status::BAD_REQUEST, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Can not log out."} });
				}
			}

			return OutResponse;
		});

	FCrowAppEndpoint::RegisterRoutes(App);
}
