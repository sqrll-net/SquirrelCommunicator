#include "Rest/IntegrationEndpoint.h"
#include "PredefinedMessages.h"
#include "Rest/CrowUtils.h"
#include "ProjectEngine.h"
#include "AbuseProtection/AbuseProtection.h"
#include "Auth/UserManager.h"
#include <cstdlib>
#include <cpr/cpr.h>
#include <nlohmann/json.hpp>
#include <nlohmann/json_fwd.hpp>

FIntegrationEndpoint::FIntegrationEndpoint(FProjectEngine* InProjectEngine)
	: FCrowAppEndpoint(InProjectEngine)
{
}

void FIntegrationEndpoint::RegisterRoutes(crow::App<FCrowAppMiddleware>& App)
{
	CROW_ROUTE(App, "/api/v1/integrate/google")
		.methods("POST"_method, "OPTIONS"_method)
		([this](const crow::request& req)
		{
			crow::response OutResponse = FCrowUtils::CreateResponse(crow::status::BAD_REQUEST, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Invalid JSON."} });

			// Get IP address
			const std::string& ClientIP = req.remote_ip_address;

			const crow::json::rvalue JsonData = crow::json::load(req.body);
			if (JsonData)
			{
				const std::string GoogleToken = JsonData["google_token"].s();

				cpr::Response response;

				// Verify google token
				try
				{
					response = cpr::Get(
						cpr::Url{"https://oauth2.googleapis.com/tokeninfo"},
						cpr::Parameters{{"id_token", GoogleToken}}
					);
				}
				catch (const std::exception& e)
				{
					std::string ExceptionText = e.what();
					LOG_ERROR("Google login exception, error: " << ExceptionText);

					OutResponse = FCrowUtils::CreateResponse(crow::status::INTERNAL_SERVER_ERROR,
						{ { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error },
							{ "message", "Google integration - cpr: " + ExceptionText} }
					);
				}

				if (response.status_code == 200)
				{
					try
					{
						auto json = nlohmann::json::parse(response.text);

						// Verify
						if (json.contains("error"))
						{
							// Token invalid
							std::string JSON_Error = json["error"];

							OutResponse = FCrowUtils::CreateResponse(crow::status::INTERNAL_SERVER_ERROR,
								{ { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error },
									{ "message", "Google integration - JSON Contains error:" + JSON_Error } }
							);
						}
						else
						{
							// SECURITY (audience validation): the ID token must have been issued
							// for OUR Google OAuth client, not some attacker-controlled client.
							// Without this check, a valid Google ID token minted for any Google
							// project would be accepted, letting an attacker authenticate as any
							// Google account they control through this integration.
							const char* GoogleClientIdEnv = std::getenv("SQRLL_GOOGLE_CLIENT_ID");
							const std::string ExpectedAudience = (GoogleClientIdEnv != nullptr) ? std::string(GoogleClientIdEnv) : std::string();
							const std::string TokenAudience = json.value("aud", "");

							if (ExpectedAudience.empty() || TokenAudience != ExpectedAudience)
							{
								// Fail closed: if the audience cannot be validated (client ID not
								// configured, or a mismatch), the token must be rejected outright.
								LOG_WARN("Google integration - token audience validation failed (expected '"
									<< ExpectedAudience << "', got '" << TokenAudience << "').");

								OutResponse = FCrowUtils::CreateResponse(crow::status::UNAUTHORIZED,
									{ { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error },
										{ "message", "Google integration - invalid token audience."} }
								);
							}
							else
							{
								// Google can let you login without verified mail, we do not want that.
								// tokeninfo may return email_verified as a boolean or a string; accept both.
								bool bEmailVerified = false;
								if (json.contains("email_verified"))
								{
									const auto& EmailVerifiedJson = json["email_verified"];
									if (EmailVerifiedJson.is_boolean())
									{
										bEmailVerified = EmailVerifiedJson.get<bool>();
									}
									else if (EmailVerifiedJson.is_string())
									{
										bEmailVerified = (EmailVerifiedJson.get<std::string>() == "true");
									}
								}

								if (bEmailVerified)
								{
									std::string Mail = json["email"];
									std::string Name = json.value("name", "");

									// User (if missing - DB Downlaod)
									FUserManager* UserManager = ProjectEngine->GetUserManager();
									std::shared_ptr<FUser> UserPtr = UserManager->FindUserByMail(Mail);

									// User missing - try Register
									if (UserPtr == nullptr)
									{
										UserPtr = RegisterIntegration(OutResponse, Mail, Name);
									}

									// Actual login
									if (UserPtr != nullptr)
									{
										// Create session
										std::string OutSessionToken;
										const ELoginStatus LoginResult = UserManager->LoginIntegration(Mail, OutSessionToken);
										HandleLoginCase(OutResponse, LoginResult, OutSessionToken, ClientIP);
									}
								}
								else
								{
									LOG_ERROR("Google integration - E-Mail not verified.");

									OutResponse = FCrowUtils::CreateResponse(crow::status::BAD_REQUEST,
										{ { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error },
											{ "message", "Google integration - E-Mail not verified."} }
									);
								}
							}
						}
					}
					catch (const nlohmann::json::exception& e)
					{
						// Parse error
						std::string ExceptionText = e.what();
						LOG_ERROR("Google integration - Parse error." << ExceptionText);

						OutResponse = FCrowUtils::CreateResponse(crow::status::INTERNAL_SERVER_ERROR,
							{ { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error },
							{ "message", "Google integration - exception." + ExceptionText} }
						);
					}
				}
				else
				{
					LOG_WARN("Google responded with error: " << response.status_code << ": " << response.text);

					ProjectEngine->GetAbuseProtection()->AddRateLimitedAttempt(ClientIP);
				}
			}
			else
			{
				ProjectEngine->GetAbuseProtection()->AddRateLimitedAttempt(ClientIP);
			}

			return OutResponse;
		});

	CROW_ROUTE(App, "/api/v1/integrate/microsoft")
		.methods("POST"_method, "OPTIONS"_method)
		([this](const crow::request& req)
		{
			crow::response OutResponse = FCrowUtils::CreateResponse(crow::status::BAD_REQUEST, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Invalid JSON."} });

			// Get IP address
			const std::string& ClientIP = req.remote_ip_address;

			const crow::json::rvalue JsonData = crow::json::load(req.body);
			if (JsonData)
			{
				const std::string MicrosoftToken = JsonData["microsoft_token"].s();

				cpr::Response response;

				// Verify microsoft token
				try
				{
					response = cpr::Get(
						cpr::Url{"https://graph.microsoft.com/v1.0/me"},
						cpr::Header{{"Authorization", "Bearer " + MicrosoftToken}}
					);
				}
				catch (const std::exception& e)
				{
					std::string ExceptionText = e.what();
					LOG_ERROR("Microsoft login exception, error: " << ExceptionText);

					OutResponse = FCrowUtils::CreateResponse(crow::status::INTERNAL_SERVER_ERROR,
						{ { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error },
							{ "message", "Microsoft integration - cpr: " + ExceptionText} }
					);
				}

				if (response.status_code == 200)
				{
					try
					{
						auto json = nlohmann::json::parse(response.text);

						// Verify
						if (json.contains("error"))
						{
							LOG_ERROR("Microsoft integration - JSON from MS has error." << json["error"]);

							OutResponse = FCrowUtils::CreateResponse(crow::status::INTERNAL_SERVER_ERROR,
								{ { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error },
								{ "message", "Microsoft integration - exception."} }
							);
						}
						else if (json.contains("mail") && json.contains("displayName"))
						{
							// Everything fine
							std::string Mail = json["mail"];
							std::string Name = json.value("displayName", "");

							// Add user (if missing)
							FUserManager* UserManager = ProjectEngine->GetUserManager();
							std::shared_ptr<FUser> UserPtr = UserManager->FindUserByMail(Mail);
							if (UserPtr == nullptr)
							{
								// Register
								UserPtr = RegisterIntegration(OutResponse, Mail, Name);
							}

							// Actual login
							if (UserPtr != nullptr)
							{
								// Create session
								std::string OutSessionToken;
								const ELoginStatus LoginResult = UserManager->LoginIntegration(Mail, OutSessionToken);
								HandleLoginCase(OutResponse, LoginResult, OutSessionToken, ClientIP);
							}
						}
						else
						{
							LOG_ERROR("Microsoft integration - missing required fields 'mail' or/and 'displayName'.");

							OutResponse = FCrowUtils::CreateResponse(crow::status::INTERNAL_SERVER_ERROR,
								{ { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error },
								{ "message", "Microsoft integration - failed due to MS data missing."} }
							);
						}
					}
					catch (const nlohmann::json::exception& e)
					{
						// Parse error
						std::string ExceptionText = e.what();
						LOG_ERROR("Microsoft integration - Parse error." << ExceptionText);

						OutResponse = FCrowUtils::CreateResponse(crow::status::INTERNAL_SERVER_ERROR,
							{ { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error },
							{ "message", "Microsoft integration - internal exception." } }
						);
					}
				}
				else
				{
					LOG_ERROR("Microsoft integration failed: " << response.text);

					OutResponse = FCrowUtils::CreateResponse(crow::status::UNAUTHORIZED,
						{ { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error },
						{ "message", "Microsoft integration - missing authorization."} }
					);
				}
			}

			return OutResponse;
		});

	FCrowAppEndpoint::RegisterRoutes(App);
}

std::shared_ptr<FUser> FIntegrationEndpoint::RegisterIntegration(crow::response &OutResponse, const std::string &Mail, const std::string &Name) const
{
	FUserManager* UserManager = ProjectEngine->GetUserManager();
	ERegisterUserStatus RegisterResult = UserManager->RegisterIntegration(Name, Mail);
	if (RegisterResult == ERegisterUserStatus::Successful)
	{
		return UserManager->FindUserByMail(Mail);
	}
	else
	{
		switch (RegisterResult)
		{
		case ERegisterUserStatus::MailTaken:
			LOG_ERROR("Integration - Mail already taken during registration.");
			break;
		case ERegisterUserStatus::PasswordLengthIncorrect:
			LOG_ERROR("Integration - Password length incorrect during registration.");
			break;
		case ERegisterUserStatus::MailLengthIncorrect:
			LOG_ERROR("Integration - Mail length incorrect during registration.");
			break;
		case ERegisterUserStatus::UserNameLengthIncorrect:
			LOG_ERROR("Integration - User name length incorrect during registration.");
			break;
		case ERegisterUserStatus::MailIncorrect:
			LOG_ERROR("Integration - Mail format incorrect during registration.");
			break;
		case ERegisterUserStatus::PasswordIncorrect:
			LOG_ERROR("Integration - Password format incorrect during registration.");
			break;
		case ERegisterUserStatus::DataBaseInsertFailed:
			LOG_ERROR("Integration - Database insert failed during registration.");
			break;
		case ERegisterUserStatus::DataBaseConnectionFailed:
			LOG_ERROR("Integration - Database connection failed during registration.");
			break;
		default:
			LOG_ERROR("Integration - Unknown error during registration.");
		}

		OutResponse = FCrowUtils::CreateResponse(crow::status::INTERNAL_SERVER_ERROR,
			{ { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error },
				{ "message", "Integration - Unable to register in internal database."} }
		);
	}

	return nullptr;
}

void FIntegrationEndpoint::HandleLoginCase(crow::response &OutResponse, ELoginStatus LoginStatus, const std::string& OutSessionToken, const std::string& ClientIP) const
{
	switch (LoginStatus)
	{
		case ELoginStatus::Successful:
		{
			OutResponse = FCrowUtils::CreateResponse(crow::status::OK, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Success }, { "message", "User login successful!"} });

			ProjectEngine->AddCookies(OutResponse, OutSessionToken);

			break;
		}

		case ELoginStatus::IncorrectCredentialsOrUserDoesNotExist:
		{
			OutResponse = FCrowUtils::CreateResponse(crow::status::BAD_REQUEST, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Incorrect Credentials Or User Does Not Exist"} });

			ProjectEngine->GetAbuseProtection()->AddRateLimitedAttempt(ClientIP);

			break;
		}

		case ELoginStatus::IncorrectInputLength:
		{
			OutResponse = FCrowUtils::CreateResponse(crow::status::FORBIDDEN, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Incorrect Input Length"} });

			ProjectEngine->GetAbuseProtection()->AddRateLimitedAttempt(ClientIP);

			break;
		}

		default:
		{
			OutResponse = FCrowUtils::CreateResponse(crow::status::INTERNAL_SERVER_ERROR, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Login: INTERNAL_SERVER_ERROR"} });
			LOG_ERROR("Login Integration Status unknown value!");
		}
	}
}
