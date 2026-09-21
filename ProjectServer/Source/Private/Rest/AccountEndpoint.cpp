#include "Rest/AccountEndpoint.h"
#include "PredefinedMessages.h"
#include "ProjectEngine.h"
#include "AbuseProtection/AbuseProtection.h"
#include "Auth/UserManager.h"
#include "Managers/MailSender.h"
#include "Managers/PasswordResetManager.h"
#include "WebUtils/CookieHelper.h"
#include "nlohmann/json.hpp"
#include "nlohmann/json_fwd.hpp"
#include "WebUtils/StringHelpers.h"
#include "Rest/CrowUtils.h"

FAccountEndpoint::FAccountEndpoint(FProjectEngine* InProjectEngine)
    : FCrowAppEndpoint(InProjectEngine)
{
}

void FAccountEndpoint::RegisterRoutes(crow::App<FCrowAppMiddleware>& App)
{
    CROW_ROUTE(App, "/api/v1/account/change_name")
    .methods("POST"_method, "OPTIONS"_method)
    ([this](const crow::request& req)
    {
        crow::response OutResponse = FCrowUtils::CreateResponse(crow::status::BAD_REQUEST, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Invalid JSON."} });

        const std::string_view CookieHeader = req.get_header_value("Cookie");
        const std::string Token = FCookieHelper::GetCookieValue(CookieHeader, "auth_token");

        // Get IP address
        const std::string& ClientIP = req.remote_ip_address;

        FUserManager* UserManager = ProjectEngine->GetUserManager();
        if (UserManager->VerifyToken(Token))
        {
            const Uint64 UserId = UserManager->GetIdFromToken(Token);

            try
            {
                const crow::json::rvalue JsonData = crow::json::load(req.body);
                if (JsonData)
                {
                    const std::string NewUserName = JsonData["new_name"].s();
                    const EUpdateUserNameStatus UpdateResult = UserManager->UpdateUserName(UserId, NewUserName);

                    if (UpdateResult == EUpdateUserNameStatus::Successful)
                    {
                        OutResponse = FCrowUtils::CreateResponse(crow::status::OK, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Success }, { "message", "User name changed."} });
                    }
                    else if (UpdateResult == EUpdateUserNameStatus::UserNameIncorrect)
                    {
                        OutResponse = FCrowUtils::CreateResponse(crow::status::BAD_REQUEST, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "User name contains invalid characters."} });
                    }
                    else
                    {
                        OutResponse = FCrowUtils::CreateResponse(crow::status::BAD_REQUEST, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "User name length is invalid."} });
                    }
                }
            }
            catch (const nlohmann::json::exception& e)
            {
                LOG_ERROR("Change name error: " << e.what());
                OutResponse = FCrowUtils::CreateResponse(crow::status::INTERNAL_SERVER_ERROR,
                    { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error },
                        { "message", std::string("error :") + e.what()} }
                );
            }
        }
        else
        {
            // Wrong token
            OutResponse = FCrowUtils::CreateResponse(crow::status::UNAUTHORIZED, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Invalid token."} });
        }

        return OutResponse;
    });

    CROW_ROUTE(App, "/api/v1/account/change_password")
     .methods("POST"_method, "OPTIONS"_method)
     ([this](const crow::request& req)
     {
         crow::response OutResponse = FCrowUtils::CreateResponse(crow::status::BAD_REQUEST, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Invalid JSON."} });

         const std::string_view CookieHeader = req.get_header_value("Cookie");
         const std::string Token = FCookieHelper::GetCookieValue(CookieHeader, "auth_token");

         // Get IP address
         const std::string& ClientIP = req.remote_ip_address;

         FUserManager* UserManager = ProjectEngine->GetUserManager();
         if (UserManager->VerifyToken(Token))
         {
             const Uint64 UserId = UserManager->GetIdFromToken(Token);

             try
             {
                 const crow::json::rvalue JsonData = crow::json::load(req.body);
                 if (JsonData)
                 {
                     const std::string OldPassword = JsonData["old_password"].s();
                     const std::string NewPassword = JsonData["new_password"].s();

                     const EUpdateUserPasswordStatus UpdateResult = UserManager->UpdateUserPassword(UserId, OldPassword, NewPassword);

                     switch (UpdateResult)
                     {
                     case EUpdateUserPasswordStatus::Successful:
                         OutResponse = FCrowUtils::CreateResponse(crow::status::OK,
                             { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Success },
                                 { "message", "User password changed."} }
                         );
                         break;

                     case EUpdateUserPasswordStatus::OldPasswordIncorrect:
                         OutResponse = FCrowUtils::CreateResponse(crow::status::FORBIDDEN,
                             { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error },
                                 { "message", "Old password is incorrect."} }
                         );
                         break;

                     case EUpdateUserPasswordStatus::PasswordLengthIncorrect:
                     case EUpdateUserPasswordStatus::PasswordIncorrect:
                         OutResponse = FCrowUtils::CreateResponse(crow::status::BAD_REQUEST,
                             { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error },
                                 { "message", "New password does not meet the requirements."} }
                         );
                         break;

                     case EUpdateUserPasswordStatus::UserNotFound:
                         OutResponse = FCrowUtils::CreateResponse(crow::status::NOT_FOUND,
                             { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error },
                                 { "message", "User not found."} }
                         );
                         break;

                     default:
                         OutResponse = FCrowUtils::CreateResponse(crow::status::INTERNAL_SERVER_ERROR,
                             { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error },
                                 { "message", "Could not change password."} }
                         );
                         break;
                     }
                 }
             }
             catch (const nlohmann::json::exception& e)
             {
                 LOG_ERROR("Change pass error: " << e.what());
                 OutResponse = FCrowUtils::CreateResponse(crow::status::INTERNAL_SERVER_ERROR,
                     { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error },
                         { "message", std::string("error :") + e.what()} }
                 );
             }
         }
         else
         {
             // Wrong token
             OutResponse = FCrowUtils::CreateResponse(crow::status::UNAUTHORIZED, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Invalid token."} });
         }

         return OutResponse;
     });

    CROW_ROUTE(App, "/api/v1/account/reset_pass_by_mail")
    .methods("POST"_method, "OPTIONS"_method)
    ([this](const crow::request& req)
    {
        crow::response OutResponse = FCrowUtils::CreateResponse(crow::status::OK, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Success }, { "message", "If such e-mail exists, it was sent. Check you mailbox."} });
        // Get IP address
        const std::string& ClientIP = req.remote_ip_address;
        std::string TargetMail;

        try
        {
            const nlohmann::json JsonData = nlohmann::json::parse(req.body);
            TargetMail = JsonData.at("target_mail").get<std::string>();
        }
        catch (const nlohmann::json::exception& e)
        {
            LOG_ERROR("Change pass error: " << e.what());

            return FCrowUtils::CreateResponse(
                crow::status::BAD_REQUEST,
                {
                    { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error },
                    { "message", "Invalid request format or missing parameters." }
                }
            );
        }

        FProjectEngine* ProjectEngine = dynamic_cast<FProjectEngine*>(FGlobalDefines::GEngine);
        if (ProjectEngine != nullptr)
        {
            if (!TargetMail.empty() && FStringHelpers::ValidateMail(TargetMail))
            {
                FUserManager* UserManager = ProjectEngine->GetUserManager();
                std::shared_ptr<FUser> User = UserManager->FindUserByMail(TargetMail);

                FAbuseProtection* AbuseProtection = ProjectEngine->GetAbuseProtection();
                if (User != nullptr)
                {
                    if (AbuseProtection->CanAddressRequestPasswordReset(ClientIP))
                    {
                        AbuseProtection->AddPasswordResetAttempt(ClientIP);

                        // Now we need to generate some kind of code, preferably 6 digit long
                        FPasswordResetManager* PasswordResetManager = ProjectEngine->GetPasswordResetManager();
                        FPasswordResetStruct ResetStruct = PasswordResetManager->GenerateResetToken(TargetMail);

                        // Mail content
                        nlohmann::json JsonBody = {
                            {"to", {{{"email", TargetMail }}}},
                            {"templateId", 1},  // your template ID
                            {"params", {
                                {"TOKEN", ResetStruct.ResetToken },
                                {"USERNAME", User->GetUserNameString() }
                            }}
                        };

                        // Do send. Wrap in try/catch: SendMail throws on mail-provider
                        // failure, and an unhandled exception here would surface a generic 500.
                        try
                        {
                            FMailSender::SendMail(JsonBody);
                        }
                        catch (const std::exception& e)
                        {
                            LOG_ERROR("Password reset mail failed: " << e.what());
                        }
                    }
                }
            }
            else
            {
                OutResponse = FCrowUtils::CreateResponse(crow::status::BAD_REQUEST, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Invalid email."} });
            }
        }
        else
        {
            OutResponse = FCrowUtils::CreateResponse(crow::status::INTERNAL_SERVER_ERROR, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Internal error."} });
        }

        return OutResponse;
    });

    CROW_ROUTE(App, "/api/v1/account/reset_pass_by_mail_verify")
    .methods("POST"_method, "OPTIONS"_method)
    ([this](const crow::request& req)
    {
        crow::response OutResponse = FCrowUtils::CreateResponse(crow::status::BAD_REQUEST, { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error }, { "message", "Invalid JSON."} });

        // Get IP address
        const std::string& ClientIP = req.remote_ip_address;
        std::string TargetMail;
        std::string ResetCode;
        std::string NewPassword;

        try
        {
            const nlohmann::json JsonData = nlohmann::json::parse(req.body);

            TargetMail = JsonData.at("target_mail").get<std::string>();
            ResetCode = JsonData.at("reset_code").get<std::string>();
            NewPassword = JsonData.at("new_password").get<std::string>();
        }
        catch (const nlohmann::json::exception& e)
        {
            LOG_WARN("Password reset JSON error: " << e.what());

            OutResponse = FCrowUtils::CreateResponse(
                crow::status::BAD_REQUEST,
                {
                    { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error },
                    { "message", "Invalid request format or missing required fields." }
                }
            );
        }

        if (!TargetMail.empty() && !ResetCode.empty() && !NewPassword.empty())
        {
            FAbuseProtection* AbuseProtection = ProjectEngine->GetAbuseProtection();
            FPasswordResetManager* PasswordResetManager = ProjectEngine->GetPasswordResetManager();

            if (AbuseProtection->CanAddressRequestPasswordReset(ClientIP))
            {
                const bool bValidationResult = PasswordResetManager->ValidateResetToken(TargetMail, ResetCode);

                if (bValidationResult)
                {
                    const bool bUpdateSuccess = PasswordResetManager->UpdatePassword(TargetMail, NewPassword);

                    if (bUpdateSuccess)
                    {
                        PasswordResetManager->InvalidateToken(ResetCode);

                        OutResponse = FCrowUtils::CreateResponse(crow::status::OK, {
                            { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Success },
                            { "message", "Password reset successful."} }
                        );
                    }
                    else
                    {
                        OutResponse = FCrowUtils::CreateResponse(crow::status::INTERNAL_SERVER_ERROR,
                            { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error },
                                { "message", "Internal error."} }
                        );
                    }
                }
                else
                {
                    OutResponse = FCrowUtils::CreateResponse(crow::status::BAD_REQUEST,
                        { { FPredefinedMessages::Status::Name, FPredefinedMessages::Status::Error },
                            { "message", "Invalid reset token or user email." } }
                    );
                }

                AbuseProtection->AddPasswordResetAttempt(ClientIP);
            }
        }

        return OutResponse;
    });

    FCrowAppEndpoint::RegisterRoutes(App);
}
