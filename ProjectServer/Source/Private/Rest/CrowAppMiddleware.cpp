#include "Rest/CrowAppMiddleware.h"
#include "ProjectEngine.h"
#include "AbuseProtection/AbuseProtection.h"
#include "Auth/UserManager.h"
#include "WebUtils/CookieHelper.h"

void FCrowAppMiddleware::before_handle(crow::request& Req, crow::response& Res, context& Ctx)
{
	const FProjectEngine* ProjectEngine = static_cast<FProjectEngine*>(FGlobalDefines::GEngine);
	const FAbuseProtection* AbuseProtection = ProjectEngine->GetAbuseProtection();

	// Get IP address
	const std::string& ClientIP = Req.remote_ip_address;

	// --- Two-tier global rate limiting ---
	// Determine if the request is authenticated (has a valid session token).
	// Authenticated users get their own per-UserID quota (generous, e.g. 2000/hr).
	// Unauthenticated requests are strictly limited per-IP (e.g. 300/hr).

	const std::string_view CookieHeader = Req.get_header_value("Cookie");
	const std::string AuthToken = FCookieHelper::GetCookieValue(CookieHeader, "auth_token");

	bool bIsAuthenticated = false;
	Uint64 UserId = 0;

	if (!AuthToken.empty()) [[likely]]
	{
		const FUserManager* UserManager = ProjectEngine->GetUserManager();
		if (UserManager->VerifyToken(AuthToken)) [[likely]]
		{
			UserId = UserManager->GetIdFromToken(AuthToken);
			bIsAuthenticated = (UserId != 0);
		}
	}

	if (bIsAuthenticated) [[likely]]
	{
		// Tier 2: per-UserID rate limit (default 2000/hr)
		const std::string UserIdStr = std::to_string(UserId);
		if (AbuseProtection->IsAuthenticatedUserBlocked(UserIdStr)) [[unlikely]]
		{
			Res.code = crow::status::TOO_MANY_REQUESTS;
			Res.body = R"({"error":"Global rate limit exceeded"})";
			Res.end();
			return;
		}

		AbuseProtection->AddAuthenticatedUserAttempt(UserIdStr);
	}
	else [[unlikely]]
	{
		// Tier 1: per-IP rate limit for unauthenticated requests (default 300/hr)
		if (AbuseProtection->IsUnauthenticatedIPBlocked(ClientIP)) [[unlikely]]
		{
			Res.code = crow::status::TOO_MANY_REQUESTS;
			Res.body = R"({"error":"Global rate limit exceeded"})";
			Res.end();
			return;
		}

		AbuseProtection->AddUnauthenticatedIPAttempt(ClientIP);
	}

	// --- Specific abuse check (auth-sensitive operations like login, register) ---
	if (!AbuseProtection->IsAddressBlocked(ClientIP)) [[likely]]
	{
		// Options support
		if (Req.method == crow::HTTPMethod::Options)
		{
			Res.code = 204;
			Res.end();
		}
	}
	else [[unlikely]]
	{
		// Block due to Too Many Requests
		Res.code = crow::status::TOO_MANY_REQUESTS;
		Res.body = R"({"error":"Rate limit exceeded"})";
		Res.end();
	}
}

void FCrowAppMiddleware::after_handle(crow::request& Req, crow::response& Res, context& Ctx)
{
	static const std::string AccessControlAllowOriginHeaderName = "Access-Control-Allow-Origin";

	const std::string Origin = Req.get_header_value("Origin");
	FProjectEngine* ProjectEngine = static_cast<FProjectEngine*>(FGlobalDefines::GEngine);
	const CArray<std::string>& Whitelist = ProjectEngine->GetOriginWhitelist();

	ProjectEngine->AddHeaders(Res, ProjectEngine->GetDefaultHeadersCache());

	if (Whitelist.Size() > 0) [[likely]]
	{
		if (Whitelist.Contains(Origin)) [[likely]]
		{
			// Origin is explicitly allowed - reflect it back.
			ProjectEngine->AddHeaders(Res, { { AccessControlAllowOriginHeaderName, Origin } });
		}
		else [[unlikely]]
		{
			// Origin is not in the whitelist. Reflect the first whitelist entry
			// as a safe default so same-origin / default-frontend requests still
			// receive a CORS response; an unlisted Origin will not match the
			// reflected value and the browser will reject the request.
			ProjectEngine->AddHeaders(Res, { { AccessControlAllowOriginHeaderName, Whitelist[0] } });
		}
	}
}
