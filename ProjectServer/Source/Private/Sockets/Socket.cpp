// Created by https://www.linkedin.com/in/przemek2122/ 2026

#include "Sockets/Socket.h"

#include "ProjectEngine.h"
#include "AbuseProtection/AbuseProtection.h"
#include "Auth/UserManager.h"
#include "DataBase/DataBaseConnect.h"
#include "WebUtils/CookieHelper.h"
#include "Sockets/SocketManager.h"
#include "Sockets/WebSocketSessionData.h"
#include <nlohmann/json.hpp>
#include <nlohmann/json_fwd.hpp>
#include <utility>

#include "Managers/ConversationsManager.h"
#include "Managers/ImageServiceManager.h"

FSocket::FSocket(const int32 InSocketIndex, std::string InHost, const int32 InPort, bool bInUseSSL, const std::string& InKeyPath, const std::string& InCertPath)
	: SocketIndex(InSocketIndex)
	, Host(std::move(InHost))
	, Port(InPort)
	, bUseSSL(bInUseSSL)
	, SocketAppWrapper(bInUseSSL, InKeyPath, InCertPath)
	, AppListenSocket(nullptr)
	, ProjectEngine(dynamic_cast<FProjectEngine*>(FGlobalDefines::GEngine))
	, PrivateSocketData(this)
	, ServersSocketData(this)
{
}

FSocket::~FSocket()
{
	RequestShutdown();
}

void FSocket::RequestShutdown()
{
	// Stop the listener first so no new connections are accepted while we
	// drain the existing ones below.
	if (AppListenSocket != nullptr)
	{
		us_listen_socket_close(bUseSSL, AppListenSocket);
		AppListenSocket = nullptr; // Prevent a double close on a second call.
	}

	// Copy to avoid simultaneous access and delete.
	CUnorderedMap<Uint64, AnyWebSocket> tempCopyMap;

	{
		// Lock should be redundant but if somebody were connecting in exact same time as close we might crash
		std::unique_lock<std::shared_mutex> Lock(UserIdToWebSocketPtrMapMutex);

		// Safe copy
		tempCopyMap = UserIdToWebSocketPtrMap;
	}

	// Close all existing sockets. Each close drains the uWS loop, which causes
	// the worker thread running Async()/Run() to return.
	for (std::pair<Uint64, AnyWebSocket> UserIdToSocketPair : tempCopyMap)
	{
#if DEBUG
		FFunctorLambda<void, void*> SocketAccessFunctor = [UserIdToSocketPair](void* ws)
#else
		FFunctorLambda<void, void*> SocketAccessFunctor = [](void* ws)
#endif
		{
#if DEBUG
			LOG_INFO("Killing socket session for ID: " << UserIdToSocketPair.first);
#endif

			auto* WebSocket = static_cast<uWS::WebSocket<false, true, FUserSessionData>*>(ws);

			WebSocket->close();
		};

		AddDeferTaskForConnectionId(UserIdToSocketPair.first, SocketAccessFunctor);
	}
}

void FSocket::AddDeferTaskForConnectionId(const Uint64 UserId, FFunctorLambda<void, void*>& FunctionToCallOnSocket)
{
	std::optional<AnyWebSocket> WebSocketOptionalPtr;

	{
		std::shared_lock<std::shared_mutex> Lock(UserIdToWebSocketPtrMapMutex);
		WebSocketOptionalPtr = UserIdToWebSocketPtrMap.FindValueByKey(UserId);
	}

	if (WebSocketOptionalPtr.has_value())
	{
		std::visit([&](auto* ws)
		{
			uWS::Loop* SocketLoop = SocketAppWrapper.GetLoop();
			SocketLoop->defer([FunctionToCallOnSocket, ws]() mutable {
				FunctionToCallOnSocket.operator()(ws);
			});
		}, WebSocketOptionalPtr.value());
	}
}

void FSocket::BeforeRunAsync()
{
}

template<bool SSL>
auto CreateSocketBehavior(FSocket* Socket) {
	return typename uWS::TemplatedApp<SSL>::template WebSocketBehavior<FWebSocketSessionData>{
		/* Settings */
		.compression = uWS::DISABLED,
		.maxPayloadLength = 16 * 1024,
		.idleTimeout = Socket->GetProjectEngine()->GetBackendSettings()->GetWebSocketIdleTimeoutSeconds(),
		.maxBackpressure = 512 * 1024,
		.sendPingsAutomatically = true,
		/* Handlers */
		.upgrade = [](/** uWS::HttpResponse<SSL> */ auto* res, uWS::HttpRequest* req, auto* context)
		{
			const std::string_view CookieHeader = req->getHeader("cookie");
			const std::string AuthTokenValue = FCookieHelper::GetCookieValue(CookieHeader, "auth_token");

			/** Upgrade data used when connecting new client */
			struct FSocketUpgradeData
			{
				std::string secWebSocketKey;
				std::string secWebSocketProtocol;
				std::string secWebSocketExtensions;
				us_socket_context_t* context;
				decltype(res) httpRes;
				bool aborted = false;
			};

			auto upgradeData = std::make_shared<FSocketUpgradeData>(FSocketUpgradeData{
				.secWebSocketKey = std::string(req->getHeader("sec-websocket-key")),
				.secWebSocketProtocol = std::string(req->getHeader("sec-websocket-protocol")),
				.secWebSocketExtensions = std::string(req->getHeader("sec-websocket-extensions")),
				.context = context,
				.httpRes = res,
				.aborted = false
			});

			/* We have to attach an abort handler for us to be aware of disconnections while we perform task */
			res->onAborted([=]()
			{
				/* We don't implement any kind of cancellation here, so simply flag us as aborted */
				upgradeData->aborted = true;

				LOG_DEBUG("HTTP socket was closed before we upgraded it!");
			});

			bool bIsTokenValid = false;
			Uint64 TempUserId = 0;
			std::string_view TempClientIp;
			if (!AuthTokenValue.empty())
			{
				FProjectEngine* ProjectEngine = dynamic_cast<FProjectEngine*>(FGlobalDefines::GEngine);
				FUserManager* UserManager = ProjectEngine->GetUserManager();
				if (UserManager->VerifyToken(AuthTokenValue))
				{
					TempUserId = UserManager->GetIdFromToken(AuthTokenValue);
					bIsTokenValid = true;
				}
				else
				{
					TempClientIp = res->getRemoteAddressAsText();

					const FBackendSettings* Settings = ProjectEngine->GetBackendSettings();
					if (Settings != nullptr && Settings->GetTrustForwardedFor())
					{
						const std::string_view ForwardedHeader = req->getHeader("x-forwarded-for");
						if (!ForwardedHeader.empty())
						{
							TempClientIp = ForwardedHeader;
						}
					}

					ProjectEngine->GetAbuseProtection()->AddRateLimitedAttempt(std::string(TempClientIp));
				}
			}

			if (bIsTokenValid)
			{
				// Accept
				res->template upgrade<FWebSocketSessionData>(
					{
						.UserId = TempUserId,
						.ClientIP = TempClientIp,
						.SessionToken = AuthTokenValue
					},  // userData
					req->getHeader("sec-websocket-key"),
					req->getHeader("sec-websocket-protocol"),
					req->getHeader("sec-websocket-extensions"),
					context
				);
			}
			else
			{
				res->writeStatus("401 Unauthorized");
				res->end("Invalid auth token");
				return;
			}
		},
		.open = [Socket](auto* ws)
		{
			Socket->OnClientConnected(ws);
		},
		.message = [Socket](auto* ws, std::string_view message, uWS::OpCode opCode)
		{
			Socket->OnMessageReceived(ws, message, opCode);
		},
		.ping = [Socket](auto* ws, std::string_view message)
		{
			Socket->OnPing(ws);
		},
		.pong = [Socket](auto* ws, std::string_view message)
		{
			Socket->OnPong(ws);
		},
		.close = [Socket](auto* ws, int code, std::string_view message)
		{
			Socket->OnClientDisconnected(ws, code, message);
		}
	};
}

void FSocket::Async()
{
	static const char* WebSocketPath = "/api/v1/ws";

	if (bUseSSL)
	{
		SocketAppWrapper.wsssl<FWebSocketSessionData>(WebSocketPath, CreateSocketBehavior<true>(this));
	}
	else
	{
		SocketAppWrapper.wssslno<FWebSocketSessionData>(WebSocketPath, CreateSocketBehavior<false>(this));
	}

	SocketAppWrapper.listen(Host, Port, [&](us_listen_socket_t* listenSocket)
	{
		if (listenSocket != nullptr)
		{
			AppListenSocket = listenSocket;

			LOG_DEBUG("Server, id: '" << SocketIndex << "', listening host: '" << Host << "', on port: '" << Port << "'.");
		}
		else
		{
			LOG_ERROR("Failed to listen on: " << Host << "@" << Port << ", id: '" << SocketIndex << "'.");
		}
	});

	BeforeRunAsync();

	SocketAppWrapper.Run();
}

void FSocket::OnClientConnected(auto* ws)
{
	LOG_VERBOSE("Client connected");

	FWebSocketSessionData* WebSocketSessionData = ws->getUserData();
	if (WebSocketSessionData != nullptr)
	{
		AddWebSocketForConnectedUser(ws, WebSocketSessionData);

		FUserManager* UserManger = ProjectEngine->GetUserManager();
		const Uint64 ConnectedUserId = WebSocketSessionData->UserId;
		std::vector<std::shared_ptr<FUser>> OutUsers;
		UserManger->GetUsersByIds({ ConnectedUserId }, OutUsers);

		// Add subscribe action
		{
			// SUBSCRIBE to a topic named after the user ID
			// syntax: "user_<id>"
			const std::string UserTopic = GenerateUserTopic(ConnectedUserId);
			ws->subscribe(UserTopic);
		}

		std::string UserName;
		// Add per user information about Socket
		if (!OutUsers.empty())
		{
			// OutUsers array keeps pointer in this case
			FUser* User = OutUsers[0].get();
			if (User != nullptr)
			{
				User->SetSocketId(SocketIndex);
				User->SetUserStatus(EUserStatus::Online);
				UserName = User->GetUserNameString();
			}
		}

		// Send initial client data
		{
			nlohmann::json JsonData;
			JsonData["user_id"] = ConnectedUserId;

			if (!UserName.empty())
			{
				JsonData["user_display_name"] = UserName;
			}
			else
			{
				LOG_ERROR("Missing User! Id = '" << ConnectedUserId << "'.");
			}

			nlohmann::json JsonRoot;
			JsonRoot["type"] = SocketMessagePrivateTypeToString(ESocketMessagePrivateType::InitialClientData);
			JsonRoot["data"] = JsonData;

			// Send initial client data
			ws->send(JsonRoot.dump(), uWS::TEXT);
		}

		// Deliver the per-session image API key (issued at login) to this device.
		{
			FImageServiceManager* ImageServiceManager = UserManger->GetImageServiceManager();
			std::string ImageKey;
			if (ImageServiceManager != nullptr)
			{
				ImageKey = ImageServiceManager->GetKeyForSession(WebSocketSessionData->SessionToken);

				// If registration failed at login (e.g. service was briefly down),
				// try issuing the key again now.
				if (ImageKey.empty())
				{
					ImageKey = ImageServiceManager->RegisterKey(WebSocketSessionData->SessionToken);
				}
			}

			nlohmann::json KeyData;
			KeyData["key"] = ImageKey;
			KeyData["available"] = !ImageKey.empty();

			nlohmann::json KeyRoot;
			KeyRoot["type"] = SocketMessagePrivateTypeToString(ESocketMessagePrivateType::ImageApiKey);
			KeyRoot["section"] = SocketMessageSectionToString(ESocketMessageSection::Priv);
			KeyRoot["data"] = KeyData;

			ws->send(KeyRoot.dump(), uWS::TEXT);
		}

		// Update status to connected clients (friends)
		BroadcastUserStatus(UserManger, ConnectedUserId, EUserStatus::Online);

		// ALSO broadcast status to all server members
		if (!UserName.empty())
		{
			ServersSocketData.BroadcastMemberStatus(ConnectedUserId, UserName, EUserStatus::Online);
		}
	}
	else
	{
		LOG_ERROR("WebSocketSessionData is NULL!");
	}
}

void FSocket::OnClientDisconnected(auto* ws, int code, std::string_view message)
{
	LOG_VERBOSE("Client disconnected");

	FWebSocketSessionData* WebSocketSessionData = ws->getUserData();
	if (WebSocketSessionData != nullptr)
	{
		const Uint64 ConnectedUserId = WebSocketSessionData->UserId;

		RemoveWebSocketForDisconnectedUser(ConnectedUserId);

		FUserManager* UserManger = ProjectEngine->GetUserManager();
		std::vector<std::shared_ptr<FUser>> OutUsers;
		UserManger->GetUsersByIds({ ConnectedUserId }, OutUsers);

		std::string UserName;
		// Remove per user information about Socket
		if (!OutUsers.empty())
		{
			// OutUsers array keeps pointer in this case
			FUser* User = OutUsers[0].get();
			if (User != nullptr)
			{
				UserName = User->GetUserNameString();
				User->SetSocketId(-1);
				User->SetUserStatus(EUserStatus::Offline);
			}
		}

		// Update status to connected clients (friends)
		BroadcastUserStatus(UserManger, ConnectedUserId, EUserStatus::Offline);

		// ALSO broadcast status to all server members
		if (!UserName.empty())
		{
			ServersSocketData.BroadcastMemberStatus(ConnectedUserId, UserName, EUserStatus::Offline);
		}

		// Auto-remove from all voice channels on disconnect
		if (!UserName.empty())
		{
			ServersSocketData.CleanupUserVoiceChannels(ConnectedUserId, UserName);
		}
	}
}

void FSocket::OnMessageReceived(auto* ws, std::string_view message, uWS::OpCode opCode)
{
	switch (opCode)
	{
		case uWS::CONTINUATION:
		{
			break;
		}
		case uWS::TEXT:
		{
			OnMessageReceived_TEXT(ws, message, opCode);

			break;
		}
		case uWS::BINARY:
		{
			break;
		}
		case uWS::CLOSE:
		{
			break;
		}
		case uWS::PING:
		{
			OnMessageReceived_Ping(ws, message, opCode);

			break;
		}
		case uWS::PONG:
		{
			OnMessageReceived_Pong(ws, message, opCode);

			break;
		}
	}
}

void FSocket::OnPing(auto* ws)
{
#if DEBUG
	LOG_DEBUG("Received ping");
#endif
}

void FSocket::OnPong(auto* ws)
{
#if DEBUG
	LOG_DEBUG("Received pong");
#endif
}

void FSocket::EarlyExit(AnyWebSocket wsVariant, const char* Message, uWS::OpCode opCode)
{
	nlohmann::json ErrorJson;
	ErrorJson["type"] = SocketMessagePrivateTypeToString(ESocketMessagePrivateType::Error);
	ErrorJson["message"] = Message;

	std::visit([&](auto* ws)
	{
		// Send data
		ws->send(ErrorJson.dump(), opCode);
	}, wsVariant);
}

std::string FSocket::GenerateUserTopic(const Uint64 UserId)
{
	return "user_" + std::to_string(UserId);
}

std::string FSocket::GenerateVoiceRoomNameFromIds(std::vector<Uint64> IdArray)
{
	// Sort array to get always same order of ids and same name regardless of which Id is first
	std::ranges::sort(IdArray);

	std::string OutString = "priv_voice_";

	for (const Uint64 Id : IdArray)
	{
		OutString += std::to_string(Id);
	}

	return OutString;
}

void FSocket::OnMessageReceived_TEXT(auto* ws, std::string_view message, uWS::OpCode opCode)
{
	LOG_VERBOSE("Received: " << message);

	// --- Two-tier global rate limit: WebSocket connections are always authenticated ---
	// Per-UserID rate limit (Tier 2). Each token/user gets their own quota.
	{
		FWebSocketSessionData* WebSocketSessionData = ws->getUserData();
		if (WebSocketSessionData != nullptr)
		{
			const std::string UserIdStr = std::to_string(WebSocketSessionData->UserId);
			FAbuseProtection* AbuseProtection = ProjectEngine->GetAbuseProtection();

			if (AbuseProtection->IsAuthenticatedUserBlocked(UserIdStr))
			{
				nlohmann::json ErrorJson;
				ErrorJson["type"] = "error";
				ErrorJson["message"] = "Global rate limit exceeded";

				ws->send(ErrorJson.dump(), opCode);
				return;
			}
			AbuseProtection->AddAuthenticatedUserAttempt(UserIdStr);
		}
	}

	try
	{
		nlohmann::json JsonMessage = nlohmann::json::parse(message);

		if (!JsonMessage.contains("section"))
		{
#if DEBUG
			LOG_ERROR("Message does not contain type");
#endif

			EarlyExit(ws, "missing section", opCode);

			return;
		}

		const std::string JSONSection = JsonMessage["section"];
		const ESocketMessageSection Section = StringToSocketMessageSection(JSONSection);
		switch (Section)
		{
			case ESocketMessageSection::Priv:
			{
				PrivateSocketData.PrimarySwitch(ws, JsonMessage, opCode);

				break;
			}

			case ESocketMessageSection::Servers:
			{
				ServersSocketData.PrimarySwitch(ws, JsonMessage, opCode);

				break;
			}

			default:
			{
#if DEBUG
				LOG_ERROR("JSON unknown case for section: '" << JSONSection << "'.");
#endif

				EarlyExit(ws, "error", opCode);
			}
		}
	}
	catch (const nlohmann::json::exception& e)
	{
#if DEBUG
		LOG_ERROR("JSON error: " << e.what());
#endif

		EarlyExit(ws, "j-error", opCode);
	}
}

void FSocket::OnMessageReceived_Ping(auto* ws, std::string_view message, uWS::OpCode opCode)
{
	if (opCode == uWS::PING)
	{
		// Pong back
		ws->send(message, uWS::PONG);

		// Update status
		FWebSocketSessionData* WebSocketSessionData = ws->getUserData();
		if (WebSocketSessionData != nullptr)
		{
			const Uint64& ConnectionUserId = WebSocketSessionData->UserId;
			FUserManager* UserManager = ProjectEngine->GetUserManager();
			UserManager->UpdateUserActivity(ConnectionUserId);
		}
	}
}

void FSocket::OnMessageReceived_Pong(auto* ws, std::string_view message, uWS::OpCode opCode)
{
	// Protocol-level pong: update activity timestamp to keep connection alive
	if (opCode == uWS::PONG)
	{
		// Update status
		FWebSocketSessionData* WebSocketSessionData = ws->getUserData();
		if (WebSocketSessionData != nullptr)
		{
			const Uint64& ConnectionUserId = WebSocketSessionData->UserId;
			FUserManager* UserManager = ProjectEngine->GetUserManager();
			UserManager->UpdateUserActivity(ConnectionUserId);
		}
	}
}

void FSocket::AddWebSocketForConnectedUser(auto* ws, FWebSocketSessionData* WebSocketSessionData)
{
	std::unique_lock<std::shared_mutex> Lock(UserIdToWebSocketPtrMapMutex);
	UserIdToWebSocketPtrMap[WebSocketSessionData->UserId] = ws;
}

void FSocket::RemoveWebSocketForDisconnectedUser(const Uint64 UserId)
{
	std::unique_lock<std::shared_mutex> Lock(UserIdToWebSocketPtrMapMutex);
	UserIdToWebSocketPtrMap.Remove(UserId);
}

void FSocket::BroadcastUserStatus(FUserManager* UserManger, const Uint64 ConnectedUserId, EUserStatus NewUserStatus)
{
	FFriendListManager* FriendListManager = ProjectEngine->GetFriendListManager();
	const std::vector<Uint64> FriendListArray = FriendListManager->GetFriendsListArrayByUserId(ConnectedUserId);

	std::vector<std::shared_ptr<FUser>> OutUsers;
	OutUsers.reserve(FriendListArray.size());

	// @TODO: It would be better to just keep this map than iterate each time
	// But this is not really important for now
	std::unordered_map<Uint64, std::shared_ptr<FUser>> FriendListMap;
	UserManger->GetUsersByIds(FriendListArray, OutUsers);

	for (const std::shared_ptr<FUser>& OutUser : OutUsers)
	{
		FriendListMap[OutUser->GetUserId()] = OutUser;
	}

	for (const Uint64 FriendID : FriendListArray)
	{
		FFunctorLambda<void, void*> SocketAccessFunctor = [ConnectedUserId, NewUserStatus](void* ws2)
		{
			auto* WebSocket = static_cast<uWS::WebSocket<false, true, FUserSessionData>*>(ws2);

			nlohmann::json MessageJson;
			MessageJson["user_id"] = ConnectedUserId;
			MessageJson["status"] = UserStatusToString(NewUserStatus);

			nlohmann::json JsonRoot;
			JsonRoot["type"] = SocketMessagePrivateTypeToString(ESocketMessagePrivateType::UserStatus);
			JsonRoot["section"] = SocketMessageSectionToString(ESocketMessageSection::Priv);
			JsonRoot["data"] = MessageJson;

			// Send initial client data
			WebSocket->send(JsonRoot.dump(), uWS::TEXT);
		};

		//AddDeferTaskForConnectionId(FriendID, SocketAccessFunctor);
		FSocketManager* SocketManager = ProjectEngine->GetSocketManager();

		const std::shared_ptr<FUser> UserPtr = FriendListMap[FriendID];
		if (UserPtr != nullptr && UserPtr->GetUserStatus() == EUserStatus::Online)
		{
			SocketManager->EnqueueTaskForUserAtSocket(UserPtr->GetSocketId(), FriendID, SocketAccessFunctor);
		}
	}
}
