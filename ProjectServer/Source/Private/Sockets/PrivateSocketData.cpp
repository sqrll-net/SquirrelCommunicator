// Created by https://www.linkedin.com/in/przemek2122/ 2026

#include "Sockets/PrivateSocketData.h"
#include "Sockets/WebSocketSessionData.h"
#include "ProjectEngine.h"
#include "Auth/User.h"
#include "Auth/UserManager.h"
#include "DataBase/DataBaseConnect.h"
#include "Managers/ConversationsManager.h"
#include "Managers/RoomsServiceManager.h"
#include "nlohmann/json.hpp"
#include "soci/statement.h"
#include "Sockets/SocketManager.h"

FPrivateSocketData::FPrivateSocketData(FSocket* InSocket)
	: Socket(InSocket)
	, ProjectEngine(Socket->GetProjectEngine())
{
}

void FPrivateSocketData::PrimarySwitch(AnyWebSocket wsVariant, nlohmann::json& JsonMessage, uWS::OpCode opCode)
{
	if (!JsonMessage.contains("type"))
	{
#if DEBUG
		LOG_ERROR("Message does not contain type");
#endif

		FSocket::EarlyExit(wsVariant, "missing type", opCode);

		// Handle error
		return;
	}

	if (!JsonMessage.contains("data"))
	{
#if DEBUG
		LOG_ERROR("Message does not contain data");
#endif

		FSocket::EarlyExit(wsVariant, "missing data", opCode);

		// Handle error
		return;
	}

	const std::string SocketMessageTypeStr = JsonMessage["type"];
	const ESocketMessagePrivateType SocketMessage = StringToSocketMessagePrivateType(SocketMessageTypeStr);

	switch (SocketMessage)
	{
		case ESocketMessagePrivateType::Message:
		{
			if (JsonMessage["data"].contains("conversation_id") && JsonMessage["data"].contains("content"))
			{
				const std::string ConversationIdString = JsonMessage["data"]["conversation_id"];
				const Uint64 ConversationId = std::stoull(ConversationIdString);
				const std::string Content = JsonMessage["data"]["content"];

				// Optional message type discriminator ("text"/"image"/"gif"/"video"). Defaults to text.
				EMessageType MessageType = EMessageType::Text;
				if (JsonMessage["data"].contains("message_type"))
				{
					MessageType = StringToMessageType(JsonMessage["data"]["message_type"].get<std::string>());
				}

				// Handle send message
				OnMessageReceived_Message(wsVariant, opCode, ConversationId, Content, MessageType);
			}
			else
			{
				FSocket::EarlyExit(wsVariant, "missing data", opCode);
			}

			break;
		}

		case ESocketMessagePrivateType::MessageEdit:
		{
			if (JsonMessage["data"].contains("conversation_id") && JsonMessage["data"].contains("message_id") && JsonMessage["data"].contains("content"))
			{
				const std::string ConversationIdString = JsonMessage["data"]["conversation_id"];
				const Uint64 ConversationId = std::stoull(ConversationIdString);
				const std::string Content = JsonMessage["data"]["content"];
				const std::string MessageIdString = JsonMessage["data"]["message_id"];
				const Uint64 MessageId = std::stoull(MessageIdString);

				OnMessageReceived_MessageEdit(wsVariant, opCode, ConversationId, MessageId, Content);
			}
			else
			{
				FSocket::EarlyExit(wsVariant, "missing data", opCode);
			}

			break;
		}

		case ESocketMessagePrivateType::MessageDelete:
		{
			if (JsonMessage["data"].contains("conversation_id") && JsonMessage["data"].contains("message_id"))
			{
				const std::string ConversationIdString = JsonMessage["data"]["conversation_id"];
				const Uint64 ConversationId = std::stoull(ConversationIdString);

				Uint64 MessageId = 0;
				if (JsonMessage["data"]["message_id"].is_string())
				{
					MessageId = std::stoull(JsonMessage["data"]["message_id"].get<std::string>());
				}
				else
				{
					MessageId = JsonMessage["data"]["message_id"].get<Uint64>();
				}

				OnMessageReceived_MessageDelete(wsVariant, opCode, ConversationId, MessageId);
			}
			else
			{
				FSocket::EarlyExit(wsVariant, "missing data", opCode);
			}

			break;
		}

		case ESocketMessagePrivateType::Typing:
		{
			if (JsonMessage["data"].contains("conversationId"))
			{
				const Uint64 ConversationId = JsonMessage["data"]["conversationId"];

				// Handle typing
				OnMessageReceived_Typing(wsVariant, opCode, ConversationId);
			}
			else
			{
				FSocket::EarlyExit(wsVariant, "missing data", opCode);
			}

			break;
		}

		case ESocketMessagePrivateType::MessageRead:
		{
			if (JsonMessage["data"].contains("conversationId"))
			{
				Uint64 ConversationId = JsonMessage["data"]["conversationId"];

				// Handle mark read
				OnMessageReceived_MessageRead(wsVariant, opCode, ConversationId);
			}
			else
			{
				FSocket::EarlyExit(wsVariant, "missing data", opCode);
			}

			break;
		}

		case ESocketMessagePrivateType::SearchUser:
		{
			if (JsonMessage["data"].contains("search_target"))
			{
				const std::string Pattern = JsonMessage["data"]["search_target"];

				OnMessageReceived_SearchUser(wsVariant, opCode, Pattern);
			}
			else
			{
				FSocket::EarlyExit(wsVariant, "missing data", opCode);
			}

			break;
		}

		case ESocketMessagePrivateType::LoadMoreMessages:
		{
			FWebSocketSessionData* WebSocketSessionData = nullptr;

			std::visit([&](auto* ws)
			{
				WebSocketSessionData = ws->getUserData();
			}, wsVariant);

			if (WebSocketSessionData != nullptr)
			{
				if (JsonMessage["data"].contains("conversation_id") && JsonMessage["data"].contains("offset") && JsonMessage["data"].contains("limit"))
				{
					const std::string ConversationIdString = JsonMessage["data"]["conversation_id"];
					const std::string OffsetString = JsonMessage["data"]["offset"];
					const std::string LimitString = JsonMessage["data"]["limit"];
					const Uint64 ConversationId = atoi(ConversationIdString.c_str());
					const int32 Offset = atoi(OffsetString.c_str());
					const int32 Limit = atoi(LimitString.c_str());

					OnMessageReceived_LoadMoreMessages(wsVariant, opCode, ConversationId, WebSocketSessionData->UserId, Offset, Limit);
				}
				else
				{
					FSocket::EarlyExit(wsVariant, "missing data", opCode);
				}
			}

			break;
		}

		case ESocketMessagePrivateType::GetConversations:
		{
			FWebSocketSessionData* WebSocketSessionData = nullptr;

			std::visit([&](auto* ws)
			{
				WebSocketSessionData = ws->getUserData();
			}, wsVariant);

			if (WebSocketSessionData != nullptr)
			{
				if (JsonMessage["data"].contains("offset") && JsonMessage["data"].contains("limit"))
				{
					const std::string OffsetString = JsonMessage["data"]["offset"];
					const std::string LimitString = JsonMessage["data"]["limit"];
					const int32 Offset = atoi(OffsetString.c_str());
					const int32 Limit = atoi(LimitString.c_str());

					OnMessageReceived_GetConversations(wsVariant, opCode, WebSocketSessionData->UserId, Offset, Limit);
				}
				else
				{
					FSocket::EarlyExit(wsVariant, "missing data", opCode);
				}
			}

			break;
		}

		case ESocketMessagePrivateType::AddConversation:
		{
			if (JsonMessage["data"].contains("user_id"))
			{
				const std::string OtherUserIdAsString = JsonMessage["data"]["user_id"];
				const Uint64 OtherUserId = atoi(OtherUserIdAsString.c_str());

				OnMessageReceived_AddConversation(wsVariant, opCode, OtherUserId);
			}
			else
			{
				FSocket::EarlyExit(wsVariant, "missing data", opCode);
			}

			break;
		}

		case ESocketMessagePrivateType::GetFriendList:
		{
			if (JsonMessage["data"].contains("offset") && JsonMessage["data"].contains("limit"))
			{
				const std::string OffsetString = JsonMessage["data"]["offset"];
				const std::string LimitString = JsonMessage["data"]["limit"];

				const int32 Offset = atoi(OffsetString.c_str());
				const int32 Limit = atoi(LimitString.c_str());

				OnMessageReceived_GetFriendList(wsVariant, opCode, Offset, Limit);
			}
			else
			{
				FSocket::EarlyExit(wsVariant, "missing data", opCode);
			}

			break;
		}

		case ESocketMessagePrivateType::GetFriendRequestList:
		{
			if (JsonMessage["data"].contains("offset") && JsonMessage["data"].contains("limit"))
			{
				const std::string OffsetString = JsonMessage["data"]["offset"];
				const std::string LimitString = JsonMessage["data"]["limit"];

				const int32 Offset = atoi(OffsetString.c_str());
				const int32 Limit = atoi(LimitString.c_str());

				OnMessageReceived_GetFriendRequestsList(wsVariant, opCode, Offset, Limit);
			}
			else
			{
				FSocket::EarlyExit(wsVariant, "missing data", opCode);
			}

			break;
		}

		case ESocketMessagePrivateType::CreateFriendRequest:
		{
			if (JsonMessage["data"].contains("other_id"))
			{
				const std::string OtherUserIdAsString = JsonMessage["data"]["other_id"];
				const Uint64 OtherUserId = atoi(OtherUserIdAsString.c_str());

				OnMessageReceived_CreateFriendRequest(wsVariant, opCode, OtherUserId);
			}
			else
			{
				FSocket::EarlyExit(wsVariant, "missing data", opCode);
			}

			break;
		}

		case ESocketMessagePrivateType::AcceptFriendRequest:
		{
			if (JsonMessage["data"].contains("other_id"))
			{
				const std::string OtherUserIdAsString = JsonMessage["data"]["other_id"];
				const Uint64 OtherUserId = atoi(OtherUserIdAsString.c_str());

				OnMessageReceived_AcceptFriendRequest(wsVariant, opCode, OtherUserId);
			}
			else
			{
				FSocket::EarlyExit(wsVariant, "missing data", opCode);
			}

			break;
		}

		case ESocketMessagePrivateType::RejectFriendRequest:
		{
			if (JsonMessage["data"].contains("other_id"))
			{
				const std::string OtherUserIdAsString = JsonMessage["data"]["other_id"];
				const Uint64 OtherUserId = atoi(OtherUserIdAsString.c_str());

				OnMessageReceived_RejectFriendRequest(wsVariant, opCode, OtherUserId);
			}
			else
			{
				FSocket::EarlyExit(wsVariant, "missing data", opCode);
			}

			break;
		}

		case ESocketMessagePrivateType::CancelFriendRequest:
		{
			if (JsonMessage["data"].contains("other_id"))
			{
				const std::string OtherUserIdAsString = JsonMessage["data"]["other_id"];
				const Uint64 OtherUserId = atoi(OtherUserIdAsString.c_str());

				OnMessageReceived_CancelFriendRequest(wsVariant, opCode, OtherUserId);
			}
			else
			{
				FSocket::EarlyExit(wsVariant, "missing data", opCode);
			}

			break;
		}

		case ESocketMessagePrivateType::RemoveFriend:
		{
			if (JsonMessage["data"].contains("other_id"))
			{
				const std::string OtherUserIdAsString = JsonMessage["data"]["other_id"];
				const Uint64 OtherUserId = atoi(OtherUserIdAsString.c_str());

				OnMessageReceived_RemoveFriend(wsVariant, opCode, OtherUserId);
			}
			else
			{
				FSocket::EarlyExit(wsVariant, "missing data", opCode);
			}

			break;
		}

		case ESocketMessagePrivateType::DataStreamChannel:
		{
			if (JsonMessage["data"].contains("other_id"))
			{
				const std::string OtherUserIdAsString = JsonMessage["data"]["other_id"];
				const Uint64 OtherUserId = atoi(OtherUserIdAsString.c_str());

				OnMessageReceived_DataStreamChannel(wsVariant, opCode, OtherUserId);
			}
			else
			{
				FSocket::EarlyExit(wsVariant, "missing data", opCode);
			}

			break;
		}

		case ESocketMessagePrivateType::UserCalling:
		{
			if (JsonMessage["data"].contains("other_id"))
			{
				const std::string OtherUserIdAsString = JsonMessage["data"]["other_id"];
				const Uint64 OtherUserId = atoi(OtherUserIdAsString.c_str());

				OnMessageReceived_OnUserCalling(wsVariant, opCode, OtherUserId);
			}
			else
			{
				FSocket::EarlyExit(wsVariant, "missing data", opCode);
			}

			break;
		}

		/** Ping/Pong — application-level latency measurement and keep-alive */
		case ESocketMessagePrivateType::Ping:
		{
			// Echo client's timestamp if provided, plus server time, for RTT calculation
			const auto NowUs = std::chrono::duration_cast<std::chrono::microseconds>(
				std::chrono::system_clock::now().time_since_epoch()).count();

			Uint64 ClientTimestamp = 0;
			if (JsonMessage["data"].contains("timestamp"))
			{
				if (JsonMessage["data"]["timestamp"].is_string())
					ClientTimestamp = std::stoull(JsonMessage["data"]["timestamp"].get<std::string>());
				else
					ClientTimestamp = JsonMessage["data"]["timestamp"].get<Uint64>();
			}

			nlohmann::json PongJson;
			PongJson["type"] = SocketMessagePrivateTypeToString(ESocketMessagePrivateType::Pong);
			PongJson["data"]["client_timestamp"] = ClientTimestamp;
			PongJson["data"]["server_timestamp"] = NowUs;

			std::visit([&](auto* ws)
			{
				ws->send(PongJson.dump(), uWS::TEXT);
			}, wsVariant);

			break;
		}

		/** Errors */
		case ESocketMessagePrivateType::Unknown:
		default:
		{
			// Send error
			nlohmann::json ErrorJson;
			ErrorJson["type"] = SocketMessagePrivateTypeToString(ESocketMessagePrivateType::Error);
			ErrorJson["message"] = "Unknown message type";

			std::visit([&](auto* ws)
			{
				// Send data
				ws->send(ErrorJson.dump(), opCode);
			}, wsVariant);

			break;
		}
	}
}

void FPrivateSocketData::OnMessageReceived_Message(AnyWebSocket wsVariant, uWS::OpCode opCode, const Uint64 ConversationId, const std::string& Content, const EMessageType MessageType)
{
	std::visit([&](auto* ws)
	{
		FWebSocketSessionData* WebSocketSessionData = ws->getUserData();
		if (WebSocketSessionData != nullptr)
		{
			if (Content.size() > ProjectEngine->GetBackendSettings()->GetMaxMessageSize())
			{
				FSocket::EarlyExit(wsVariant, "Message too large", opCode);

				return;
			}

			// Media messages must reference the content-addressable image service by a
			// well-formed SHA-256 hash. This is what makes media "verified" server-side.
			if (MessageType != EMessageType::Text && !IsValidSha256Hex(Content))
			{
				FSocket::EarlyExit(wsVariant, "invalid media hash", opCode);

				return;
			}

			FConversationsManager* ConversationsManager = ProjectEngine->GetConversationsManager();
			std::shared_ptr<FConversationData> Conversation = ConversationsManager->GetConversation(ConversationId);
			const Uint64& ConnectionUserId = WebSocketSessionData->UserId;
			if (Conversation != nullptr)
			{
				// SECURITY (authorization): only actual conversation participants may post.
				if (!ConversationsManager->IsUserInConversation(ConnectionUserId, ConversationId))
				{
					FSocket::EarlyExit(wsVariant, "not a member of this conversation", opCode);
					return;
				}

				const Uint64 OutId = ConversationsManager->AddMessage(ConversationId, ConnectionUserId, Content, MessageType);

				// Build the message payload used for both direct confirmation and broadcast
				nlohmann::json MessageJson;
				MessageJson["sender_id"] = ConnectionUserId;
				MessageJson["message_id"] = OutId;
				MessageJson["conversation_id"] = ConversationId;
				MessageJson["conversation_message"] = Content;
				MessageJson["message_type"] = MessageTypeToString(MessageType);

				// 1) Send immediate confirmation back to the sender
				//    This is consistent with every other handler (CreateFriendRequest, etc.)
				//    that sends a direct ws->send() response to the requester.
				nlohmann::json ConfirmJson;
				ConfirmJson["type"] = SocketMessagePrivateTypeToString(ESocketMessagePrivateType::Message);
				ConfirmJson["message"] = MessageJson;
				ConfirmJson["message"]["status"] = "sent";

				ws->send(ConfirmJson.dump(), opCode);

				// 2) Broadcast to all conversation members (including sender, so they
				//    also get the echo without the "status":"sent" marker if desired —
				//    but sender already has the confirmation above, so this is fine).
				nlohmann::json JsonRoot;
				JsonRoot["type"] = SocketMessagePrivateTypeToString(ESocketMessagePrivateType::Message);
				JsonRoot["message"] = MessageJson;

				FSocketManagerHelper::BroadcastDataToUsers(ProjectEngine, Conversation->UsersIds.Vector(), JsonRoot.dump());
			}
		}
	}, wsVariant);
}

void FPrivateSocketData::OnMessageReceived_MessageEdit(AnyWebSocket wsVariant, uWS::OpCode opCode, const Uint64 ConversationId, Uint64 MessageId, const std::string& Content)
{
	std::visit([&](auto* ws)
	{
		FWebSocketSessionData* WebSocketSessionData = ws->getUserData();
		if (WebSocketSessionData != nullptr)
		{
			FConversationsManager* ConversationManager = ProjectEngine->GetConversationsManager();
			const Uint64 ConnectionUserId = WebSocketSessionData->UserId;

			// Check if ConnectionUserId belongs to conversation by ConversationId (also check if conversation even exists)
			if (ConversationManager->IsUserInConversation(ConnectionUserId, ConversationId))
			{
				// Check if message belongs to given conversation
				if (ConversationManager->IsMessageInConversation(MessageId, ConversationId))
				{
					ConversationManager->EditMessage(ConnectionUserId, ConversationId, MessageId, Content);

					std::shared_ptr<FConversationData> Conversation = ConversationManager->GetConversation(ConversationId);
	                if (Conversation != nullptr)
	                {
						nlohmann::json MessageJson;
						MessageJson["message_id"] = MessageId;
						MessageJson["conversation_id"] = ConversationId;
						MessageJson["conversation_message"] = Content;

						nlohmann::json JsonRoot;
						JsonRoot["type"] = SocketMessagePrivateTypeToString(ESocketMessagePrivateType::MessageEdit);
						JsonRoot["message"] = MessageJson;

						FSocketManagerHelper::BroadcastDataToUsers(ProjectEngine, Conversation->UsersIds.Vector(), JsonRoot.dump());
	                }
				}
			}
		}
	}, wsVariant);
}

void FPrivateSocketData::OnMessageReceived_MessageDelete(AnyWebSocket wsVariant, uWS::OpCode opCode, const Uint64 ConversationId, const Uint64 MessageId)
{
	std::visit([&](auto* ws)
	{
		FWebSocketSessionData* WebSocketSessionData = ws->getUserData();
		if (WebSocketSessionData != nullptr)
		{
			FConversationsManager* ConversationManager = ProjectEngine->GetConversationsManager();
			const Uint64 ConnectionUserId = WebSocketSessionData->UserId;

			// Check if ConnectionUserId belongs to conversation by ConversationId (also check if conversation even exists)
			if (ConversationManager->IsUserInConversation(ConnectionUserId, ConversationId))
			{
				// Check if message belongs to given conversation
				if (ConversationManager->IsMessageInConversation(MessageId, ConversationId))
				{
					// Soft-delete: only the author's own message (enforced in DB).
					// Returns false if unauthorized or missing.
					if (ConversationManager->DeleteMessage(ConnectionUserId, ConversationId, MessageId))
					{
						std::shared_ptr<FConversationData> Conversation = ConversationManager->GetConversation(ConversationId);
						if (Conversation != nullptr)
						{
							nlohmann::json MessageJson;
							MessageJson["message_id"] = MessageId;
							MessageJson["conversation_id"] = ConversationId;
							MessageJson["conversation_message"] = std::string(DeletedMessagePlaceholder);
							MessageJson["status"] = static_cast<int>(EConversationMessageStatus::Deleted);

							nlohmann::json JsonRoot;
							JsonRoot["type"] = SocketMessagePrivateTypeToString(ESocketMessagePrivateType::MessageDelete);
							JsonRoot["message"] = MessageJson;

							FSocketManagerHelper::BroadcastDataToUsers(ProjectEngine, Conversation->UsersIds.Vector(), JsonRoot.dump());
						}
					}
				}
			}
		}
	}, wsVariant);
}

void FPrivateSocketData::OnMessageReceived_Typing(AnyWebSocket wsVariant, uWS::OpCode opCode, const Uint64 ConversationId)
{
	std::visit([&](auto* ws)
	{
		FWebSocketSessionData* WebSocketSessionData = ws->getUserData();
		if (WebSocketSessionData != nullptr)
		{
			const Uint64& ConnectionUserId = WebSocketSessionData->UserId;
			FConversationsManager* ConversationsManager = ProjectEngine->GetConversationsManager();
			FSocketManager* SocketManager = ProjectEngine->GetSocketManager();
			FUserManager* UserManager = ProjectEngine->GetUserManager();
			std::shared_ptr<FConversationData> Conversation = ConversationsManager->GetConversation(ConversationId);

			if (Conversation == nullptr || !ConversationsManager->IsUserInConversation(ConnectionUserId, ConversationId))
			{
				return;
			}

			std::vector<std::shared_ptr<FUser>> Users;
			UserManager->GetUsersByIds(Conversation->UsersIds.Vector(), Users);

			nlohmann::json MessageJson;
			MessageJson["conversation_id"] = ConversationId;
			MessageJson["typing_id"] = ConnectionUserId;

			nlohmann::json JsonRoot;
			JsonRoot["type"] = SocketMessagePrivateTypeToString(ESocketMessagePrivateType::Typing);
			JsonRoot["message"] = MessageJson;

			for (std::shared_ptr<FUser>& User : Users)
			{
				if (User->GetUserId() != ConnectionUserId)
				{
					FFunctorLambda<void, void*> SocketAccessFunctor = [this, JsonRoot, User](void* ws)
					{
						auto* WebSocket = static_cast<uWS::WebSocket<false, true, FUserSessionData>*>(ws);

						// To send message to a specific user
						const std::string UserTopic = FSocket::GenerateUserTopic(User->GetUserId());
						if (WebSocket->isSubscribed(UserTopic))
						{
							WebSocket->send(JsonRoot.dump(), uWS::OpCode::TEXT);
						}
					};
					SocketManager->EnqueueTaskForUserAtSocket(User->GetSocketId(), User->GetUserId(), SocketAccessFunctor);
				}
			}
		}
	}, wsVariant);
}

void FPrivateSocketData::OnMessageReceived_MessageRead(AnyWebSocket wsVariant, uWS::OpCode opCode, const Uint64 ConversationId)
{
	std::visit([&](auto* ws)
	{
		FWebSocketSessionData* WebSocketSessionData = ws->getUserData();
		if (WebSocketSessionData != nullptr)
		{
			FConversationsManager* ConversationsManager = ProjectEngine->GetConversationsManager();
			const Uint64 ConnectionUserId = WebSocketSessionData->UserId;

			if (std::shared_ptr<FConversationData> ConversationPtr = ConversationsManager->GetConversation(ConversationId))
			{
				// Verify that ConnectionUserId is in conversation
				if (ConversationPtr->UsersIds.Contains(ConnectionUserId))
				{
					FSocketManager* SocketManager = ProjectEngine->GetSocketManager();

					for (const Uint64 UsersId : ConversationPtr->UsersIds)
					{
						if (UsersId != ConnectionUserId)
						{
							nlohmann::json MessageJson;
							MessageJson["conversation_id"] = ConversationId;
							MessageJson["typing_id"] = ConnectionUserId;

							nlohmann::json JsonRoot;
							JsonRoot["type"] = SocketMessagePrivateTypeToString(ESocketMessagePrivateType::MessageRead);
							JsonRoot["message"] = MessageJson;

							const std::shared_ptr<FUser> User = ProjectEngine->GetUserManager()->GetUserById(ConnectionUserId);

							const int32 SocketId = User->GetSocketId();

							FFunctorLambda<void, void*> SocketAccessFunctor = [this, JsonRoot, ConnectionUserId](void* ws)
							{
								auto* WebSocket = static_cast<uWS::WebSocket<false, true, FUserSessionData>*>(ws);

								// To send message to a specific user
								const std::string UserTopic = FSocket::GenerateUserTopic(ConnectionUserId);
								if (WebSocket->isSubscribed(UserTopic))
								{
									WebSocket->send(JsonRoot.dump(), uWS::OpCode::TEXT);
								}
							};
							SocketManager->EnqueueTaskForUserAtSocket(SocketId, ConnectionUserId, SocketAccessFunctor);
						}
					}
				}
			}
		}
	}, wsVariant);
}

void FPrivateSocketData::OnMessageReceived_SearchUser(AnyWebSocket wsVariant, uWS::OpCode opCode, const std::string& Pattern)
{
	std::visit([&](auto* ws)
	{
		if (!Pattern.empty())
		{
			FDataBaseConnect Connect;
			if (Connect.IsConnected())
			{
				// Get database connection session
				soci::session& DataBaseSession = Connect.GetSession();

				static constexpr Uint32 SearchResults = 20;

				std::string PatternQuery = "%" + Pattern + "%";

				struct FDataBaseUserStruct
				{
					Uint64 UserId;
					std::string UserName;
					std::string DisplayName;
				};

				std::vector<std::string> UserNames;
				std::vector<Uint64> UserIds;

				UserNames.reserve(SearchResults);
				UserIds.reserve(SearchResults);

				Uint64 UserId;
				std::string UserName;

				// Try with id
				try
				{
					soci::statement St = (DataBaseSession.prepare <<
						"SELECT id, username "
						"FROM users "
						"WHERE id = :PatternQuery "
						"LIMIT 2",
						soci::into(UserId),      // Bind output variables
						soci::into(UserName),    // before execution
						soci::use(PatternQuery));

					St.execute();

					while (St.fetch())  // Fetch populates the bound variables
					{
						UserIds.push_back(UserId);
						UserNames.push_back(UserName);
					}
				}
				catch (const nlohmann::json::exception& e)
				{
					LOG_ERROR("Database error (id search): " << e.what());
				}

				// Try with username
				if (UserNames.empty())
				{
					try
					{
						soci::statement St = (DataBaseSession.prepare <<
							"SELECT id, username "
							"FROM users "
							"WHERE username LIKE :PatternQuery "
							"LIMIT 20",
							soci::into(UserId),      // Bind output variables
							soci::into(UserName),    // before execution
							soci::use(PatternQuery));

						St.execute();

						while (St.fetch())  // Fetch populates the bound variables
						{
							UserIds.push_back(UserId);
							UserNames.push_back(UserName);
						}
					}
					catch (const nlohmann::json::exception& e)
					{
						LOG_ERROR("Database error (username search): " << e.what());
					}
				}

				const nlohmann::json UsersJson = FormatUsersToJson(UserIds, UserNames);
				const std::string JsonString = UsersJson.dump();

				nlohmann::json ReturnJson;
				ReturnJson["type"] = SocketMessagePrivateTypeToString(ESocketMessagePrivateType::SearchUser);
				ReturnJson["message"] = JsonString;
				ws->send(ReturnJson.dump(), opCode);
			}
		}
	}, wsVariant);
}

void FPrivateSocketData::OnMessageReceived_LoadMoreMessages(AnyWebSocket wsVariant, uWS::OpCode opCode, Uint64 ConversationId, Uint64 CurrentUserId, int32 Offset, int32 Count)
{
	std::visit([&](auto* ws)
	{
		nlohmann::json JsonRoot;
		JsonRoot["type"] = SocketMessagePrivateTypeToString(ESocketMessagePrivateType::LoadMoreMessages);

		if (ConversationId > 0 && Offset > 0 && Count > 0)
		{
			FConversationsManager* ConversationsManager = ProjectEngine->GetConversationsManager();
			std::shared_ptr<FConversationData> Conversation = ConversationsManager->GetConversation(ConversationId);
			if (Conversation != nullptr && Conversation->UsersIds.Contains(CurrentUserId))
			{
				std::vector<FConversationMessageData> MessagesInRange = ConversationsManager->GetConversationMessagesForRange(Conversation, Offset, Count);
				if (!MessagesInRange.empty())
				{
					JsonRoot["status"] = "success";

					nlohmann::json MessagesJsonArray = nlohmann::json::array();

					for (FConversationMessageData& Message : MessagesInRange | std::views::reverse)
					{
						nlohmann::json NewMessage;
						NewMessage["message"] = Message.Message;
						NewMessage["sender_id"] = Message.SenderId;
						NewMessage["message_type"] = MessageTypeToString(Message.MessageType);

						MessagesJsonArray.push_back(NewMessage);
					}

					JsonRoot["message"] = MessagesJsonArray;
				}
				else
				{
					JsonRoot["status"] = "no_more_messages";
					JsonRoot["message"] = "No messages in range.";
				}
			}
			else
			{
				JsonRoot["status"] = "unauthorized";
				JsonRoot["message"] = "Chat not suitable for user.";
			}
		}
		else
		{
			JsonRoot["status"] = "wrong_input";
			JsonRoot["message"] = "One of input parameters: ConversationId, Offset, Count is wrong.";
		}

		ws->send(JsonRoot.dump(), uWS::TEXT);

	}, wsVariant);
}

void FPrivateSocketData::OnMessageReceived_GetConversations(AnyWebSocket wsVariant, uWS::OpCode opCode, Uint64 CurrentUserId, int32 Offset, int32 Limit)
{
	std::visit([&](auto* ws)
	{
		FConversationsManager* ConversationsManager = ProjectEngine->GetConversationsManager();

		CArray<Uint64> ConversationIds;
		ConversationsManager->GetLastConversationByUserId(CurrentUserId, Offset, Limit, ConversationIds);

		const nlohmann::json ConversationsJsonArray = FormatConversationIntoJson(ConversationIds);

		nlohmann::json JsonRoot;
		JsonRoot["type"] = SocketMessagePrivateTypeToString(ESocketMessagePrivateType::GetConversations);
		JsonRoot["message"] = ConversationsJsonArray;

		// Send initial client data
		ws->send(JsonRoot.dump(), uWS::TEXT);

	}, wsVariant);
}

void FPrivateSocketData::OnMessageReceived_AddConversation(AnyWebSocket wsVariant, uWS::OpCode opCode, const Uint64 OtherUserId)
{
	std::visit([&](auto* ws)
	{
		FWebSocketSessionData* WebSocketSessionData = ws->getUserData();
		if (WebSocketSessionData != nullptr && OtherUserId > 0)
		{
			CArray<Uint64> UserIdArray;
			UserIdArray.Push(WebSocketSessionData->UserId);
			UserIdArray.Push(OtherUserId);

			FConversationsManager* ConversationManager = ProjectEngine->GetConversationsManager();
			FFriendListManager* FriendListManager = ProjectEngine->GetFriendListManager();

			if (FriendListManager->IsFriend(OtherUserId, WebSocketSessionData->UserId))
			{
				// Find or create conversation
				bool bIsNewConversation = false;
				const Uint64 ConversationId = ConversationManager->GetOrCreateConversation(UserIdArray, bIsNewConversation);

				const nlohmann::json MessageJson = FormatConversationIntoJson({ ConversationId });

				nlohmann::json JsonRoot;
				JsonRoot["type"] = SocketMessagePrivateTypeToString(ESocketMessagePrivateType::AddConversation);
				JsonRoot["message"] = MessageJson;
				ws->send(JsonRoot.dump(), opCode);

				if (bIsNewConversation)
				{
					FSocketManager* SocketManager = ProjectEngine->GetSocketManager();
					FUserManager* UserManager = ProjectEngine->GetUserManager();

					std::shared_ptr<FConversationData> ConversationPtr = ConversationManager->GetConversation(ConversationId);
					for (Uint64 Id : ConversationPtr->UsersIds)
					{
						// Can't send publish to self
						if (Id != WebSocketSessionData->UserId)
						{
							std::vector<std::shared_ptr<FUser>> UserPtrArray;
							UserManager->GetUsersByIds({ Id }, UserPtrArray);
							if (UserPtrArray.size() == 1)
							{
								FFunctorLambda<void, void*> SocketAccessFunctor = [this, JsonRoot, Id](void* ws)
								{
									auto* WebSocket = static_cast<uWS::WebSocket<false, true, FUserSessionData>*>(ws);

									// To send message to a specific user
									const std::string UserTopic = FSocket::GenerateUserTopic(Id);
									if (WebSocket->isSubscribed(UserTopic))
									{
										WebSocket->send(JsonRoot.dump(), uWS::OpCode::TEXT);
									}
								};

								const std::shared_ptr<FUser>& UserPtr = UserPtrArray[0];
								SocketManager->EnqueueTaskForUserAtSocket(UserPtr->GetSocketId(), Id, SocketAccessFunctor);
							}
						}
					}
				}
			}
		}
	}, wsVariant);
}

void FPrivateSocketData::OnMessageReceived_CreateFriendRequest(AnyWebSocket wsVariant, uWS::OpCode opCode, Uint64 OtherUserId)
{
	std::visit([&](auto* ws)
	{
		FWebSocketSessionData* WebSocketSessionData = ws->getUserData();
		if (WebSocketSessionData != nullptr && OtherUserId > 0)
		{
			const Uint64 CurrentUserId = WebSocketSessionData->UserId;

			if (CurrentUserId == OtherUserId)
			{
				FSocket::EarlyExit(wsVariant, "cannot friend yourself", opCode);
				return;
			}

			const EFriendRequestStatus Status = ProjectEngine->GetFriendListManager()->SendFriendRequest(CurrentUserId, OtherUserId);
			if (Status == EFriendRequestStatus::RequestAdded)
			{
				const nlohmann::json JSON = FormatDataToJson(ESocketMessagePrivateType::CreateFriendRequest, "friend request added");
				ws->send(JSON.dump(), opCode);
				// Notify the target user that they received a friend request.
				SendFriendEventToUser(OtherUserId, ESocketMessagePrivateType::FriendRequestReceived, CurrentUserId);
			}
			else if (Status == EFriendRequestStatus::RequestAlreadyExists)
			{
				const nlohmann::json JSON = FormatDataToJson(ESocketMessagePrivateType::CreateFriendRequest, "friend request already exists");
				ws->send(JSON.dump(), opCode);
			}
			else if (Status == EFriendRequestStatus::FriendAlreadyExists)
			{
				const nlohmann::json JSON = FormatDataToJson(ESocketMessagePrivateType::CreateFriendRequest, "already friends");
				ws->send(JSON.dump(), opCode);
			}
			else if (Status == EFriendRequestStatus::SentRequestsLimitReached)
			{
				const nlohmann::json JSON = FormatDataToJson(ESocketMessagePrivateType::CreateFriendRequest, "sent requests limit reached");
				ws->send(JSON.dump(), opCode);
			}
			else if (Status == EFriendRequestStatus::IncomingRequestsLimitReached)
			{
				const nlohmann::json JSON = FormatDataToJson(ESocketMessagePrivateType::CreateFriendRequest, "target incoming requests limit reached");
				ws->send(JSON.dump(), opCode);
			}
			else
			{
#if DEBUG
				LOG_ERROR("Unknown friend request status: " << static_cast<int32>(Status));
#endif
				FSocket::EarlyExit(wsVariant, "request failed", opCode);
				return;
			}
		}
		else
		{
			FSocket::EarlyExit(wsVariant, "missing type", opCode);
		}
	}, wsVariant);
}

void FPrivateSocketData::OnMessageReceived_AcceptFriendRequest(AnyWebSocket wsVariant, uWS::OpCode opCode, Uint64 OtherUserId)
{
	std::visit([&](auto* ws)
	{
		FWebSocketSessionData* WebSocketSessionData = ws->getUserData();
		if (WebSocketSessionData != nullptr && OtherUserId > 0)
		{
			const Uint64 CurrentUserId = WebSocketSessionData->UserId;

			if (CurrentUserId == OtherUserId)
			{
				FSocket::EarlyExit(wsVariant, "cannot accept yourself", opCode);
				return;
			}

			const EAcceptFriendRequestStatus Status = ProjectEngine->GetFriendListManager()->AcceptFriendRequest(CurrentUserId, OtherUserId);
			if (Status == EAcceptFriendRequestStatus::RequestAccepted)
			{
				const nlohmann::json JSON = FormatDataToJson(ESocketMessagePrivateType::AcceptFriendRequest, "friend request accepted");
				ws->send(JSON.dump(), opCode);
				// Notify the original requester that the request was accepted (they are now friends).
				SendFriendEventToUser(OtherUserId, ESocketMessagePrivateType::FriendRequestAccepted, CurrentUserId);
			}
			else if (Status == EAcceptFriendRequestStatus::RequestNotExists)
			{
				const nlohmann::json JSON = FormatDataToJson(ESocketMessagePrivateType::AcceptFriendRequest, "no friend request");
				ws->send(JSON.dump(), opCode);
			}
			else if (Status == EAcceptFriendRequestStatus::FriendsLimitReached)
			{
				const nlohmann::json JSON = FormatDataToJson(ESocketMessagePrivateType::AcceptFriendRequest, "friends limit reached");
				ws->send(JSON.dump(), opCode);
			}
			else
			{
#if DEBUG
				LOG_ERROR("Unknown friend request status: " << static_cast<int32>(Status));
#endif
				FSocket::EarlyExit(wsVariant, "request failed", opCode);
				return;
			}
		}
	}, wsVariant);
}

void FPrivateSocketData::OnMessageReceived_RejectFriendRequest(AnyWebSocket wsVariant, uWS::OpCode opCode, const Uint64 OtherUserId)
{
	std::visit([&](auto* ws)
	{
		FWebSocketSessionData* WebSocketSessionData = ws->getUserData();
		if (WebSocketSessionData != nullptr && OtherUserId > 0)
		{
			const Uint64 CurrentUserId = WebSocketSessionData->UserId;

			if (CurrentUserId == OtherUserId)
			{
				FSocket::EarlyExit(wsVariant, "cannot remove yourself", opCode);
				return;
			}

			const ERejectFriendRequestStatus Status = ProjectEngine->GetFriendListManager()->RejectFriendRequest(CurrentUserId, OtherUserId);
			if (Status == ERejectFriendRequestStatus::RequestRejected)
			{
				const nlohmann::json JSON = FormatDataToJson(ESocketMessagePrivateType::RejectFriendRequest, "friend request rejected");
				ws->send(JSON.dump(), opCode);
				// Notify the original requester that the request was rejected.
				SendFriendEventToUser(OtherUserId, ESocketMessagePrivateType::FriendRequestRejected, CurrentUserId);
			}
			else if (Status == ERejectFriendRequestStatus::RequestNotExists)
			{
				const nlohmann::json JSON = FormatDataToJson(ESocketMessagePrivateType::RejectFriendRequest, "friend request not found");
				ws->send(JSON.dump(), opCode);
			}
			else
			{
#if DEBUG
				LOG_ERROR("Unknown friend request status: " << static_cast<int32>(Status));
#endif
				FSocket::EarlyExit(wsVariant, "request failed", opCode);
				return;
			}

		}
	}, wsVariant);
}

void FPrivateSocketData::OnMessageReceived_CancelFriendRequest(AnyWebSocket wsVariant, uWS::OpCode opCode, const Uint64 OtherUserId)
{
	std::visit([&](auto* ws)
{
	FWebSocketSessionData* WebSocketSessionData = ws->getUserData();
	if (WebSocketSessionData != nullptr && OtherUserId > 0)
	{
		const Uint64 CurrentUserId = WebSocketSessionData->UserId;

		if (CurrentUserId == OtherUserId)
		{
			FSocket::EarlyExit(wsVariant, "cannot remove yourself", opCode);
			return;
		}

		const ECancelFriendRequestStatus Status = ProjectEngine->GetFriendListManager()->CancelFriendRequest(CurrentUserId, OtherUserId);
		if (Status == ECancelFriendRequestStatus::RequestCanceled)
		{
			const nlohmann::json JSON = FormatDataToJson(ESocketMessagePrivateType::CancelFriendRequest, "friend request canceled");
			ws->send(JSON.dump(), opCode);
			// Notify the target user that the incoming request was canceled.
			SendFriendEventToUser(OtherUserId, ESocketMessagePrivateType::FriendRequestCanceled, CurrentUserId);
		}
		else if (Status == ECancelFriendRequestStatus::RequestNotExists)
		{
			const nlohmann::json JSON = FormatDataToJson(ESocketMessagePrivateType::CancelFriendRequest, "friend request not found");
			ws->send(JSON.dump(), opCode);
		}
		else
		{
#if DEBUG
			LOG_ERROR("Unknown friend request status: " << static_cast<int32>(Status));
#endif
			FSocket::EarlyExit(wsVariant, "request failed", opCode);
			return;
		}
	}
}, wsVariant);
}

void FPrivateSocketData::OnMessageReceived_GetFriendRequestsList(AnyWebSocket wsVariant, const uWS::OpCode opCode, const int32 Offset, const int32 Limit)
{
	std::visit([&](auto* ws)
	{
		FWebSocketSessionData* WebSocketSessionData = ws->getUserData();
		if (WebSocketSessionData != nullptr)
		{
			const Uint64 CurrentUserId = WebSocketSessionData->UserId;

			if (Limit <= 0)
			{
				FSocket::EarlyExit(wsVariant, "Limit <= 0", opCode);
				return;
			}

			FFriendListManager* FriendListManager = ProjectEngine->GetFriendListManager();
			std::vector<Uint64> FriendRequestListVector = FriendListManager->GetFriendRequestListInRange(CurrentUserId, Offset, Limit);
			std::vector<Uint64> IncomingFriendRequestListVector = FriendListManager->GetIncomingFriendRequestListInRange(CurrentUserId, Offset, Limit);

			FUserManager* UserManager = ProjectEngine->GetUserManager();
			
			auto FormatRequests = [&](const std::vector<Uint64>& Ids) {
				nlohmann::json Array = nlohmann::json::array();
				std::vector<std::shared_ptr<FUser>> Users;
				UserManager->GetUsersByIds(Ids, Users);
				for (const auto& User : Users) {
					if (User) {
						nlohmann::json Obj;
						Obj["id"] = User->GetUserId();
						Obj["name"] = User->GetUserNameString();
						Obj["status"] = UserStatusToString(User->GetUserStatus());
						Array.push_back(Obj);
					}
				}
				return Array;
			};

			nlohmann::json JsonData;
			JsonData["sent"] = FormatRequests(FriendRequestListVector);
			JsonData["incoming"] = FormatRequests(IncomingFriendRequestListVector);
			JsonData["offset"] = Offset;
			JsonData["limit"] = Limit;

			nlohmann::json JsonRoot;
			JsonRoot["type"] = SocketMessagePrivateTypeToString(ESocketMessagePrivateType::GetFriendRequestList);
			JsonRoot["data"] = JsonData;

			ws->send(JsonRoot.dump(), opCode);
		}
		else
		{
			FSocket::EarlyExit(wsVariant, "user not found", opCode);
			return;
		}
	}, wsVariant);
}

void FPrivateSocketData::OnMessageReceived_GetFriendList(AnyWebSocket wsVariant, uWS::OpCode opCode, const int32 Offset, const int32 Limit)
{
	std::visit([&](auto* ws)
	{
		FWebSocketSessionData* WebSocketSessionData = ws->getUserData();
		if (WebSocketSessionData != nullptr)
		{
			const Uint64 CurrentUserId = WebSocketSessionData->UserId;

			if (Limit <= 0)
			{
				FSocket::EarlyExit(wsVariant, "Limit <= 0", opCode);
				return;
			}

			FFriendListManager* FriendListManager = ProjectEngine->GetFriendListManager();
			std::vector<Uint64> FriendListVector = FriendListManager->GetFriendListInRange(CurrentUserId, Offset, Limit);

			FUserManager* UserManager = ProjectEngine->GetUserManager();
			std::vector<std::shared_ptr<FUser>> Users;
			UserManager->GetUsersByIds(FriendListVector, Users);

			nlohmann::json FriendsArray = nlohmann::json::array();
			for (const auto& User : Users) {
				if (User) {
					nlohmann::json Obj;
					Obj["id"] = User->GetUserId();
					Obj["name"] = User->GetUserNameString();
					Obj["status"] = UserStatusToString(User->GetUserStatus());
					FriendsArray.push_back(Obj);
				}
			}

			nlohmann::json JsonData;
			JsonData["friends"] = FriendsArray;
			JsonData["offset"] = Offset;
			JsonData["limit"] = Limit;

			nlohmann::json JsonRoot;
			JsonRoot["type"] = SocketMessagePrivateTypeToString(ESocketMessagePrivateType::GetFriendList);
			JsonRoot["data"] = JsonData;

			ws->send(JsonRoot.dump(), opCode);
		}
		else
		{
			FSocket::EarlyExit(wsVariant, "user not found", opCode);
			return;
		}
	}, wsVariant);
}

void FPrivateSocketData::OnMessageReceived_RemoveFriend(AnyWebSocket wsVariant, uWS::OpCode opCode, Uint64 OtherUserId)
{
	std::visit([&](auto* ws)
	{
		FWebSocketSessionData* WebSocketSessionData = ws->getUserData();
		if (WebSocketSessionData != nullptr && OtherUserId > 0)
		{
			const Uint64 CurrentUserId = WebSocketSessionData->UserId;

			if (CurrentUserId == OtherUserId)
			{
				FSocket::EarlyExit(wsVariant, "cannot remove yourself", opCode);
				return;
			}

			const ERemoveFriendStatus Status = ProjectEngine->GetFriendListManager()->RemoveFriend(CurrentUserId, OtherUserId);
			if (Status == ERemoveFriendStatus::FriendRemoved)
			{
				const nlohmann::json JSON = FormatDataToJson(ESocketMessagePrivateType::RemoveFriend, "friend removed");
				ws->send(JSON.dump(), opCode);
				// Notify the removed user that they are no longer a friend.
				SendFriendEventToUser(OtherUserId, ESocketMessagePrivateType::FriendRemoved, CurrentUserId);
			}
			else if (Status == ERemoveFriendStatus::FriendNotExists)
			{
				const nlohmann::json JSON = FormatDataToJson(ESocketMessagePrivateType::RemoveFriend, "friend not found");
				ws->send(JSON.dump(), opCode);
			}
			else
			{
	#if DEBUG
				LOG_ERROR("Unknown friend request status: " << static_cast<int32>(Status));
	#endif
				FSocket::EarlyExit(wsVariant, "request failed", opCode);
				return;
			}
		}
	}, wsVariant);
}

void FPrivateSocketData::OnMessageReceived_DataStreamChannel(AnyWebSocket wsVariant, uWS::OpCode opCode, Uint64 OtherUserId)
{
	std::visit([&](auto* ws)
	{
		FWebSocketSessionData* WebSocketSessionData = ws->getUserData();
		if (WebSocketSessionData != nullptr && OtherUserId > 0 && OtherUserId != WebSocketSessionData->UserId)
		{
			const Uint64 CurrentUserId = WebSocketSessionData->UserId;

			// Check if both users are friends
			FFriendListManager* FriendListManager = ProjectEngine->GetFriendListManager();
			if (!FriendListManager->IsFriend(CurrentUserId, OtherUserId))
			{
				return FSocket::EarlyExit(wsVariant, "not friends", opCode);
			}

			const std::string RoomName = FSocket::GenerateVoiceRoomNameFromIds({CurrentUserId, OtherUserId});

			const ERoomExistenceStatus CheckRoomResult = ProjectEngine->GetRoomsManager()->CheckRoom(RoomName);
			if (CheckRoomResult == ERoomExistenceStatus::NotExists)
			{
				// Create voice room if missing
				const ERoomCreateStatus CreateStatus = ProjectEngine->GetRoomsManager()->CreateRoom(RoomName);
				if (CreateStatus == ERoomCreateStatus::AlreadyExistsDifferentToken ||
					CreateStatus == ERoomCreateStatus::Failed)
				{
					// The room exists in Go but with a different token (drift), or the call
					// failed outright. Do NOT hand the client a stale/empty token.
					LOG_ERROR("Failed to create voice room (status: " << static_cast<int32>(CreateStatus) << ")");
					return FSocket::EarlyExit(wsVariant, "voice room unavailable", opCode);
				}
				// Created or AlreadyExists -> proceed with the locally cached token.
			}

			const std::string RoomToken = ProjectEngine->GetRoomsManager()->GetRoomToken(RoomName);

			nlohmann::json JsonData;
			JsonData["name"] = RoomName;
			JsonData["token"] = RoomToken;

			nlohmann::json JsonRoot;
			JsonRoot["type"] = SocketMessagePrivateTypeToString(ESocketMessagePrivateType::DataStreamChannel);
			JsonRoot["data"] = JsonData;

			ws->send(JsonRoot.dump(), opCode);
		}
	}, wsVariant);
}

void FPrivateSocketData::OnMessageReceived_OnUserCalling(AnyWebSocket wsVariant, uWS::OpCode opCode, Uint64 OtherUserId)
{
	std::visit([&](auto* ws)
	{
		FWebSocketSessionData* WebSocketSessionData = ws->getUserData();
		if (WebSocketSessionData != nullptr && OtherUserId > 0)
		{
			const Uint64 CurrentUserId = WebSocketSessionData->UserId;

			FFriendListManager* FriendManager = ProjectEngine->GetFriendListManager();
			if (FriendManager->IsFriend(CurrentUserId, OtherUserId))
			{
				FSocketManager* SocketManager = ProjectEngine->GetSocketManager();
				FUserManager* UserManager = ProjectEngine->GetUserManager();

				FFunctorLambda<void, void*> SocketAccessFunctor = [CurrentUserId](void* ws2)
				{
					auto* WebSocket = static_cast<uWS::WebSocket<false, true, FUserSessionData>*>(ws2);

					nlohmann::json MessageJson;
					MessageJson["user_id"] = CurrentUserId;

					nlohmann::json JsonRoot;
					JsonRoot["type"] = SocketMessagePrivateTypeToString(ESocketMessagePrivateType::UserCalling);
					JsonRoot["section"] = SocketMessageSectionToString(ESocketMessageSection::Priv);
					JsonRoot["data"] = MessageJson;

					// Send initial client data
					WebSocket->send(JsonRoot.dump(), uWS::TEXT);
				};

				const std::shared_ptr<FUser> UserPtr = UserManager->GetUserById(OtherUserId);
				SocketManager->EnqueueTaskForUserAtSocket(UserPtr->GetSocketId(), OtherUserId, SocketAccessFunctor);
			}
		}
	}, wsVariant);
}

nlohmann::json FPrivateSocketData::FormatConversationIntoJson(const CArray<Uint64>& ConversationIds)
{
	FConversationsManager* ConversationsManager = ProjectEngine->GetConversationsManager();
	FUserManager* UserManager = ProjectEngine->GetUserManager();

	nlohmann::json ConversationsJsonArray = nlohmann::json::array();

	for (Uint64 ConversationId : ConversationIds)
	{
		std::shared_ptr<FConversationData> Conversation = ConversationsManager->GetConversation(ConversationId);
		if (Conversation != nullptr)
		{
			nlohmann::json NewConversation;
			NewConversation["id"] = ConversationId;

			std::vector<std::shared_ptr<FUser>> OutUsers;
			UserManager->GetUsersByIds(Conversation->UsersIds.Vector(), OutUsers);

			// Add users (id to name)
			{
				nlohmann::json UsersJsonArray = nlohmann::json::array();

				for (std::shared_ptr<FUser>& UserPtr : OutUsers)
				{
					nlohmann::json NewUser;

					NewUser["id"] = UserPtr->GetUserId();
					NewUser["name"] = UserPtr->GetUserNameString();
					NewUser["status"] = UserStatusToString(UserPtr->GetUserStatus());

					UsersJsonArray.push_back(NewUser);
				}

				NewConversation["users"] = UsersJsonArray;
			}

			// Add users Ids
			NewConversation["userids"] = Conversation->UsersIds.Vector();

			// Add messages
			{
				std::vector<FConversationMessageData> LastMessages = Conversation->MessagesDeque.PeekFirst(25);
				nlohmann::json MessagesJsonArray = nlohmann::json::array();

				for (FConversationMessageData& Message : LastMessages | std::views::reverse)
				{
					nlohmann::json NewMessage;
					NewMessage["message"] = Message.Message;
					NewMessage["message_id"] = Message.MessageId;
					NewMessage["sender_id"] = Message.SenderId;
					NewMessage["time"] = Message.CreatedAt;
					NewMessage["status"] = Message.Status;
					NewMessage["message_type"] = MessageTypeToString(Message.MessageType);

					MessagesJsonArray.push_back(NewMessage);
				}

				NewConversation["messages"] = MessagesJsonArray;
			}

			ConversationsJsonArray.push_back(NewConversation);
		}
	}

	return ConversationsJsonArray;
}

nlohmann::json FPrivateSocketData::FormatUsersToJson(const std::vector<uint64_t>& UserIds, const std::vector<std::string>& DisplayNames)
{
	nlohmann::json DataUserArray = nlohmann::json::array();

	for (size_t i = 0; i < UserIds.size(); i++)
	{
		nlohmann::json SingleUser = {
			{"id", UserIds[i]},
			{"displayName", DisplayNames[i]}
		};

		DataUserArray.push_back(SingleUser);
	}

	// Standard JSON with root object
	nlohmann::json JsonRoot;
	JsonRoot["data"] = DataUserArray;
	return JsonRoot;
}

nlohmann::json FPrivateSocketData::FormatDataToJson(const ESocketMessagePrivateType Type, const std::string& Message)
{
	nlohmann::json JsonRoot;

	JsonRoot["type"] = SocketMessagePrivateTypeToString(Type);
	JsonRoot["message"] = Message;

	return JsonRoot;
}


void FPrivateSocketData::SendFriendEventToUser(const Uint64 TargetUserId, const ESocketMessagePrivateType EventType, const Uint64 ActorUserId)
{
	FUserManager* UserManager = ProjectEngine->GetUserManager();
	FSocketManager* SocketManager = ProjectEngine->GetSocketManager();

	// Resolve the target user to find their socket. If offline / unknown there is nothing to send.
	const std::shared_ptr<FUser> TargetUser = UserManager->GetUserById(TargetUserId);
	if (TargetUser == nullptr)
	{
		return;
	}

	// Resolve actor display name to attach to the event payload.
	std::string ActorUserName;
	{
		const std::shared_ptr<FUser> ActorUser = UserManager->GetUserById(ActorUserId);
		if (ActorUser != nullptr)
		{
			ActorUserName = ActorUser->GetUserNameString();
		}
	}

	nlohmann::json DataJson;
	DataJson["user_id"] = ActorUserId;
	if (!ActorUserName.empty())
	{
		DataJson["user_name"] = ActorUserName;
	}

	nlohmann::json JsonRoot;
	JsonRoot["type"] = SocketMessagePrivateTypeToString(EventType);
	JsonRoot["section"] = SocketMessageSectionToString(ESocketMessageSection::Priv);
	JsonRoot["data"] = DataJson;

	FFunctorLambda<void, void*> SocketAccessFunctor = [JsonRoot, TargetUserId](void* ws)
	{
		auto* WebSocket = static_cast<uWS::WebSocket<false, true, FWebSocketSessionData>*>(ws);

		const std::string UserTopic = FSocket::GenerateUserTopic(TargetUserId);
		if (WebSocket->isSubscribed(UserTopic))
		{
			WebSocket->send(JsonRoot.dump(), uWS::OpCode::TEXT);
		}
	};

	SocketManager->EnqueueTaskForUserAtSocket(TargetUser->GetSocketId(), TargetUserId, SocketAccessFunctor);
}
