// Created by https://www.linkedin.com/in/przemek2122/ 2020-2026

#include "Managers/ServersManager.h"
#include "DataBase/DataBaseConnect.h"
#include "Logger/Logger.h"
#include "SQRLLEncryption.h"

#include <soci/session.h>
#include <soci/statement.h>
#include <random>
#include <iomanip>
#include <sstream>
#include <unordered_set>

#include "BackendSettings.h"
#include "ProjectEngine.h"
#include "AbuseProtection/AbuseProtection.h"

FServersManager::FServersManager() = default;

void FServersManager::PostSecondTick()
{
    PostSecondTickCounter++;

    // Run invite abuse cleanup every ~300 ticks (5 minutes at 1 tick/sec)
    if (PostSecondTickCounter >= 300)
    {
        PostSecondTickCounter = 0;
        FGlobalDefines::GEngine->GetAbuseProtection()->PeriodicInviteAbuseCleanup();
    }

    // Message retention cleanup (keep the last N messages per text channel).
    const FBackendSettings* Settings = FGlobalDefines::GEngine->GetBackendSettings();
    const int32 CleanupIntervalSeconds = Settings->GetMessageRetentionCleanupIntervalSeconds();
    const int32 RetainCount = Settings->GetMessageRetentionCount();
    if (CleanupIntervalSeconds > 0 && RetainCount > 0)
    {
        MessageRetentionCounter++;
        if (MessageRetentionCounter >= CleanupIntervalSeconds)
        {
            MessageRetentionCounter = 0;
            CleanupOldMessages(RetainCount);
        }
    }
}

void FServersManager::CleanupOldMessages(const int32 RetainCount)
{
    // Guard against overlapping runs. The trim runs on the engine tick thread and
    // can outlive a single interval under load; skip if a previous run is still
    // in flight so trims never pile up.
    if (bCleanupInProgress.exchange(true))
    {
        return;
    }

    // RAII release so the guard is always cleared even if an exception escapes.
    struct FCleanupGuard
    {
        std::atomic<bool>& Flag;
        ~FCleanupGuard() { Flag.store(false); }
    } CleanupGuard{ bCleanupInProgress };

    if (RetainCount <= 0)
    {
        return;
    }

    // Memory-only trim. The database is NEVER touched here: server channel
    // history stays fully accessible and is re-fetched from the DB on demand
    // when a client scrolls back. We only clip the in-RAM per-channel message
    // cache to bound memory usage.
    std::vector<std::shared_ptr<FServer>> Servers;
    {
        std::shared_lock Lock(ServersMapMutex);
        Servers.reserve(ServersMap.size());
        for (const auto& Pair : ServersMap)
        {
            if (Pair.second)
            {
                Servers.push_back(Pair.second);
            }
        }
    }

    for (const std::shared_ptr<FServer>& Server : Servers)
    {
        Server->TrimChannelMessagesToCount(RetainCount);
    }
}


std::shared_ptr<FServer> FServersManager::GetServerById(const Uint64 InServerId)
{
    // Try cache first
    {
        std::shared_lock Lock(ServersMapMutex);
        auto ServerIter = ServersMap.find(InServerId);
        if (ServerIter != ServersMap.end())
        {
            return ServerIter->second;
        }
    }

    // Try loading from DB
    if (DownloadServerFromDB(InServerId))
    {
        std::shared_lock Lock(ServersMapMutex);
        auto ServerIter = ServersMap.find(InServerId);
        if (ServerIter != ServersMap.end())
        {
            return ServerIter->second;
        }
    }

    return nullptr;
}

std::vector<std::shared_ptr<FServer>> FServersManager::GetUserServers(const Uint64 UserId)
{
    std::vector<std::shared_ptr<FServer>> Result;

    const std::vector<Uint64> ServerIds = GetUserServerIds(UserId);

    // Load each server (from cache or DB)
    for (const Uint64 Id : ServerIds)
    {
        const std::shared_ptr<FServer> Server = GetServerById(Id);
        if (Server)
        {
            Result.push_back(Server);
        }
    }

    return Result;
}

std::vector<Uint64> FServersManager::GetUserServerIds(Uint64 UserId)
{
    // Fast path: serve from the in-memory membership cache. It is invalidated on
    // every membership mutation, so it never returns stale data. This removes a
    // synchronous DB SELECT from the connect/disconnect hot path.
    {
        std::shared_lock Lock(UserToServerIdsCacheMutex);
        const auto Iter = UserToServerIdsCache.find(UserId);
        if (Iter != UserToServerIdsCache.end())
        {
            return Iter->second;
        }
    }

    std::vector<Uint64> ServerIds;

    FDataBaseConnect Connect;
    if (!Connect.IsConnected())
    {
        LOG_ERROR("Database connection failed in GetUserServerIds");
        return ServerIds;
    }

    try
    {
        soci::session& Session = Connect.GetSession();

        Uint64 ServerId = 0;

        soci::statement St = (Session.prepare <<
            "SELECT server_id FROM server_members WHERE user_id = :uid",
            soci::into(ServerId),
            soci::use(UserId));

        St.execute();
        while (St.fetch())
        {
            ServerIds.push_back(ServerId);
        }
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("GetUserServerIds DB error: " << e.what());
        return ServerIds;
    }

    {
        std::unique_lock Lock(UserToServerIdsCacheMutex);
        UserToServerIdsCache[UserId] = ServerIds;
    }

    return ServerIds;
}

Uint64 FServersManager::AddServer(const std::string& InServerName, Uint64 OwnerId)
{
    if (InServerName.empty() || OwnerId == 0)
    {
        LOG_ERROR("AddServer: Invalid parameters");
        return 0;
    }

    const std::shared_ptr<FServer> NewServer = std::make_shared<FServer>();
    NewServer->SetServerName(InServerName);
    NewServer->SetOwnerId(OwnerId);
    NewServer->SetToken(GenerateServerToken());

    // Get current time as ISO string (simplified: use Unix timestamp as string for now)
    NewServer->SetCreatedAt(static_cast<Uint64>(std::chrono::system_clock::now().time_since_epoch().count()));

    // Upload to DB (this also sets the server ID via auto-increment)
    if (!UploadNewServerToDB(NewServer))
    {
        LOG_ERROR("AddServer: Failed to upload to DB");
        return 0;
    }

    const Uint64 NewServerId = NewServer->GetServerId();

    // Add owner as member
    FServerMember OwnerMember;
    OwnerMember.UserId = OwnerId;
    OwnerMember.Permissions = EServerPermission::ALL_PERMISSIONS;
    OwnerMember.Status = "online";
    NewServer->AddMember(OwnerMember);
    UploadMemberToDB(NewServerId, OwnerId, EServerPermission::ALL_PERMISSIONS);

    // Create default channels (position 0 and 1)
    AddChannel(NewServerId, "general", EServerChannelType::Text, OwnerId);
    AddChannel(NewServerId, "General", EServerChannelType::Voice, OwnerId);

    // Add to cache
    {
        std::unique_lock Lock(ServersMapMutex);
        ServersMap[NewServerId] = NewServer;
    }

    // Invalidate the owner's membership cache (they gained a server).
    {
        std::unique_lock Lock(UserToServerIdsCacheMutex);
        UserToServerIdsCache.erase(OwnerId);
    }

    LOG_INFO("Created server '" << InServerName << "' with ID " << NewServerId);
    return NewServerId;
}

bool FServersManager::RemoveServer(const Uint64 InServerId)
{
    if (!DeleteServerFromDB(InServerId))
    {
        LOG_ERROR("RemoveServer: Failed to delete from DB");
        return false;
    }

    {
        std::unique_lock Lock(ServersMapMutex);
        ServersMap.erase(InServerId);
    }

    // Removing a server affects the membership of every former member; clear the
    // entire membership cache (rebuilding per-user would require a member list).
    {
        std::unique_lock Lock(UserToServerIdsCacheMutex);
        UserToServerIdsCache.clear();
    }

    return true;
}

bool FServersManager::AddUserToServer(Uint64 ServerId, Uint64 UserId,
                                       const std::string& UserName, Uint64 Permissions)
{
    auto Server = GetServerById(ServerId);
    if (!Server)
    {
        LOG_ERROR("AddUserToServer: Server not found: " << ServerId);
        return false;
    }

    if (Server->HasMember(UserId))
    {
        return true; // Already a member
    }

    if (!UploadMemberToDB(ServerId, UserId, Permissions))
    {
        LOG_ERROR("AddUserToServer: Failed to upload member to DB");
        return false;
    }

    FServerMember Member;
    Member.UserId = UserId;
    Member.UserName = UserName;
    Member.Status = "online";
    Server->AddMember(Member);

    // Invalidate the membership cache so the next GetUserServerIds() re-queries.
    {
        std::unique_lock Lock(UserToServerIdsCacheMutex);
        UserToServerIdsCache.erase(UserId);
    }

    return true;
}

bool FServersManager::RemoveUserFromServer(const Uint64 ServerId, const Uint64 UserId)
{
    auto Server = GetServerById(ServerId);
    if (!Server)
    {
        return false;
    }

    if (!RemoveMemberFromDB(ServerId, UserId))
    {
        LOG_ERROR("RemoveUserFromServer: Failed to remove member from DB");
        return false;
    }

    Server->RemoveMember(UserId);

    // Invalidate the membership cache so the next GetUserServerIds() re-queries.
    {
        std::unique_lock Lock(UserToServerIdsCacheMutex);
        UserToServerIdsCache.erase(UserId);
    }

    return true;
}

bool FServersManager::IsUserInServer(const Uint64 ServerId, const Uint64 UserId)
{
    auto Server = GetServerById(ServerId);
    if (!Server)
    {
        return false;
    }
    return Server->HasMember(UserId);
}
bool FServersManager::UpdateMemberPermissions(Uint64 ServerId, Uint64 TargetUserId, Uint64 NewPermissions)
{
    std::shared_ptr<FServer> Server = GetServerById(ServerId);
    if (!Server)
    {
        LOG_ERROR("UpdateMemberPermissions: Server not found: " << ServerId);
        return false;
    }

    if (!Server->HasMember(TargetUserId))
    {
        LOG_ERROR("UpdateMemberPermissions: Target user not a member of server");
        return false;
    }

    // Persist to DB
    if (!UpdateMemberPermissionsInDB(ServerId, TargetUserId, NewPermissions))
    {
        LOG_ERROR("UpdateMemberPermissions: Failed to update in DB");
        return false;
    }

    // Update in-memory cache
    Server->UpdateMemberPermissions(TargetUserId, NewPermissions);

    LOG_INFO("Updated permissions for user " << TargetUserId << " in server " << ServerId
             << " to " << NewPermissions);
    return true;
}

Uint64 FServersManager::GetMemberPermissions(const Uint64 ServerId, const Uint64 UserId)
{
    const std::shared_ptr<FServer> Server = GetServerById(ServerId);
    if (!Server)
    {
        return 0;
    }
    return Server->GetMemberPermissions(UserId);
}

bool FServersManager::UserHasPermission(const Uint64 ServerId, const Uint64 UserId, const Uint64 Permission)
{
    const std::shared_ptr<FServer> Server = GetServerById(ServerId);
    if (!Server)
    {
        return false;
    }

    // Owner always has all permissions
    if (Server->GetOwnerId() == UserId)
    {
        return true;
    }

    const Uint64 Permissions = Server->GetMemberPermissions(UserId);
    return EServerPermission::HasPermission(Permissions, Permission);
}


Uint64 FServersManager::AddChannel(Uint64 ServerId, const std::string& ChannelName, EServerChannelType ChannelType, Uint64 RequestedByUserId)
{
    auto Server = GetServerById(ServerId);
    if (!Server)
    {
        LOG_ERROR("AddChannel: Server not found: " << ServerId);
        return 0;
    }


    // Check permission: user must have CAN_MANAGE_CHANNELS or be owner
    if (!UserHasPermission(ServerId, RequestedByUserId, EServerPermission::CAN_MANAGE_CHANNELS))
    {
        LOG_WARN("AddChannel: User " << RequestedByUserId << " lacks CAN_MANAGE_CHANNELS permission"
                 << " in server " << ServerId);
        return 0;
    }

    FServerChannel Channel;
    Channel.ServerId = ServerId;
    Channel.ChannelName = ChannelName;
    Channel.ChannelType = ChannelType;

    // Auto-assign the next available position so the new channel
    // appears at the bottom of the list by default.
    Channel.Position = GetNextChannelPosition(ServerId);

    // Upload to DB first to get channel ID
    if (!UploadChannelToDB(ServerId, Channel))
    {
        LOG_ERROR("AddChannel: Failed to upload channel to DB");
        return 0;
    }

    Server->AddChannel(Channel);
    return Channel.ChannelId;
}

bool FServersManager::RemoveChannel(Uint64 ServerId, Uint64 ChannelId, Uint64 RequestedByUserId)
{
    std::shared_ptr<FServer> Server = GetServerById(ServerId);
    if (!Server)
    {
        LOG_ERROR("RemoveChannel: Server not found: " << ServerId);
        return false;
    }

    // Check permission: user must have CAN_MANAGE_CHANNELS or be owner
    if (!UserHasPermission(ServerId, RequestedByUserId, EServerPermission::CAN_MANAGE_CHANNELS))
    {
        LOG_WARN("RemoveChannel: User " << RequestedByUserId << " lacks CAN_MANAGE_CHANNELS permission"
                 << " in server " << ServerId);
        return false;
    }

    // Verify channel exists before deleting
    if (!Server->GetChannel(ChannelId))
    {
        LOG_ERROR("RemoveChannel: Channel not found: " << ChannelId << " in server " << ServerId);
        return false;
    }

    if (!DeleteChannelFromDB(ServerId, ChannelId))
    {
        LOG_ERROR("RemoveChannel: Failed to delete channel from DB");
        return false;
    }

    Server->RemoveChannel(ChannelId);

    // Renumber to eliminate position gaps after deletion
    RenumberChannelPositions(ServerId);

    LOG_INFO("Channel " << ChannelId << " deleted from server " << ServerId
             << " by user " << RequestedByUserId);
    return true;
}

bool FServersManager::MoveChannel(Uint64 ServerId, Uint64 ChannelId, uint32 NewPosition, Uint64 RequestedByUserId)
{
    std::shared_ptr<FServer> Server = GetServerById(ServerId);
    if (!Server)
    {
        LOG_ERROR("MoveChannel: Server not found: " << ServerId);
        return false;
    }

    // Check permission: user must have CAN_MANAGE_CHANNELS or be owner
    if (!UserHasPermission(ServerId, RequestedByUserId, EServerPermission::CAN_MANAGE_CHANNELS))
    {
        LOG_WARN("MoveChannel: User " << RequestedByUserId << " lacks CAN_MANAGE_CHANNELS permission"
                 << " in server " << ServerId);
        return false;
    }

    // Get channels sorted by current position
    std::vector<std::shared_ptr<FServerChannel>> Channels = Server->GetAllChannels();
    if (Channels.empty())
    {
        return false;
    }

    // Clamp NewPosition to valid range [0, Channels.size() - 1]
    if (NewPosition >= static_cast<uint32>(Channels.size()))
        NewPosition = static_cast<uint32>(Channels.size()) - 1;

    // Find the channel to move by ID
    std::shared_ptr<FServerChannel> MovedChannel = nullptr;
    int32 OldPosition = -1;
    for (int32 i = 0; i < static_cast<int32>(Channels.size()); ++i)
    {
        if (Channels[i]->ChannelId == ChannelId)
        {
            MovedChannel = Channels[i];
            OldPosition = i;
            break;
        }
    }

    if (!MovedChannel || OldPosition < 0)
    {
        LOG_ERROR("MoveChannel: Channel " << ChannelId << " not found in server " << ServerId);
        return false;
    }

    // No-op if already at the requested position
    if (OldPosition == NewPosition)
    {
        return true;
    }

    // Remove the channel from its current position
    Channels.erase(Channels.begin() + OldPosition);

    // Insert at the new position
    Channels.insert(Channels.begin() + NewPosition, MovedChannel);

    // Renumber all positions sequentially (0, 1, 2, ...)
    FDataBaseConnect Connect;
    if (!Connect.IsConnected())
    {
        LOG_ERROR("MoveChannel: Database connection failed");
        return false;
    }

    // Build the {ChannelId -> Position} map and apply it under the server lock
    // (also invalidates the sorted-channel cache). Writing Position without the
    // lock would race with the sort in GetAllChannels().
    {
        std::unordered_map<Uint64, uint32> NewPositions;
        NewPositions.reserve(Channels.size());
        for (int32 i = 0; i < static_cast<int32>(Channels.size()); ++i)
        {
            NewPositions[Channels[i]->ChannelId] = static_cast<uint32>(i);
        }
        Server->SetChannelPositions(NewPositions);
    }

    try
    {
        soci::session& Session = Connect.GetSession();

        for (int32 i = 0; i < static_cast<int32>(Channels.size()); ++i)
        {
            Session << "UPDATE server_channels SET position = :pos WHERE id = :cid AND server_id = :sid",
                soci::use(i),
                soci::use(Channels[i]->ChannelId),
                soci::use(ServerId);
        }
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("MoveChannel DB error: " << e.what());
        return false;
    }

    LOG_INFO("Channel " << ChannelId << " moved from position " << OldPosition
             << " to " << NewPosition << " in server " << ServerId
             << " by user " << RequestedByUserId);
    return true;
}

bool FServersManager::ReorderChannels(const Uint64 ServerId, const std::vector<Uint64>& ChannelIds, const Uint64 RequestedByUserId)
{
    std::shared_ptr<FServer> Server = GetServerById(ServerId);
    if (!Server)
    {
        LOG_ERROR("ReorderChannels: Server not found: " << ServerId);
        return false;
    }

    // Check permission: user must have CAN_MANAGE_CHANNELS or be owner
    if (!UserHasPermission(ServerId, RequestedByUserId, EServerPermission::CAN_MANAGE_CHANNELS))
    {
        LOG_DEBUG("ReorderChannels: User " << RequestedByUserId << " lacks CAN_MANAGE_CHANNELS permission"
                 << " in server " << ServerId);
        return false;
    }

    // Get existing channels sorted by current position
    std::vector<std::shared_ptr<FServerChannel>> Channels = Server->GetAllChannels();
    if (Channels.empty())
    {
        LOG_DEBUG("ReorderChannels: No channels in server " << ServerId);
        return false;
    }

    // Validate: channel_ids must contain every channel exactly once
    if (ChannelIds.size() != Channels.size())
    {
        LOG_DEBUG("ReorderChannels: channel_ids size (" << ChannelIds.size()
                  << ") does not match server channel count (" << Channels.size() << ")");
        return false;
    }

    // Build a set of existing channel IDs for O(1) lookup
    std::unordered_set<Uint64> ExistingIds;
    for (const std::shared_ptr<FServerChannel>& Ch : Channels)
    {
        ExistingIds.insert(Ch->ChannelId);
    }

    // Validate: every ID in channel_ids must exist, and no duplicates
    std::unordered_set<Uint64> Seen;
    for (const Uint64 Id : ChannelIds)
    {
        if (!ExistingIds.contains(Id))
        {
            LOG_ERROR("ReorderChannels: Channel " << Id << " does not exist in server " << ServerId);
            return false;
        }
        if (!Seen.insert(Id).second)
        {
            LOG_ERROR("ReorderChannels: Duplicate channel ID " << Id << " in channel_ids array");
            return false;
        }
    }

    // Update all positions atomically in a single DB transaction
    FDataBaseConnect Connect;
    if (!Connect.IsConnected())
    {
        LOG_ERROR("ReorderChannels: Database connection failed");
        return false;
    }

    // Apply the new in-memory positions under the server lock (also invalidates
    // the sorted-channel cache). The DB updates below use the loop index.
    {
        std::unordered_map<Uint64, uint32> NewPositions;
        NewPositions.reserve(ChannelIds.size());
        for (int32 i = 0; i < static_cast<int32>(ChannelIds.size()); ++i)
        {
            NewPositions[ChannelIds[i]] = static_cast<uint32>(i);
        }
        Server->SetChannelPositions(NewPositions);
    }

    try
    {
        soci::session& Session = Connect.GetSession();

        for (int32 i = 0; i < static_cast<int32>(ChannelIds.size()); ++i)
        {
            const Uint64 ChannelId = ChannelIds[i];

            Session << "UPDATE server_channels SET position = :pos WHERE id = :cid AND server_id = :sid",
                soci::use(i),
                soci::use(ChannelId),
                soci::use(ServerId);
        }
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("ReorderChannels DB error: " << e.what());
        return false;
    }

    LOG_INFO("Channels reordered in server " << ServerId
             << " (" << ChannelIds.size() << " channels) by user " << RequestedByUserId);
    return true;
}

bool FServersManager::RenameChannel(Uint64 ServerId, Uint64 ChannelId, const std::string& NewName, Uint64 RequestedByUserId)
{
    std::shared_ptr<FServer> Server = GetServerById(ServerId);
    if (!Server)
    {
        LOG_ERROR("RenameChannel: Server not found: " << ServerId);
        return false;
    }

    // Check permission: user must have CAN_MANAGE_CHANNELS or be owner
    if (!UserHasPermission(ServerId, RequestedByUserId, EServerPermission::CAN_MANAGE_CHANNELS))
    {
        LOG_WARN("RenameChannel: User " << RequestedByUserId << " lacks CAN_MANAGE_CHANNELS permission"
                 << " in server " << ServerId);
        return false;
    }

    // Validate the new name
    if (NewName.empty())
    {
        LOG_ERROR("RenameChannel: New channel name is empty");
        return false;
    }

    // Verify channel exists
    const std::shared_ptr<FServerChannel> Channel = Server->GetChannel(ChannelId);
    if (!Channel)
    {
        LOG_ERROR("RenameChannel: Channel " << ChannelId << " not found in server " << ServerId);
        return false;
    }

    // Persist to DB
    if (!UpdateChannelNameInDB(ServerId, ChannelId, NewName))
    {
        LOG_ERROR("RenameChannel: Failed to update channel name in DB");
        return false;
    }

    // Update in-memory cache (shared_ptr, so this modifies the server's cached copy directly)
    Channel->ChannelName = NewName;

    LOG_INFO("Channel " << ChannelId << " renamed to '" << NewName << "' in server " << ServerId
             << " by user " << RequestedByUserId);
    return true;
}

Uint64 FServersManager::AddMessage(Uint64 ServerId, Uint64 ChannelId, Uint64 SenderId, const std::string& SenderName, const std::string& Content, const EMessageType MessageType)
{
    auto Server = GetServerById(ServerId);
    if (!Server)
    {
        LOG_ERROR("AddMessage: Server not found: " << ServerId);
        return 0;
    }

    // Verify the channel actually belongs to this server before persisting.
    if (!Server->GetChannel(ChannelId))
    {
        LOG_WARN("AddMessage: channel " << ChannelId << " does not belong to server " << ServerId);
        return 0;
    }

    FServerMessage Message;
    Message.ChannelId = ChannelId;
    Message.SenderId = SenderId;
    Message.SenderName = SenderName;
    Message.Content = Content;
    Message.MessageType = MessageType;
    Message.CreatedAt = static_cast<Uint64>(std::chrono::system_clock::now().time_since_epoch().count());

    Uint64 OutMessageId = 0;
    if (!UploadMessageToDB(Message, OutMessageId))
    {
        LOG_ERROR("AddMessage: Failed to upload message to DB");
        return 0;
    }

    Message.MessageId = OutMessageId;
    Server->AddMessage(Message);

    return OutMessageId;
}

EDeleteServerMessageResult FServersManager::DeleteMessage(const Uint64 ServerId, const Uint64 ChannelId, const Uint64 MessageId, const Uint64 RequestedByUserId)
{
    const std::shared_ptr<FServer> Server = GetServerById(ServerId);
    if (!Server)
    {
        LOG_ERROR("DeleteMessage: Server not found: " << ServerId);
        return EDeleteServerMessageResult::ServerNotFound;
    }

    // Resolve the message's channel and author so we can authorize the deletion.
    Uint64 MessageChannelId = 0;
    Uint64 MessageSenderId = 0;
    if (!GetServerMessageOwnerFromDB(MessageId, MessageChannelId, MessageSenderId))
    {
        LOG_ERROR("DeleteMessage: Message " << MessageId << " not found in DB");
        return EDeleteServerMessageResult::MessageNotFound;
    }

    // Defensive: the message must actually belong to the requested channel.
    if (MessageChannelId != ChannelId)
    {
        LOG_ERROR("DeleteMessage: Message " << MessageId << " does not belong to channel " << ChannelId);
        return EDeleteServerMessageResult::MessageNotFound;
    }

    // Authorization: message author or server owner may delete.
    const bool bIsAuthor = (MessageSenderId == RequestedByUserId);
    const bool bIsOwner = (Server->GetOwnerId() == RequestedByUserId);
    if (!bIsAuthor && !bIsOwner)
    {
        LOG_WARN("DeleteMessage: User " << RequestedByUserId << " is not authorized to delete message "
                 << MessageId << " (sender=" << MessageSenderId << ", owner=" << Server->GetOwnerId() << ")");
        return EDeleteServerMessageResult::NotAuthorized;
    }

    // Soft-delete in DB first (retains the row, replaces content with a tombstone).
    if (!MarkMessageDeletedInDB(MessageId, ChannelId))
    {
        LOG_ERROR("DeleteMessage: Failed to soft-delete message " << MessageId << " from DB");
        return EDeleteServerMessageResult::Failed;
    }

    // Mark the message as deleted in the in-memory cache (best effort; the cache
    // may not have it loaded, in which case the next DB load serves the tombstone).
    Server->MarkMessageDeleted(ChannelId, MessageId);

    LOG_INFO("Message " << MessageId << " soft-deleted (tombstoned) in channel " << ChannelId
             << " in server " << ServerId << " by user " << RequestedByUserId);
    return EDeleteServerMessageResult::Success;
}

std::vector<FServerMessage> FServersManager::GetChannelMessages(const Uint64 ServerId, const Uint64 ChannelId, const Uint64 BeforeTimestamp, const Uint32 Limit)
{
    const std::shared_ptr<FServer> Server = GetServerById(ServerId);
    if (!Server)
    {
        return {};
    }

    // Try cache first
    std::vector<FServerMessage> CachedMessages = Server->GetChannelMessages(ChannelId, BeforeTimestamp, Limit);
    if (!CachedMessages.empty())
    {
        return CachedMessages;
    }

    // Load from DB with timestamp pagination
    DownloadMessagesFromDB(ChannelId, Server, BeforeTimestamp, Limit);
    return Server->GetChannelMessages(ChannelId, BeforeTimestamp, Limit);
}

std::string FServersManager::CreateInvite(const Uint64 ServerId, const Uint64 CreatedByUserId,
                                          Uint32 MaxUses, Uint32 ExpiresInSeconds)
{
    const std::shared_ptr<FServer> Server = GetServerById(ServerId);
    if (!Server)
    {
        LOG_ERROR("CreateInvite: Server not found: " << ServerId);
        return "";
    }

    // Check permission: user must have CAN_CREATE_INVITES or be the owner
    if (!UserHasPermission(ServerId, CreatedByUserId, EServerPermission::CAN_CREATE_INVITES))
    {
        LOG_WARN("CreateInvite: User " << CreatedByUserId << " lacks CAN_CREATE_INVITES permission"
                 << " in server " << ServerId);
        return "";
    }

    // Resolve defaults from backend settings
    const FBackendSettings* Settings = FGlobalDefines::GEngine->GetBackendSettings();

    if (MaxUses == 0)
        MaxUses = static_cast<Uint32>(Settings->GetInviteDefaultMaxUses());

    if (ExpiresInSeconds == 0)
        ExpiresInSeconds = static_cast<Uint32>(Settings->GetInviteDefaultExpiresInSeconds());

    // Clamp expiration to the hard maximum (12 months)
    const Uint32 MaxExpiry = static_cast<Uint32>(Settings->GetInviteMaxExpiresInSeconds());
    if (ExpiresInSeconds > MaxExpiry)
    {
        LOG_WARN("CreateInvite: Requested expiry " << ExpiresInSeconds
                 << "s exceeds max " << MaxExpiry << "s, clamping");
        ExpiresInSeconds = MaxExpiry;
    }

    // Enforce per-server invite cap (only count active, non-expired invites)
    const int32 MaxInvites = Settings->GetMaxInvitesPerServer();
    if (MaxInvites > 0)
    {
        const int32 ActiveCount = GetActiveInviteCountForServer(ServerId);
        if (ActiveCount >= MaxInvites)
        {
            LOG_WARN("CreateInvite: Server " << ServerId << " has reached max invites ("
                     << ActiveCount << "/" << MaxInvites << ")");
            return "";
        }
    }

    std::string InviteCode = GenerateInviteCode();

    if (!UploadInviteToDB(InviteCode, ServerId, CreatedByUserId, MaxUses, ExpiresInSeconds))
    {
        LOG_ERROR("CreateInvite: Failed to upload invite to DB");
        return "";
    }

    {
        std::unique_lock Lock(InviteMapMutex);
        InviteCodeToServerId[InviteCode] = ServerId;
    }

    LOG_INFO("Invite " << InviteCode << " created for server " << ServerId
             << " by user " << CreatedByUserId
             << " (maxUses=" << MaxUses << ", expiresIn=" << ExpiresInSeconds << "s)");

    return InviteCode;
}

std::shared_ptr<FServer> FServersManager::JoinViaInvite(const std::string& InviteCode, Uint64 UserId,
                                                         const std::string& UserName,
                                                         const std::string& ClientIp,
                                                         std::string* OutError)
{
    // --- Abuse protection: check if IP is banned ---
    FAbuseProtection* AbuseProtection = FGlobalDefines::GEngine->GetAbuseProtection();
    if (!ClientIp.empty())
    {
        const Uint64 BanRemaining = AbuseProtection->IsInviteAbuseBanned(ClientIp);
        if (BanRemaining > 0)
        {
            LOG_WARN("JoinViaInvite: IP " << ClientIp << " is banned for " << BanRemaining << "s");
            if (OutError) *OutError = "abuse_ban";
            return nullptr;
        }
    }

    Uint64 ServerId = 0;
    bool bInviteValid = false;

    // Check in-memory cache first
    {
        std::shared_lock Lock(InviteMapMutex);
        auto Iter = InviteCodeToServerId.find(InviteCode);
        if (Iter != InviteCodeToServerId.end())
        {
            ServerId = Iter->second;
        }
    }

    // If not in cache, query DB (ConsumeInviteFromDB also validates expiry & usage limits)
    if (ServerId == 0)
    {
        if (ConsumeInviteFromDB(InviteCode, ServerId))
        {
            bInviteValid = true;
        }
    }
    else
    {
        // Found in cache, but still need to consume in DB to validate limits.
        // Use DbServerId from DB as the authoritative server ID (cache could be stale).
        Uint64 DbServerId = 0;
        if (ConsumeInviteFromDB(InviteCode, DbServerId))
        {
            bInviteValid = true;

            // Use the DB-authoritative server ID. If cache was stale, update it.
            if (DbServerId != ServerId)
            {
                LOG_WARN("JoinViaInvite: Cached ServerId (" << ServerId
                         << ") differs from DB (" << DbServerId << "), using DB value");
                ServerId = DbServerId;
                {
                    std::unique_lock Lock(InviteMapMutex);
                    InviteCodeToServerId[InviteCode] = DbServerId;
                }
            }
        }
        else
        {
            // DB rejected (expired or max uses), remove from cache
            {
                std::unique_lock Lock(InviteMapMutex);
                InviteCodeToServerId.erase(InviteCode);
            }
        }
    }

    if (!bInviteValid)
    {
        // --- Abuse protection: record failed attempt ---
        if (!ClientIp.empty())
        {
            const bool bTriggeredBan = AbuseProtection->AddInviteAbuseAttempt(ClientIp);
            if (bTriggeredBan)
            {
                LOG_WARN("JoinViaInvite: IP " << ClientIp << " banned after too many failed invite attempts");
                if (OutError) *OutError = "abuse_ban";
            }
            else
            {
                if (OutError) *OutError = "invalid";
            }
        }
        else
        {
            if (OutError) *OutError = "invalid";
        }

        LOG_ERROR("JoinViaInvite: Invalid or expired invite code");
        return nullptr;
    }

    const std::shared_ptr<FServer> Server = GetServerById(ServerId);
    if (!Server)
    {
        LOG_ERROR("JoinViaInvite: Server not found: " << ServerId);
        if (OutError) *OutError = "server_not_found";
        return nullptr;
    }

    // New members via invite get zero permissions by default (can chat but no special actions)
    if (!AddUserToServer(ServerId, UserId, UserName, 0))
    {
        LOG_ERROR("JoinViaInvite: Failed to add user to server");
        if (OutError) *OutError = "join_failed";
        return nullptr;
    }

    // --- Abuse protection: clear records on successful join ---
    if (!ClientIp.empty())
    {
        AbuseProtection->ClearInviteAbuseForIp(ClientIp);
    }

    return Server;
}

bool FServersManager::DeleteInvite(const Uint64 ServerId, const std::string& InviteCode,
                                    const Uint64 RequestedByUserId)
{
    const std::shared_ptr<FServer> Server = GetServerById(ServerId);
    if (!Server)
    {
        LOG_ERROR("DeleteInvite: Server not found: " << ServerId);
        return false;
    }

    // Check permission: user must have CAN_CREATE_INVITES or be the owner
    if (!UserHasPermission(ServerId, RequestedByUserId, EServerPermission::CAN_CREATE_INVITES))
    {
        LOG_WARN("DeleteInvite: User " << RequestedByUserId << " lacks CAN_CREATE_INVITES permission"
                 << " in server " << ServerId);
        return false;
    }

    // Delete from DB
    if (!DeleteInviteFromDB(InviteCode, ServerId))
    {
        LOG_ERROR("DeleteInvite: Failed to delete invite " << InviteCode << " from DB");
        return false;
    }

    // Remove from in-memory cache
    {
        std::unique_lock Lock(InviteMapMutex);
        InviteCodeToServerId.erase(InviteCode);
    }

    LOG_INFO("Invite " << InviteCode << " deleted from server " << ServerId
             << " by user " << RequestedByUserId);

    return true;
}

std::vector<FInviteInfo> FServersManager::ListInvites(const Uint64 ServerId, const Uint64 RequestedByUserId,
                                                       Uint32 Start, Uint32 Count,
                                                       Uint32* OutTotal)
{
    const std::shared_ptr<FServer> Server = GetServerById(ServerId);
    if (!Server)
    {
        LOG_ERROR("ListInvites: Server not found: " << ServerId);
        return {};
    }

    // Check permission: user must have CAN_CREATE_INVITES or be the owner
    if (!UserHasPermission(ServerId, RequestedByUserId, EServerPermission::CAN_CREATE_INVITES))
    {
        LOG_WARN("ListInvites: User " << RequestedByUserId << " lacks CAN_CREATE_INVITES permission"
                 << " in server " << ServerId);
        return {};
    }

    // Clamp pagination parameters
    if (Count == 0) Count = 50;
    else if (Count > 200) Count = 200;

    std::vector<FInviteInfo> Invites;
    Uint32 Total = 0;

    if (!ListInvitesFromDB(ServerId, Start, Count, Invites, Total))
    {
        LOG_ERROR("ListInvites: Failed to query invites from DB for server " << ServerId);
        return {};
    }

    if (OutTotal)
    {
        *OutTotal = Total;
    }

    return Invites;
}

void FServersManager::JoinVoiceChannel(const Uint64 ServerId, const Uint64 ChannelId, const Uint64 UserId)
{
    const std::shared_ptr<FServer> Server = GetServerById(ServerId);
    if (!Server)
    {
        return;
    }

    const std::shared_ptr<FServerChannel> Channel = Server->GetChannel(ChannelId);
    if (!Channel || Channel->ChannelType != EServerChannelType::Voice)
    {
        return;
    }

    std::unique_lock Lock(Server->GetMutex());
    // Add user to connected users if not already there
    std::vector<Uint64>& Users = Channel->ConnectedUsers;
    if (std::ranges::find(Users, UserId) == Users.end())
    {
        Users.push_back(UserId);
    }
}

void FServersManager::LeaveVoiceChannel(const Uint64 ServerId, const Uint64 ChannelId, const Uint64 UserId)
{
    const std::shared_ptr<FServer> Server = GetServerById(ServerId);
    if (!Server)
    {
        return;
    }

    const std::shared_ptr<FServerChannel> Channel = Server->GetChannel(ChannelId);
    if (!Channel)
    {
        return;
    }

    std::unique_lock Lock(Server->GetMutex());
    std::vector<Uint64>& Users = Channel->ConnectedUsers;
    Users.erase(std::ranges::remove(Users, UserId).begin(), Users.end());
}

std::vector<Uint64> FServersManager::GetVoiceChannelConnectedUsers(const Uint64 ServerId, const Uint64 ChannelId)
{
    std::vector<Uint64> Result;

    const std::shared_ptr<FServer> Server = GetServerById(ServerId);
    if (!Server)
    {
        return Result;
    }

    const std::shared_ptr<FServerChannel> Channel = Server->GetChannel(ChannelId);
    if (!Channel || Channel->ChannelType != EServerChannelType::Voice)
    {
        return Result;
    }

    // Thread-safe snapshot: ConnectedUsers is written under ServerMutex by
    // JoinVoiceChannel/LeaveVoiceChannel, so read it under a shared lock.
    std::shared_lock Lock(Server->GetMutex());
    Result = Channel->ConnectedUsers;
    return Result;
}

std::vector<std::pair<Uint64, Uint64>> FServersManager::GetUserVoiceChannels(const Uint64 UserId)
{
    std::vector<std::pair<Uint64, Uint64>> Result;

    // Get all server IDs this user is a member of
    const std::vector<Uint64> ServerIds = GetUserServerIds(UserId);

    for (Uint64 ServerId : ServerIds)
    {
        const std::shared_ptr<FServer> Server = GetServerById(ServerId);
        if (!Server)
        {
            continue;
        }

        // Check each voice channel for this user
        std::vector<std::shared_ptr<FServerChannel>> Channels = Server->GetAllChannels();
        for (const std::shared_ptr<FServerChannel>& Channel : Channels)
        {
            if (Channel->ChannelType != EServerChannelType::Voice)
            {
                continue;
            }

            // ConnectedUsers is mutated under ServerMutex by Join/LeaveVoiceChannel
            // and LeaveAllVoiceChannelsInServer, so snapshot it under a shared lock.
            std::vector<Uint64> Users;
            {
                std::shared_lock Lock(Server->GetMutex());
                Users = Channel->ConnectedUsers;
            }
            if (std::ranges::find(Users, UserId) != Users.end())
            {
                Result.emplace_back(ServerId, Channel->ChannelId);
            }
        }
    }

    return Result;
}

std::vector<Uint64> FServersManager::LeaveAllVoiceChannelsInServer(const Uint64 ServerId, const Uint64 UserId)
{
    std::vector<Uint64> LeftChannelIds;

    const std::shared_ptr<FServer> Server = GetServerById(ServerId);
    if (!Server)
    {
        return LeftChannelIds;
    }

    const std::vector<std::shared_ptr<FServerChannel>> Channels = Server->GetAllChannels();
    for (const std::shared_ptr<FServerChannel>& Channel : Channels)
    {
        if (Channel->ChannelType != EServerChannelType::Voice)
        {
            continue;
        }

        std::unique_lock Lock(Server->GetMutex());
        std::vector<Uint64>& Users = Channel->ConnectedUsers;
        const auto It = std::ranges::find(Users, UserId);
        if (It != Users.end())
        {
            Users.erase(It);
            LeftChannelIds.push_back(Channel->ChannelId);
        }
    }

    return LeftChannelIds;
}

void FServersManager::EnsureServerLoaded(const Uint64 ServerId)
{
    GetServerById(ServerId); // This triggers download if not cached
}

// ========== DB Operations ==========

bool FServersManager::UploadNewServerToDB(const std::shared_ptr<FServer>& ServerPtr)
{
    FDataBaseConnect Connect;
    if (!Connect.IsConnected())
    {
        LOG_ERROR("UploadNewServerToDB: No DB connection");
        return false;
    }

    try
    {
        soci::session& Session = Connect.GetSession();

        Session << "INSERT INTO servers (name, owner_id, token, created_at) VALUES (:name, :owner, :token, :created)",
            soci::use(ServerPtr->GetServerName()),
            soci::use(ServerPtr->GetOwnerId()),
            soci::use(ServerPtr->GetToken()),
            soci::use(ServerPtr->GetCreatedAt());

        // Get the last inserted ID
        long long LastId = 0;
        Session.get_last_insert_id("servers", LastId);
        ServerPtr->SetServerId(static_cast<Uint64>(LastId));

        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("UploadNewServerToDB error: " << e.what());
        return false;
    }
}

bool FServersManager::DeleteServerFromDB(Uint64 InServerId)
{
    FDataBaseConnect Connect;
    if (!Connect.IsConnected())
    {
        return false;
    }

    try
    {
        soci::session& Session = Connect.GetSession();

        // Delete in order: messages -> channels -> members -> invites -> server
        Session << "DELETE FROM server_messages WHERE channel_id IN (SELECT id FROM server_channels WHERE server_id = :sid)",
            soci::use(InServerId);
        Session << "DELETE FROM server_channels WHERE server_id = :sid",
            soci::use(InServerId);
        Session << "DELETE FROM server_members WHERE server_id = :sid",
            soci::use(InServerId);
        Session << "DELETE FROM server_invites WHERE server_id = :sid",
            soci::use(InServerId);
        Session << "DELETE FROM servers WHERE id = :sid",
            soci::use(InServerId);

        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("DeleteServerFromDB error: " << e.what());
        return false;
    }
}

bool FServersManager::UploadChannelToDB(Uint64 ServerId, FServerChannel& Channel)
{
    FDataBaseConnect Connect;
    if (!Connect.IsConnected())
    {
        return false;
    }

    try
    {
        soci::session& Session = Connect.GetSession();

        std::string ChannelTypeStr = (Channel.ChannelType == EServerChannelType::Text) ? "text" : "voice";

        Session << "INSERT INTO server_channels (server_id, name, type, position) VALUES (:sid, :name, :type, :pos)",
            soci::use(ServerId),
            soci::use(Channel.ChannelName),
            soci::use(ChannelTypeStr),
            soci::use(Channel.Position);

        long long LastId = 0;
        Session.get_last_insert_id("server_channels", LastId);
        Channel.ChannelId = static_cast<Uint64>(LastId);

        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("UploadChannelToDB error: " << e.what());
        return false;
    }
}

bool FServersManager::DeleteChannelFromDB(Uint64 ServerId, Uint64 ChannelId)
{
    FDataBaseConnect Connect;
    if (!Connect.IsConnected())
    {
        return false;
    }

    try
    {
        soci::session& Session = Connect.GetSession();

        Session << "DELETE FROM server_channels WHERE id = :cid AND server_id = :sid",
            soci::use(ChannelId),
            soci::use(ServerId);

        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("DeleteChannelFromDB error: " << e.what());
        return false;
    }
}

bool FServersManager::UpdateChannelNameInDB(Uint64 ServerId, Uint64 ChannelId, const std::string& NewName)
{
    FDataBaseConnect Connect;
    if (!Connect.IsConnected())
    {
        return false;
    }

    try
    {
        soci::session& Session = Connect.GetSession();

        Session << "UPDATE server_channels SET name = :name WHERE id = :cid AND server_id = :sid",
            soci::use(NewName),
            soci::use(ChannelId),
            soci::use(ServerId);

        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("UpdateChannelNameInDB error: " << e.what());
        return false;
    }
}

bool FServersManager::UploadMessageToDB(const FServerMessage& Message, Uint64& OutMessageId)
{
    FDataBaseConnect Connect;
    if (!Connect.IsConnected())
    {
        return false;
    }

    try
    {
        soci::session& Session = Connect.GetSession();

        // Encrypt the message content for at-rest DB storage; write encryption flag separately
        const FBackendSettings* Settings = FGlobalDefines::GEngine->GetBackendSettings();
        const bool bEncrypted = Settings->IsEncryptionEnabled();
        const std::string StoredContent = bEncrypted
            ? Settings->EncryptMessage(Message.Content)
            : Message.Content;

        // Message status: Sent=0
        const int MsgStatus = 0;

        Session << "INSERT INTO server_messages (channel_id, sender_id, content, created_at, text_status, is_encrypted, message_type) VALUES (:cid, :sid, :content, :created, :status, :encrypted, :type)",
            soci::use(Message.ChannelId),
            soci::use(Message.SenderId),
            soci::use(StoredContent),
            soci::use(Message.CreatedAt),
            soci::use(MsgStatus),
            soci::use(static_cast<int>(bEncrypted ? 1 : 0)),
            soci::use(static_cast<int>(Message.MessageType));

        long long LastId = 0;
        Session.get_last_insert_id("server_messages", LastId);
        OutMessageId = static_cast<Uint64>(LastId);

        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("UploadMessageToDB error: " << e.what());
        return false;
    }
}

bool FServersManager::MarkMessageDeletedInDB(const Uint64 MessageId, const Uint64 ChannelId)
{
    FDataBaseConnect Connect;
    if (!Connect.IsConnected())
    {
        return false;
    }

    try
    {
        soci::session& Session = Connect.GetSession();

        // Soft delete: keep the row but replace content with the tombstone and
        // flag it as deleted. is_encrypted is cleared because the placeholder is
        // plain text and must not be decrypted on read.
        const std::string TombstoneText(DeletedMessagePlaceholder);
        const int DeletedStatus = 2; // 0=Sent, 1=Edited, 2=Deleted

        soci::statement St = (Session.prepare <<
            "UPDATE server_messages SET content = :content, text_status = :status, is_encrypted = 0 "
            "WHERE id = :msgId AND channel_id = :channelId",
            soci::use(TombstoneText, "content"),
            soci::use(DeletedStatus, "status"),
            soci::use(MessageId, "msgId"),
            soci::use(ChannelId, "channelId"));

        St.execute();

        const long long Affected = St.get_affected_rows();
        return Affected > 0;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("MarkMessageDeletedInDB error: " << e.what());
        return false;
    }
}

bool FServersManager::GetServerMessageOwnerFromDB(const Uint64 MessageId, Uint64& OutChannelId, Uint64& OutSenderId)
{
    FDataBaseConnect Connect;
    if (!Connect.IsConnected())
    {
        return false;
    }

    try
    {
        soci::session& Session = Connect.GetSession();

        long long ChannelId = 0;
        long long SenderId = 0;
        soci::indicator SenderInd;

        Session << "SELECT channel_id, sender_id FROM server_messages WHERE id = :msgId",
            soci::into(ChannelId),
            soci::into(SenderId, SenderInd),
            soci::use(MessageId);

        if (!Session.got_data())
        {
            return false;
        }

        OutChannelId = static_cast<Uint64>(ChannelId);
        // sender_id is NULLable (ON DELETE SET NULL); a NULL sender means the author's
        // account is gone, so only the server owner can delete it.
        OutSenderId = (SenderInd == soci::i_null) ? 0 : static_cast<Uint64>(SenderId);

        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("GetServerMessageOwnerFromDB error: " << e.what());
        return false;
    }
}

bool FServersManager::UploadMemberToDB(Uint64 ServerId, Uint64 UserId, Uint64 Permissions)
{
    FDataBaseConnect Connect;
    if (!Connect.IsConnected())
    {
        return false;
    }

    try
    {
        soci::session& Session = Connect.GetSession();
        Session << "INSERT INTO server_members (server_id, user_id, permissions) VALUES (:sid, :uid, :perm)"
                   " ON DUPLICATE KEY UPDATE permissions = :perm2",
            soci::use(ServerId),
            soci::use(UserId),
            soci::use(Permissions),
            soci::use(Permissions);
        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("UploadMemberToDB error: " << e.what());
        return false;
    }
}

bool FServersManager::RemoveMemberFromDB(Uint64 ServerId, Uint64 UserId)
{
    FDataBaseConnect Connect;
    if (!Connect.IsConnected())
    {
        return false;
    }

    try
    {
        soci::session& Session = Connect.GetSession();
        Session << "DELETE FROM server_members WHERE server_id = :sid AND user_id = :uid",
            soci::use(ServerId),
            soci::use(UserId);
        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("RemoveMemberFromDB error: " << e.what());
        return false;
    }
}

bool FServersManager::UpdateMemberPermissionsInDB(Uint64 ServerId, Uint64 UserId, Uint64 NewPermissions)
{
    FDataBaseConnect Connect;
    if (!Connect.IsConnected())
    {
        return false;
    }

    try
    {
        soci::session& Session = Connect.GetSession();
        Session << "UPDATE server_members SET permissions = :perm WHERE server_id = :sid AND user_id = :uid",
            soci::use(NewPermissions),
            soci::use(ServerId),
            soci::use(UserId);
        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("UpdateMemberPermissionsInDB error: " << e.what());
        return false;
    }
}

bool FServersManager::UploadInviteToDB(const std::string& InviteCode, Uint64 ServerId,
                                        Uint64 CreatedByUserId, Uint32 MaxUses, const Uint32 ExpiresInSeconds)
{
    FDataBaseConnect Connect;
    if (!Connect.IsConnected())
    {
        return false;
    }

    // Compute expiration timestamp
    const auto ExpiresTime = std::chrono::system_clock::now() + std::chrono::seconds(ExpiresInSeconds);
    const std::string ExpiresStr = FormatTimestamp(ExpiresTime);

    try
    {
        soci::session& Session = Connect.GetSession();

        Session << "INSERT INTO server_invites (invite_code, server_id, created_by, max_uses, expires_at)"
                   " VALUES (:code, :sid, :uid, :max_uses, :expires)",
            soci::use(InviteCode),
            soci::use(ServerId),
            soci::use(CreatedByUserId),
            soci::use(MaxUses),
            soci::use(ExpiresStr);

        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("UploadInviteToDB error: " << e.what());
        return false;
    }
}

bool FServersManager::ConsumeInviteFromDB(const std::string& InviteCode, Uint64& OutServerId)
{
    FDataBaseConnect Connect;
    if (!Connect.IsConnected())
    {
        return false;
    }

    // Session reference declared outside try so it's accessible in the catch block
    // for proper rollback on the same connection (transactions are connection-scoped).
    soci::session* SessionPtr = nullptr;

    try
    {
        soci::session& Session = Connect.GetSession();
        SessionPtr = &Session;

        // Wrap in a transaction to make the check-and-increment atomic.
        // Without this, two concurrent calls could both pass the WHERE clause
        // and both increment, exceeding max_uses.
        Session << "START TRANSACTION";

        // SELECT ... FOR UPDATE locks the row to prevent concurrent consumption
        long long ServerId = 0;
        soci::indicator Ind;

        Session << "SELECT server_id FROM server_invites"
                   " WHERE invite_code = :code"
                   "   AND expires_at > UTC_TIMESTAMP()"
                   "   AND current_uses < max_uses"
                   " FOR UPDATE",
            soci::into(ServerId, Ind),
            soci::use(InviteCode);

        if (Session.got_data() && Ind == soci::i_ok)
        {
            OutServerId = static_cast<Uint64>(ServerId);

            // Increment current_uses within the same transaction
            Session << "UPDATE server_invites SET current_uses = current_uses + 1"
                       " WHERE invite_code = :code",
                soci::use(InviteCode);

            Session << "COMMIT";
            return true;
        }

        // No valid invite found - rollback the empty transaction
        Session << "ROLLBACK";
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("ConsumeInviteFromDB error: " << e.what());

        // Attempt rollback on the SAME connection (transactions are connection-scoped).
        // Only try if we still have a valid session pointer from within the try block.
        if (SessionPtr != nullptr)
        {
            try
            {
                (*SessionPtr) << "ROLLBACK";
            }
            catch (...)
            {
                // Connection may be broken - nothing more we can do.
            }
        }
    }

    return false;
}

int32 FServersManager::GetActiveInviteCountForServer(const Uint64 ServerId)
{
    FDataBaseConnect Connect;
    if (!Connect.IsConnected())
    {
        return 0;
    }

    try
    {
        soci::session& Session = Connect.GetSession();

        int Count = 0;
        Session << "SELECT COUNT(*) FROM server_invites"
                   " WHERE server_id = :sid AND expires_at > UTC_TIMESTAMP()",
            soci::into(Count),
            soci::use(ServerId);

        return Count;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("GetActiveInviteCountForServer error: " << e.what());
        return 0;
    }
}

uint32 FServersManager::GetNextChannelPosition(const Uint64 ServerId)
{
    FDataBaseConnect Connect;
    if (!Connect.IsConnected())
    {
        return 0;
    }

    try
    {
        soci::session& Session = Connect.GetSession();

        int MaxPos = -1;
        soci::indicator Ind;
        Session << "SELECT MAX(position) FROM server_channels WHERE server_id = :sid",
            soci::into(MaxPos, Ind),
            soci::use(ServerId);

        // If no channels exist (Ind is null), start at 0. Otherwise max + 1.
        return (Ind == soci::i_ok && MaxPos >= 0) ? (MaxPos + 1) : 0;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("GetNextChannelPosition error: " << e.what());
        return 0;
    }
}

void FServersManager::RenumberChannelPositions(const Uint64 ServerId)
{
    std::shared_ptr<FServer> Server = GetServerById(ServerId);
    if (!Server)
    {
        return;
    }

    // Get channels sorted by current position
    std::vector<std::shared_ptr<FServerChannel>> Channels = Server->GetAllChannels();
    if (Channels.empty())
    {
        return;
    }

    FDataBaseConnect Connect;
    if (!Connect.IsConnected())
    {
        LOG_ERROR("RenumberChannelPositions: Database connection failed");
        return;
    }

    // Apply the new in-memory positions under the server lock (also invalidates
    // the sorted-channel cache). The DB updates below use the loop index.
    {
        std::unordered_map<Uint64, uint32> NewPositions;
        NewPositions.reserve(Channels.size());
        for (int32 i = 0; i < static_cast<int32>(Channels.size()); ++i)
        {
            NewPositions[Channels[i]->ChannelId] = static_cast<uint32>(i);
        }
        Server->SetChannelPositions(NewPositions);
    }

    try
    {
        soci::session& Session = Connect.GetSession();

        for (int32 i = 0; i < static_cast<int32>(Channels.size()); ++i)
        {
            Session << "UPDATE server_channels SET position = :pos WHERE id = :cid AND server_id = :sid",
                soci::use(i),
                soci::use(Channels[i]->ChannelId),
                soci::use(ServerId);
        }
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("RenumberChannelPositions error: " << e.what());
    }
}

bool FServersManager::DeleteInviteFromDB(const std::string& InviteCode, const Uint64 ServerId)
{
    FDataBaseConnect Connect;
    if (!Connect.IsConnected())
    {
        return false;
    }

    try
    {
        soci::session& Session = Connect.GetSession();

        // Only delete if the invite belongs to the specified server (security: prevent
        // a user from deleting invites for servers they aren't a member of via brute force).
        // Use soci::statement to get affected_rows (soci::session does NOT have this method).
        soci::statement St = (Session.prepare <<
            "DELETE FROM server_invites WHERE invite_code = :code AND server_id = :sid",
            soci::use(InviteCode),
            soci::use(ServerId));

        St.execute();

        // get_affected_rows() returns long long - no-arg, return-value form (SOCI 4.0+).
        // Confirmed by ConversationsManager.cpp:493: if (St.get_affected_rows() == 0)
        const long long Affected = St.get_affected_rows();

        return Affected > 0;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("DeleteInviteFromDB error: " << e.what());
        return false;
    }
}

bool FServersManager::ListInvitesFromDB(const Uint64 ServerId, const Uint32 Start, const Uint32 Count,
                                         std::vector<FInviteInfo>& OutInvites, Uint32& OutTotal)
{
    FDataBaseConnect Connect;
    if (!Connect.IsConnected())
    {
        return false;
    }

    OutTotal = 0;
    OutInvites.clear();

    try
    {
        soci::session& Session = Connect.GetSession();

        // First: count total invites for this server
        Uint32 TotalCount = 0;
        Session << "SELECT COUNT(*) FROM server_invites WHERE server_id = :sid",
            soci::into(TotalCount),
            soci::use(ServerId);
        OutTotal = TotalCount;

        if (TotalCount == 0)
        {
            return true; // No invites, but operation succeeded
        }

        // Second: fetch the paginated slice, ordered by creation time (newest first).
        // Secondary sort by invite_code ASC ensures deterministic ordering when
        // multiple invites share the same created_at timestamp.
        std::string InviteCode;
        long long CreatedBy = 0;
        Uint32 MaxUses = 0;
        Uint32 CurrentUses = 0;
        std::string CreatedAt;
        std::string ExpiresAt;

        soci::statement St = (Session.prepare <<
            "SELECT invite_code, created_by, max_uses, current_uses, created_at, expires_at "
            "FROM server_invites "
            "WHERE server_id = :sid "
            "ORDER BY created_at DESC, invite_code ASC "
            "LIMIT :lim OFFSET :off",
            soci::into(InviteCode),
            soci::into(CreatedBy),
            soci::into(MaxUses),
            soci::into(CurrentUses),
            soci::into(CreatedAt),
            soci::into(ExpiresAt),
            soci::use(ServerId),
            soci::use(Count),
            soci::use(Start));

        St.execute();
        while (St.fetch())
        {
            FInviteInfo Info;
            Info.InviteCode = InviteCode;
            Info.CreatedBy = static_cast<Uint64>(CreatedBy);
            Info.MaxUses = MaxUses;
            Info.CurrentUses = CurrentUses;
            Info.CreatedAt = CreatedAt;
            Info.ExpiresAt = ExpiresAt;
            OutInvites.push_back(Info);
        }

        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("ListInvitesFromDB error: " << e.what());
        return false;
    }
}


bool FServersManager::DownloadServerFromDB(Uint64 ServerId)
{
    FDataBaseConnect Connect;
    if (!Connect.IsConnected())
    {
        return false;
    }

    try
    {
        soci::session& Session = Connect.GetSession();

        std::string Name, Token;
        unsigned long long CreatedAt = 0;
        long long OwnerId = 0;
        soci::indicator IndName, IndToken;

        Session << "SELECT name, owner_id, token, created_at FROM servers WHERE id = :sid",
            soci::into(Name, IndName),
            soci::into(OwnerId),
            soci::into(Token, IndToken),
            soci::into(CreatedAt),
            soci::use(ServerId);

        if (!Session.got_data())
        {
            return false;
        }

        const std::shared_ptr<FServer> Server = std::make_shared<FServer>();
        Server->SetServerId(ServerId);
        Server->SetServerName(Name);
        Server->SetOwnerId(static_cast<Uint64>(OwnerId));
        Server->SetToken(Token);
        Server->SetCreatedAt(CreatedAt);

        // Download channels
        DownloadChannelsFromDB(ServerId, Server);

        // Download members (with usernames from users table)
        DownloadMembersFromDB(ServerId, Server);

        {
            std::unique_lock Lock(ServersMapMutex);
            ServersMap[ServerId] = Server;
        }

        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("DownloadServerFromDB error: " << e.what());
        return false;
    }
}

bool FServersManager::DownloadChannelsFromDB(Uint64 ServerId, const std::shared_ptr<FServer>& Server)
{
    FDataBaseConnect Connect;
    if (!Connect.IsConnected())
    {
        return false;
    }

    try
    {
        soci::session& Session = Connect.GetSession();

        long long ChannelId = 0;
        std::string ChannelName, ChannelType;
        int32 Position = 0;
        soci::indicator IndId, IndName, IndType, IndPos;

        soci::statement St = (Session.prepare <<
            "SELECT id, name, type, position FROM server_channels WHERE server_id = :sid ORDER BY position ASC",
            soci::into(ChannelId, IndId),
            soci::into(ChannelName, IndName),
            soci::into(ChannelType, IndType),
            soci::into(Position, IndPos),
            soci::use(ServerId));

        St.execute();
        while (St.fetch())
        {
            FServerChannel Channel;
            Channel.ChannelId = static_cast<Uint64>(ChannelId);
            Channel.ServerId = ServerId;
            Channel.ChannelName = ChannelName;
            Channel.ChannelType = (ChannelType == "voice") ? EServerChannelType::Voice : EServerChannelType::Text;
            Channel.Position = (IndPos == soci::i_ok) ? Position : 0;
            Server->AddChannel(Channel);
        }

        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("DownloadChannelsFromDB error: " << e.what());
        return false;
    }
}

bool FServersManager::DownloadMembersFromDB(Uint64 ServerId, const std::shared_ptr<FServer>& Server)
{
    FDataBaseConnect Connect;
    if (!Connect.IsConnected())
    {
        return false;
    }

    try
    {
        soci::session& Session = Connect.GetSession();

        long long UserId = 0;
        long long Permissions = 0;
        std::string UserName;
        soci::indicator IndUserId, IndUserName, IndPermissions;

        // JOIN with users table to get usernames, also fetch permissions
        soci::statement St = (Session.prepare <<
            "SELECT sm.user_id, u.username, sm.permissions FROM server_members sm "
            "JOIN users u ON sm.user_id = u.id "
            "WHERE sm.server_id = :sid",
            soci::into(UserId, IndUserId),
            soci::into(UserName, IndUserName),
            soci::into(Permissions, IndPermissions),
            soci::use(ServerId));

        St.execute();
        while (St.fetch())
        {
            FServerMember Member;
            Member.UserId = static_cast<Uint64>(UserId);
            Member.UserName = IndUserName == soci::i_ok ? UserName : "";
            Member.Permissions = static_cast<Uint64>(Permissions);
            Member.Status = "offline"; // Default; will be updated via WebSocket status events
            Server->AddMember(Member);
        }

        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("DownloadMembersFromDB error: " << e.what());
        return false;
    }
}

bool FServersManager::DownloadMessagesFromDB(Uint64 ChannelId, const std::shared_ptr<FServer>& Server, Uint64 BeforeTimestamp, Uint32 Limit)
{
    FDataBaseConnect Connect;
    if (!Connect.IsConnected())
    {
        return false;
    }

    try
    {
        soci::session& Session = Connect.GetSession();

        long long MessageId = 0, SenderId = 0;
        std::string Content, SenderName;
        unsigned long long CreatedAt = 0;
        soci::indicator IndMsgId, IndSenderId, IndContent, IndSenderName;

        // Get encryption settings once for the whole batch
        const FBackendSettings* Settings = FGlobalDefines::GEngine->GetBackendSettings();
        int TextStatus = 0;
        int IsEncrypted = 0;
        int MessageType = 0;

        // Pagination: fetch messages before a timestamp, newest first
        if (BeforeTimestamp > 0)
        {
            soci::statement St = (Session.prepare <<
                "SELECT sm.id, sm.sender_id, u.username, sm.content, sm.created_at, sm.text_status, sm.is_encrypted, sm.message_type "
                "FROM server_messages sm "
                "JOIN users u ON sm.sender_id = u.id "
                "WHERE sm.channel_id = :cid AND sm.created_at < :before "
                "ORDER BY sm.id DESC LIMIT :lim",
                soci::into(MessageId, IndMsgId),
                soci::into(SenderId, IndSenderId),
                soci::into(SenderName, IndSenderName),
                soci::into(Content, IndContent),
                soci::into(CreatedAt),
                soci::into(TextStatus),
                soci::into(IsEncrypted),
                soci::into(MessageType),
                soci::use(ChannelId),
                soci::use(BeforeTimestamp),
                soci::use(Limit));

            St.execute();
            while (St.fetch())
            {
                FServerMessage Message;
                Message.MessageId = static_cast<Uint64>(MessageId);
                Message.ChannelId = ChannelId;
                Message.SenderId = static_cast<Uint64>(SenderId);
                Message.SenderName = IndSenderName == soci::i_ok ? SenderName : "";
                // Conditionally decrypt based on the is_encrypted column
                if (IsEncrypted != 0)
                {
                    Message.Content = Settings->DecryptMessage(Content, EMessageEncryptionStatus::Encrypted);
                }
                else
                {
                    Message.Content = Content;
                }
                Message.CreatedAt = CreatedAt;
                Message.MessageType = static_cast<EMessageType>(MessageType);
                Server->AddMessage(Message);
            }
        }
        else
        {
            // No timestamp filter: get the most recent messages
            soci::statement St = (Session.prepare <<
                "SELECT sm.id, sm.sender_id, u.username, sm.content, sm.created_at, sm.text_status, sm.is_encrypted, sm.message_type "
                "FROM server_messages sm "
                "JOIN users u ON sm.sender_id = u.id "
                "WHERE sm.channel_id = :cid "
                "ORDER BY sm.id DESC LIMIT :lim",
                soci::into(MessageId, IndMsgId),
                soci::into(SenderId, IndSenderId),
                soci::into(SenderName, IndSenderName),
                soci::into(Content, IndContent),
                soci::into(CreatedAt),
                soci::into(TextStatus),
                soci::into(IsEncrypted),
                soci::into(MessageType),
                soci::use(ChannelId),
                soci::use(Limit));

            St.execute();
            while (St.fetch())
            {
                FServerMessage Message;
                Message.MessageId = static_cast<Uint64>(MessageId);
                Message.ChannelId = ChannelId;
                Message.SenderId = static_cast<Uint64>(SenderId);
                Message.SenderName = IndSenderName == soci::i_ok ? SenderName : "";
                // Conditionally decrypt based on the is_encrypted column
                if (IsEncrypted != 0)
                {
                    Message.Content = Settings->DecryptMessage(Content, EMessageEncryptionStatus::Encrypted);
                }
                else
                {
                    Message.Content = Content;
                }
                Message.CreatedAt = CreatedAt;
                Message.MessageType = static_cast<EMessageType>(MessageType);
                Server->AddMessage(Message);
            }
        }

        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("DownloadMessagesFromDB error: " << e.what());
        return false;
    }
}

std::string FServersManager::GenerateServerToken()
{
    static constexpr int32 TokenLength = 32;
    return FEncryptionUtil::GenerateSecureSalt(TokenLength);
}

std::string FServersManager::GenerateInviteCode()
{
    static constexpr int32 RawLength = 8;
    const std::string Raw = FEncryptionUtil::GenerateSecureSalt(RawLength);
    return FEncryptionUtil::ToBaseN_Irreversible(Raw, FPredefinedCharsets::BASE62);
}

std::string FServersManager::FormatTimestamp(const std::chrono::system_clock::time_point& Time)
{
    const time_t TimeT = std::chrono::system_clock::to_time_t(Time);
    std::tm UtcTime{};

#ifdef _WIN32
    gmtime_s(&UtcTime, &TimeT);
#else
    gmtime_r(&TimeT, &UtcTime);
#endif

    std::ostringstream Oss;
    Oss << std::put_time(&UtcTime, "%Y-%m-%d %H:%M:%S");
    return Oss.str();
}
