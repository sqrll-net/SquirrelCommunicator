// Created by https://www.linkedin.com/in/przemek2122/ 2020-2026

#pragma once

#include "EngineCompat.h"
#include "SQRLLEncryption.h"

/** Database-level indicator of whether a stored message is encrypted at rest */
enum class EMessageEncryptionStatus : uint8
{
	Unencrypted = 0,
	Encrypted  = 1,
	MAX        = 2
};

/** Class for global backend settings */
class FBackendSettings
{
public:
    FBackendSettings();

    void LoadBackendSettings();

    std::shared_ptr<FIniObject> GetBackendSettingsIni() const { return BackendSettingsIniObject; }

    /** Max number of letters per message */
    int32 GetMaxMessageSize() const { return MaxMessageSize; }

    // --- Two-tier global rate limiting ---

    /** Tier 1: Max unauthenticated (no token) requests per IP per hour (default 300) */
    int32 GetUnauthenticatedRequestsPerHour() const { return UnauthenticatedRequestsPerHour; }

    /** Tier 2: Max authenticated (with token) requests per UserID per hour (default 2000) */
    int32 GetAuthenticatedRequestsPerHour() const { return AuthenticatedRequestsPerHour; }

    // --- WebSocket settings ---

    /** WebSocket idle timeout in seconds before uWS disconnects an inactive client (default 300 = 5 min) */
    int32 GetWebSocketIdleTimeoutSeconds() const { return WebSocketIdleTimeoutSeconds; }

    /**
     * Whether the WebSocket listener should trust the client-supplied
     * "x-forwarded-for" header for abuse/rate-limiting attribution. This must
     * remain FALSE unless the WebSocket port is reachable only through a
     * trusted reverse proxy (nginx/cloudflared) that overwrites the header.
     * When false, the real socket peer address is used, so a direct client
     * cannot spoof the header to evade rate limits or abuse bans.
     */
    bool GetTrustForwardedFor() const { return bTrustForwardedFor; }

    // --- Image service settings ---

    /**
     * How long (in seconds) a per-session image-service API key is kept before
     * it is invalidated and re-issued on the next login / reconnect. Bounds the
     * staleness window after an image-service restart (its key registry is RAM
     * only). Values <= 0 disable invalidation (keys are cached indefinitely).
     */
    int32 GetImageKeyInvalidationSeconds() const { return ImageKeyInvalidationSeconds; }

    /**
     * How often (in seconds) the backend polls the image service's /instance
     * endpoint to read its "instanceId" and detect a restart (which wipes
     * the service's RAM-only key registry, orphaning every issued per-session
     * key). On a detected instance change the backend drops all cached keys
     * and re-issues them on the next login / reconnect. Values <= 0 disable
     * the probe entirely (time-based invalidation still applies).
     */
    int32 GetImageInstanceProbeIntervalSeconds() const { return ImageInstanceProbeIntervalSeconds; }

    /**
     * Number of consecutive failed image-service HTTP calls that opens the
     * circuit breaker (after which key registration and instance probes fail
     * fast without an HTTP round-trip). Values <= 0 disable the breaker.
     */
    int32 GetImageServiceCircuitBreakerThreshold() const { return ImageServiceCircuitBreakerThreshold; }

    /**
     * How long (in seconds) the image-service circuit breaker stays open
     * before it half-opens to allow a single probe to test whether the
     * service is back. Values <= 0 mean the breaker, once tripped, stays
     * open until the backend is restarted.
     */
    int32 GetImageServiceCircuitBreakerCooldownSeconds() const { return ImageServiceCircuitBreakerCooldownSeconds; }

    // --- Voice service settings ---

    /**
     * Number of consecutive failed voice-service HTTP calls that opens the
     * circuit breaker (after which room checks / creates fail fast without an
     * HTTP round-trip, so a down voice service can't stall the WebSocket event
     * loop). Values <= 0 disable the breaker.
     */
    int32 GetVoiceServiceCircuitBreakerThreshold() const { return VoiceServiceCircuitBreakerThreshold; }

    /**
     * How long (in seconds) the voice-service circuit breaker stays open
     * before it half-opens to allow a single probe to test whether the
     * service is back. Values <= 0 mean the breaker, once tripped, stays
     * open until the backend is restarted.
     */
    int32 GetVoiceServiceCircuitBreakerCooldownSeconds() const { return VoiceServiceCircuitBreakerCooldownSeconds; }

    // --- Logging settings ---

    /**
     * Verbose logging level:
     *   0 = ERROR only
     *   1 = ERROR + WARN  (default, recommended for production)
     *   2 = ERROR + WARN + INFO
     *   3 = ERROR + WARN + INFO + VERBOSE
     *
     * NOTE: In DEBUG builds, ALL levels fire unconditionally regardless of this value —
     *       this ensures no log is missed during development.
     *
     * WARNING: Levels >= 2 (INFO and VERBOSE) involve JSON parsing and string formatting
     * on every WebSocket message, causing SIGNIFICANT CPU overhead under heavy traffic.
     * Never use level 2+ in production unless diagnosing a specific issue.
     */
    int32 GetVerboseLoggingLevel() const { return VerboseLoggingLevel; }

    // --- Invite settings ---

    /** Default max number of uses per invite */
    int32 GetInviteDefaultMaxUses() const { return InviteDefaultMaxUses; }

    /** Default invite expiration time in seconds */
    int32 GetInviteDefaultExpiresInSeconds() const { return InviteDefaultExpiresInSeconds; }

    /** Maximum allowed invite expiration time in seconds (hard cap, 12 months) */
    int32 GetInviteMaxExpiresInSeconds() const { return InviteMaxExpiresInSeconds; }

    /** Maximum number of active (non-expired) invites per server (default 10) */
    int32 GetMaxInvitesPerServer() const { return MaxInvitesPerServer; }

    // --- Invite abuse protection settings ---

    /** Max failed invite attempts before an IP is banned (default 10) */
    int32 GetInviteAbuseMaxAttempts() const { return InviteAbuseMaxAttempts; }

    /** Rolling window in seconds for counting failed invite attempts (default 120) */
    int32 GetInviteAbuseWindowSeconds() const { return InviteAbuseWindowSeconds; }

    /** Ban duration in seconds for invite abuse (default 3600 = 1 hour) */
    int32 GetInviteAbuseBanDurationSeconds() const { return InviteAbuseBanDurationSeconds; }

    // --- Invite hourly rate limits (simple per-IP counter, separate from rolling-window ban) ---

    /** Max invite creation requests per IP per hour (default 20) */
    int32 GetInviteCreateLimitPerHour() const { return InviteCreateLimitPerHour; }

    /** Max invite use attempts per IP per hour (default 30) */
    int32 GetInviteUseLimitPerHour() const { return InviteUseLimitPerHour; }

    // --- Registration rate limiting ---

    /** Max new account registrations per IP per hour (default 10) */
    int32 GetRegisterAccountLimitPerHour() const { return RegisterAccountLimitPerHour; }

    // --- Message retention settings ---

    /**
     * Number of most recent messages kept per private conversation and per
     * server text channel in the in-memory cache. When the periodic trim
     * runs, older cached messages are dropped from RAM only - the database is
     * never modified, so history stays fully accessible and is re-fetched on
     * demand when a client scrolls back. Values <= 0 disable the trim.
     * Disabled by default (the interval setting defaults to 0).
     */
    int32 GetMessageRetentionCount() const { return MessageRetentionCount; }

    /** How often (in seconds) the in-memory cache trim runs. Values <= 0 disable it. */
    int32 GetMessageRetentionCleanupIntervalSeconds() const { return MessageRetentionCleanupIntervalSeconds; }

    // --- Message encryption ---

    /** Path to the encryption key file (from INI). Relative to Assets/Config or absolute. */
    const std::string& GetMessageEncryptionKeyFilePath() const { return MessageEncryptionKeyFilePath; }

    /** Server-side message encryption key (BASE62). Empty = at-rest encryption disabled. */
    const std::string& GetMessageEncryptionKey() const { return MessageEncryptionKey; }

    /** Whether server-side at-rest message encryption is active */
    bool IsEncryptionEnabled() const { return !MessageEncryptionKey.empty(); }

    /** Get the SQRLL encryption settings for message at-rest encryption */
    const SQRLLSettings& GetEncryptionSettings() const { return MessageEncryptionSettings; }

    /**
     * Encrypt a plaintext message for at-rest DB storage.
     * Returns plaintext unchanged if encryption is disabled.
     */
    [[nodiscard]] std::string EncryptMessage(const std::string& Plaintext) const;

    /**
     * Decrypt a ciphertext message from DB storage.
     * @param Ciphertext  The raw ciphertext (base64-encoded if encrypted, or plaintext).
     * @param Status      Whether this message was encrypted at rest.
     *                    When Unencrypted, Ciphertext is returned as-is without decryption.
     * @return On success the decrypted plaintext. If the message is marked encrypted
     *         but the key is missing or mismatched (or the data is corrupted), returns
     *         "[ENCRYPTED - INVALID KEY]" instead of leaking the raw ciphertext.
     */
    [[nodiscard]] std::string DecryptMessage(const std::string& Ciphertext, EMessageEncryptionStatus Status) const;

protected:
    /** Load the message encryption key from disk or environment variable */
    void LoadMessageEncryptionKey();

    /** Settings ini object */
    std::shared_ptr<FIniObject> BackendSettingsIniObject;

    /** Max number of letters per message */
    int32 MaxMessageSize;

    // --- Two-tier global rate limiting ---
    int32 UnauthenticatedRequestsPerHour;
    int32 AuthenticatedRequestsPerHour;

    // --- WebSocket settings ---
    int32 WebSocketIdleTimeoutSeconds;
    bool bTrustForwardedFor;

    // --- Image service settings ---
    int32 ImageKeyInvalidationSeconds;
    int32 ImageInstanceProbeIntervalSeconds;
    int32 ImageServiceCircuitBreakerThreshold;
    int32 ImageServiceCircuitBreakerCooldownSeconds;

    // --- Voice service settings ---
    int32 VoiceServiceCircuitBreakerThreshold;
    int32 VoiceServiceCircuitBreakerCooldownSeconds;

    // --- Logging settings ---
    int32 VerboseLoggingLevel;

    // --- Invite settings ---
    int32 InviteDefaultMaxUses;
    int32 InviteDefaultExpiresInSeconds;
    int32 InviteMaxExpiresInSeconds;
    int32 MaxInvitesPerServer;

    // --- Invite abuse protection settings ---
    int32 InviteAbuseMaxAttempts;
    int32 InviteAbuseWindowSeconds;
    int32 InviteAbuseBanDurationSeconds;

    // --- Invite hourly rate limits ---
    int32 InviteCreateLimitPerHour;
    int32 InviteUseLimitPerHour;

    // --- Registration rate limiting ---
    int32 RegisterAccountLimitPerHour;

    // --- Message retention settings ---
    int32 MessageRetentionCount;
    int32 MessageRetentionCleanupIntervalSeconds;

    // --- Message encryption ---
    std::string MessageEncryptionKeyFilePath;
    std::string MessageEncryptionKey;

    /** SQRLL encryption settings for at-rest message storage */
    SQRLLSettings MessageEncryptionSettings;
};
