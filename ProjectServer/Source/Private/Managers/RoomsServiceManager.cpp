// Created by https://www.linkedin.com/in/przemek2122/ 2026

#include "Logger/Logger.h"
#include "Managers/RoomsServiceManager.h"
#include <cpr/cpr.h>
#include "crow/json.h"
#include "SQRLLEncryption.h"
#include "nlohmann/json.hpp"
#include "nlohmann/json_fwd.hpp"

FRoomsServiceManager::FRoomsServiceManager()
{
    // Get service password and address from env vars
    const char* ServicePasswordPtr = getenv("SQRLL_VOICE_API_KEY");
    const char* ServiceAddressPtr = getenv("SQRLL_VOICE_ADDRESS");
    const char* ServicePortPtr = getenv("SQRLL_VOICE_PORT");
    ServicePassword = ServicePasswordPtr != nullptr ? ServicePasswordPtr : "";
    if (ServiceAddressPtr != nullptr && ServicePortPtr != nullptr)
    {
        ServiceAddress = ServiceAddressPtr + std::string(":") + ServicePortPtr;
    }
    else if (ServiceAddressPtr != nullptr)
    {
        // Allow a single variable that already contains the port.
        ServiceAddress = ServiceAddressPtr;
    }

    // Normalize the base URL so it always carries an explicit scheme (parity
    // with the image service). The config examples set SQRLL_VOICE_ADDRESS to a
    // bare host ("127.0.0.1"); without a scheme libcurl's behaviour is
    // version-dependent (some builds guess http://, others reject the URL
    // outright). The voice service is plain HTTP internally, so default to that.
    if (!ServiceAddress.empty())
    {
        if (ServiceAddress.rfind("http://", 0) != 0 &&
            ServiceAddress.rfind("https://", 0) != 0)
        {
            ServiceAddress = "http://" + ServiceAddress;
        }
    }

    if (ServicePassword.empty())
    {
        LOG_ERROR("Service password is empty!");
    }

    if (ServiceAddress.empty())
    {
        LOG_ERROR("Service address is empty!");
    }
}

bool FRoomsServiceManager::IsEnabled() const
{
    return !ServicePassword.empty() && !ServiceAddress.empty();
}

void FRoomsServiceManager::SetCircuitBreakerSettings(const int32 InThreshold, const int32 InCooldownSeconds)
{
    std::unique_lock<std::shared_mutex> Lock(VoiceCircuitBreakerMutex);

    CircuitBreakerThreshold = (InThreshold > 0) ? InThreshold : 0;
    CircuitBreakerCooldown = (InCooldownSeconds > 0) ? std::chrono::seconds(InCooldownSeconds) : std::chrono::seconds(0);

    // Disabling the breaker resets its state so a later re-enable starts clean.
    if (CircuitBreakerThreshold <= 0)
    {
        ConsecutiveVoiceServiceFailures = 0;
        CircuitOpenedAt = std::chrono::steady_clock::time_point{};
    }
}

bool FRoomsServiceManager::IsCircuitOpenLocked(const std::chrono::steady_clock::time_point Now) const
{
    // Breaker disabled.
    if (CircuitBreakerThreshold <= 0)
    {
        return false;
    }

    // Not enough consecutive failures to trip yet.
    if (ConsecutiveVoiceServiceFailures < CircuitBreakerThreshold)
    {
        return false;
    }

    // No cooldown configured: once tripped, stay open until the backend is
    // restarted (operator explicitly disabled auto-recovery).
    if (CircuitBreakerCooldown.count() <= 0)
    {
        return true;
    }

    // Tripped. During the cooldown window the circuit is open (fail fast).
    // Once it elapses we half-open: a single call is allowed through to test
    // whether the service has come back.
    return (Now - CircuitOpenedAt) < CircuitBreakerCooldown;
}

void FRoomsServiceManager::RecordVoiceServiceFailureLocked()
{
    // Breaker disabled: nothing to track.
    if (CircuitBreakerThreshold <= 0)
    {
        return;
    }

    // Clamp so the counter can never overflow on a permanently-down service.
    if (ConsecutiveVoiceServiceFailures < CircuitBreakerThreshold)
    {
        ++ConsecutiveVoiceServiceFailures;
    }

    if (ConsecutiveVoiceServiceFailures >= CircuitBreakerThreshold)
    {
        // (Re)open the circuit; each further failure restarts the cooldown.
        CircuitOpenedAt = std::chrono::steady_clock::now();
    }
}

void FRoomsServiceManager::RecordVoiceServiceSuccessLocked()
{
    ConsecutiveVoiceServiceFailures = 0;
    CircuitOpenedAt = std::chrono::steady_clock::time_point{};
}

ERoomCreateStatus FRoomsServiceManager::CreateRoom(const std::string& RoomName)
{
    // If the room name is empty there is nothing to create. If the voice
    // service is not configured, fail immediately rather than issuing a
    // doomed HTTP request against a malformed URL.
    if (RoomName.empty() || !IsEnabled())
    {
        return ERoomCreateStatus::Failed;
    }

    // Circuit breaker fail-fast: when the service is known down, skip the
    // synchronous HTTP round-trip so a down voice service can't stall the
    // WebSocket event loop.
    {
        std::shared_lock<std::shared_mutex> Lock(VoiceCircuitBreakerMutex);
        if (IsCircuitOpenLocked(std::chrono::steady_clock::now()))
        {
            return ERoomCreateStatus::Failed;
        }
    }

    // 1. Build the request body in JSON format
    crow::json::wvalue JSONData;
    JSONData["RoomId"] = RoomName;
    JSONData["Token"] = CreateRoomToken(RoomName);

    // 2. Construct the target URL
    const std::string TargetURL = ServiceAddress + "/api/rooms/create";

    // 3. Synchronous POST request (blocks the current thread, which is fine here)
    cpr::Response CPRResponse = cpr::Post(
        cpr::Url{TargetURL},
        cpr::Header{
            {"Content-Type", "application/json"},
            {"X-API-Token", ServicePassword}       // Pass the password for Go verification
        },
        cpr::Body{JSONData.dump()},               // Inject the generated JSON string
        cpr::Timeout{3000}                         // Failsafe: max 3 seconds wait time
    );

    // Track reachability for the circuit breaker: a status code of 0 means no
    // HTTP response was received at all (connection refused / timeout / DNS),
    // which counts as a failure. Any non-zero status (even 5xx) means the
    // service is up and reachable.
    {
        std::unique_lock<std::shared_mutex> Lock(VoiceCircuitBreakerMutex);
        if (CPRResponse.status_code == 0)
        {
            RecordVoiceServiceFailureLocked();
        }
        else
        {
            RecordVoiceServiceSuccessLocked();
        }
    }

    // 4. Interpret the response from Go.
    //    Go reports three distinct success / near-success states:
    //      201 Created   -> brand new room
    //      200 OK        -> room already existed with the SAME token (harmless)
    //      409 Conflict  -> room already existed with a DIFFERENT token (token drift)
    switch (CPRResponse.status_code)
    {
        case 201: // Created
        {
            try
            {
                nlohmann::json JsonResponse = nlohmann::json::parse(CPRResponse.text);

                if (JsonResponse["created"].get<bool>())
                {
                    LOG_DEBUG("Created room in Go Voice Service.");

                    return ERoomCreateStatus::Created;
                }
            }
            catch (const nlohmann::json::exception& e)
            {
                LOG_ERROR("parsing of CreateRoom failed: " << e.what());
            }

            // A 201 with a malformed body is still a failure.
            return ERoomCreateStatus::Failed;
        }

        case 200: // Already exists with the SAME token
        {
            LOG_DEBUG("Room already exists in Go Voice Service with matching token.");
            return ERoomCreateStatus::AlreadyExists;
        }

        case 409: // Already exists with a DIFFERENT token
        {
            LOG_WARN("Room already exists in Go Voice Service with a DIFFERENT token (token drift). Room: " << RoomName);
            return ERoomCreateStatus::AlreadyExistsDifferentToken;
        }

        default:
        {
            LOG_ERROR("Failed to create room in Go. Status: " << CPRResponse.status_code << " Msg: " << CPRResponse.text);
            return ERoomCreateStatus::Failed;
        }
    }
}

ERoomExistenceStatus FRoomsServiceManager::CheckRoom(const std::string& RoomName)
{
    // If the room name is empty there is nothing to check. If the voice
    // service is not configured, report unknown without an HTTP round-trip.
    if (RoomName.empty() || !IsEnabled())
    {
        return ERoomExistenceStatus::Unknown;
    }

    // Circuit breaker fail-fast: skip the doomed HTTP round-trip when the
    // service is known down.
    {
        std::shared_lock<std::shared_mutex> Lock(VoiceCircuitBreakerMutex);
        if (IsCircuitOpenLocked(std::chrono::steady_clock::now()))
        {
            return ERoomExistenceStatus::Unknown;
        }
    }

    // 1. Construct the target URL base
    const std::string TargetURL = ServiceAddress + "/api/rooms/check";

    // 2. Synchronous GET request
    cpr::Response r = cpr::Get(
        cpr::Url{TargetURL},
        cpr::Parameters{{"room", RoomName}},       // Automatically builds "?room=RoomName"
        cpr::Header{
            {"X-API-Token", ServicePassword}       // Pass the password for Go verification
        },
        cpr::Timeout{3000}                         // Failsafe: max 3 seconds wait time
    );

    // Track reachability for the circuit breaker (status 0 = unreachable).
    {
        std::unique_lock<std::shared_mutex> Lock(VoiceCircuitBreakerMutex);
        if (r.status_code == 0)
        {
            RecordVoiceServiceFailureLocked();
        }
        else
        {
            RecordVoiceServiceSuccessLocked();
        }
    }

    // 3. Verify the response from Go
    // GO Voice Service code uses w.WriteHeader(http.StatusOK) for success, which is code 200.
    if (r.status_code == 200)
    {
        try
        {
            if (nlohmann::json JsonResponse = nlohmann::json::parse(r.text); JsonResponse["exists"].get<bool>())
            {
                return ERoomExistenceStatus::Exists;
            }
            else
            {
                return ERoomExistenceStatus::NotExists;
            }
        }
        catch (const nlohmann::json::exception& e)
        {
            LOG_ERROR("Error json parsing in rooms service: " << e.what());
            return ERoomExistenceStatus::Unknown;
        }
    }
    else
    {
        LOG_ERROR("Rooms service API error, Status: " << r.status_code);

        return ERoomExistenceStatus::Unknown;
    }

    return ERoomExistenceStatus::Unknown;
}

std::string FRoomsServiceManager::GetRoomToken(const std::string& RoomName)
{
    std::shared_lock<std::shared_mutex> Lock(RoomNameToTokenMutex);

    auto TokenIter = RoomNameToToken.find(RoomName);
    if (TokenIter != RoomNameToToken.end())
    {
        return TokenIter->second;
    }

    return "";
}

std::string FRoomsServiceManager::CreateRoomToken(const std::string& RoomName)
{
    bool bTokenExists = false;
    std::string Token;

    {
        // Lock shared to check if token exists already
        std::shared_lock<std::shared_mutex> Lock(RoomNameToTokenMutex);

        const auto TokenIter = RoomNameToToken.find(RoomName);
        if (TokenIter != RoomNameToToken.end() && !TokenIter->second.empty())
        {
            bTokenExists = true;
            Token = TokenIter->second;
        }
    }

    if (!bTokenExists)
    {
        // @TODO: What should be actual length of Token?
        // Create token
        Token = GenerateRandomBase64(64);

        std::unique_lock<std::shared_mutex> Lock(RoomNameToTokenMutex);
        RoomNameToToken[RoomName] = Token;
    }

    return Token;
}

std::string FRoomsServiceManager::GenerateRandomBase64(const size_t OutLength)
{
    if (OutLength == 0)
    {
        return {};
    }

    static constexpr std::string_view B64_CHARS = SQRLLPredefinedCharsets::BASE64;

    // Round up to ensure we generate enough raw bytes to satisfy OutLength
    const size_t RequiredBytes = (OutLength * 3 + 3) / 4;
    const std::string Raw = FEncryptionUtil::GenerateSecureSalt(RequiredBytes);

    std::string Encoded;
    Encoded.reserve(OutLength);

    size_t i = 0;
    while (i < RequiredBytes && Encoded.length() < OutLength)
    {
        const uint32_t OctetA = static_cast<unsigned char>(Raw[i++]);
        const uint32_t OctetB = (i < RequiredBytes) ? static_cast<unsigned char>(Raw[i++]) : 0;
        const uint32_t OctetC = (i < RequiredBytes) ? static_cast<unsigned char>(Raw[i++]) : 0;

        const uint32_t Triple = (OctetA << 16) | (OctetB << 8) | OctetC;

        Encoded += B64_CHARS[(Triple >> 18) & 0x3F];

        if (Encoded.length() < OutLength)
            Encoded += B64_CHARS[(Triple >> 12) & 0x3F];
        if (Encoded.length() < OutLength)
            Encoded += B64_CHARS[(Triple >> 6) & 0x3F];
        if (Encoded.length() < OutLength)
            Encoded += B64_CHARS[Triple & 0x3F];
    }

    return Encoded;
}
