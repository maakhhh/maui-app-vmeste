using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NvkInWay.Api.Domain;
using NvkInWay.Api.Exceptions;
using NvkInWay.Api.Persistence.Repositories;
using NvkInWay.Api.Utils;

namespace NvkInWay.Api.Services.Impl;

internal sealed class AuthService : IAuthService
{
    private readonly IUserRepository userRepository;
    private readonly IRefreshTokenRepository refreshTokenRepository;
    private readonly IUserSessionRepository userSessionRepository;
    private readonly IJwtService jwtService;
    private readonly ILogger<AuthService> logger;
    private readonly IPasswordHasher passwordHasher;

    public AuthService(
        IUserRepository userRepository,
        IRefreshTokenRepository refreshTokenRepository,
        IUserSessionRepository userSessionRepository,
        IJwtService jwtService,
        ILogger<AuthService> logger,
        IPasswordHasher passwordHasher)
    {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.userSessionRepository = userSessionRepository;
        this.jwtService = jwtService;
        this.logger = logger;
        this.passwordHasher = passwordHasher;
    }

    public async Task<JwtTokens> LoginAsync(string email, string password, string deviceId, string? deviceName = null)
    {
        if (string.IsNullOrWhiteSpace(email))
            throw new ArgumentException("Email cannot be empty", nameof(email));
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("Password cannot be empty", nameof(password));
        if (string.IsNullOrWhiteSpace(deviceId))
            throw new ArgumentException("Device ID cannot be empty", nameof(deviceId));

        try
        {
            var user = await userRepository.GetByEmailAsync(email);
            if (user == null)
            {
                logger.LogWarning("Login attempt with non-existent email: {Email}", email);
                throw new UnauthorizedException("Invalid credentials");
            }

            if (user.IsBlocked)
            {
                logger.LogWarning("Login attempt for blocked user: {UserId}", user.Id);
                throw new UnauthorizedException("Account is blocked");
            }

            if (!passwordHasher.VerifyPassword(password, user.HashedPassword))
            {
                logger.LogWarning("Invalid password for user: {UserId}", user.Id);
                throw new UnauthorizedException("Invalid credentials");
            }

            _ = await userSessionRepository.GetOrCreateAsync(user.Id, deviceId, deviceName);
            
            var tokens = jwtService.GenerateToken(user, deviceId);

            var refreshToken = new RefreshToken
            {
                UserId = user.Id,
                Token = tokens.RefreshToken,
                JwtId = jwtService.GetJwtId(tokens.AccessToken) ?? throw new InvalidOperationException("Failed to get JWT ID from token"),
                DeviceId = deviceId,
                CreatedAt = DateTime.UtcNow,
                ExpiryDate = tokens.RefreshTokenExpiry
            };

            await refreshTokenRepository.AddAsync(refreshToken);
            await userSessionRepository.UpdateLastActivityAsync(user.Id, deviceId);
            
            logger.LogInformation("User {UserId} successfully logged in from device {DeviceId}", user.Id, deviceId);

            return tokens;
        }
        catch (Exception ex) when (ex is not UnauthorizedException)
        {
            logger.LogError(ex, "Error during login for email: {Email}", email);
            throw new UnauthorizedException("Login failed");
        }
    }

    public async Task<JwtTokens> RefreshTokenAsync(string accessToken, string refreshToken, string deviceId)
    {
        if (string.IsNullOrWhiteSpace(accessToken))
            throw new ArgumentException("Access token cannot be empty", nameof(accessToken));
        if (string.IsNullOrWhiteSpace(refreshToken))
            throw new ArgumentException("Refresh token cannot be empty", nameof(refreshToken));
        if (string.IsNullOrWhiteSpace(deviceId))
            throw new ArgumentException("Device ID cannot be empty", nameof(deviceId));

        try
        {
            var principal = jwtService.GetPrincipalFromExpiredToken(accessToken);
            if (principal == null)
            {
                throw new SecurityTokenException("Invalid access token");
            }

            var userIdClaim = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value 
                ?? principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            
            if (string.IsNullOrEmpty(userIdClaim) || !int.TryParse(userIdClaim, out var userId))
            {
                throw new SecurityTokenException("Invalid user ID in token");
            }

            var jwtId = principal.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
            if (string.IsNullOrEmpty(jwtId))
            {
                throw new SecurityTokenException("Missing JTI claim in token");
            }

            var storedRefreshToken = await refreshTokenRepository.GetValidTokenAsync(
                userId, deviceId, refreshToken, jwtId);

            if (storedRefreshToken == null)
            {
                logger.LogWarning("Invalid refresh token for user {UserId}, device {DeviceId}", userId, deviceId);
                throw new SecurityTokenException("Invalid refresh token");
            }

            var user = await userRepository.GetUserByIdAsync(userId);
            if (user == null)
            {
                logger.LogWarning("User not found during token refresh: {UserId}", userId);
                throw new SecurityTokenException("User not found");
            }

            if (user.IsBlocked || user.IsDeleted)
            {
                logger.LogWarning("Inactive user attempted token refresh: {UserId}", userId);
                throw new SecurityTokenException("User account is deactivated");
            }

            storedRefreshToken.IsUsed = true;
            storedRefreshToken.RevokedAt = DateTime.UtcNow;

            var newTokens = jwtService.GenerateToken(user, deviceId);

            var newRefreshToken = new RefreshToken
            {
                UserId = userId,
                Token = newTokens.RefreshToken,
                JwtId = jwtService.GetJwtId(newTokens.AccessToken) ?? throw new InvalidOperationException("Failed to get JWT ID from new token"),
                DeviceId = deviceId,
                CreatedAt = DateTime.UtcNow,
                ExpiryDate = newTokens.RefreshTokenExpiry
            };

            await refreshTokenRepository.AddAsync(newRefreshToken);

            await userSessionRepository.UpdateLastActivityAsync(userId, deviceId);

            logger.LogInformation("Tokens refreshed for user {UserId}, device {DeviceId}", userId, deviceId);

            return newTokens;
        }
        catch (Exception ex) when (ex is not SecurityTokenException)
        {
            logger.LogError(ex, "Error during token refresh for device: {DeviceId}", deviceId);
            throw new SecurityTokenException("Token refresh failed");
        }
    }

    public async Task LogoutAsync(int userId, string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
            throw new ArgumentException("Device ID cannot be empty", nameof(deviceId));

        try
        {
            var revokedCount = await refreshTokenRepository.RevokeAllForDeviceAsync(userId, deviceId);

            _ = await userSessionRepository.DeactivateAsync(userId, deviceId);

            logger.LogInformation(
                "User {UserId} logged out from device {DeviceId}. Revoked {TokenCount} refresh tokens", 
                userId, deviceId, revokedCount);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error during logout for user {UserId}, device {DeviceId}", userId, deviceId);
            throw;
        }
    }

    public async Task LogoutAllDevicesAsync(int userId)
    {
        try
        {
            var revokedCount = await refreshTokenRepository.RevokeAllForUserAsync(userId);

            var deactivatedCount = await userSessionRepository.DeactivateAllAsync(userId);
            logger.LogInformation(
                "User {UserId} logged out from all devices. Revoked {TokenCount} tokens, deactivated {SessionCount} sessions", 
                userId, revokedCount, deactivatedCount);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error during logout from all devices for user {UserId}", userId);
            throw;
        }
    }

    public async Task<bool> ValidateAccessTokenAsync(string accessToken)
    {
        if (string.IsNullOrWhiteSpace(accessToken))
            return false;

        try
        {
            return await jwtService.ValidateTokenAsync(accessToken);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Access token validation failed");
            return false;
        }
    }

    public async Task<IEnumerable<UserSession>> GetUserSessionsAsync(int userId)
    {
        var sessions = await userSessionRepository.GetActiveSessionsAsync(userId);
        return sessions;
    }

    public async Task RevokeSessionAsync(int userId, string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
            throw new ArgumentException("Device ID cannot be empty", nameof(deviceId));

        try
        {
            var revokedCount = await refreshTokenRepository.RevokeAllForDeviceAsync(userId, deviceId);

            await userSessionRepository.DeactivateAsync(userId, deviceId);

            logger.LogInformation(
                "Session revoked for user {UserId}, device {DeviceId}. Revoked {TokenCount} tokens", 
                userId, deviceId, revokedCount);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error revoking session for user {UserId}, device {DeviceId}", userId, deviceId);
            throw;
        }
    }

    public async Task<bool> IsValidRefreshTokenAsync(string refreshToken, int userId, string deviceId)
    {
        if (string.IsNullOrWhiteSpace(refreshToken) || string.IsNullOrWhiteSpace(deviceId))
            return false;

        try
        {
            var validToken = await refreshTokenRepository.GetValidTokenByValueAsync(userId, deviceId, refreshToken);
            return validToken != null;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Error validating refresh token for user {UserId}", userId);
            return false;
        }
    }
}