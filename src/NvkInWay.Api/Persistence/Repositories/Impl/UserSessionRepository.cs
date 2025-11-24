using AutoMapper;
using Microsoft.EntityFrameworkCore;
using NvkInWay.Api.Domain;
using NvkInWay.Api.Persistence.DbContext;
using NvkInWay.Api.Persistence.Entities;

namespace NvkInWay.Api.Persistence.Repositories.Impl;

internal sealed class UserSessionRepository(ApplicationContext context,
    IMapper mapper, ILogger<UserSessionRepository> logger)
    : IUserSessionRepository
{
    public async Task<UserSession> GetOrCreateAsync(long userId, string deviceId, string? deviceName = null)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
            throw new ArgumentException("Device ID cannot be empty", nameof(deviceId));

        try
        {
            var existingSession = await context.UserSessions
                .FirstOrDefaultAsync(us => 
                    us.UserId == userId && 
                    us.DeviceId == deviceId && 
                    us.IsActive);

            if (existingSession != null)
            {
                existingSession.LastActivity = DateTime.UtcNow;
                await context.SaveChangesAsync();

                logger.LogDebug("Existing session found for user {UserId}, device {DeviceId}", userId, deviceId);
                return mapper.Map<UserSession>(existingSession);
            }

            var newSession = new UserSessionsEntity
            {
                UserId = userId,
                DeviceId = deviceId,
                LastActivity = DateTime.UtcNow,
                CreatedAt = DateTime.UtcNow,
                IsActive = true
            };

            context.UserSessions.Add(newSession);
            await context.SaveChangesAsync();

            logger.LogInformation("New session created for user {UserId}, device {DeviceId}", userId, deviceId);
            return mapper.Map<UserSession>(newSession);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error getting or creating session for user {UserId}, device {DeviceId}", userId, deviceId);
            throw;
        }
    }

    public async Task UpdateLastActivityAsync(long userId, string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
            throw new ArgumentException("Device ID cannot be empty", nameof(deviceId));

        try
        {
            var session = await context.UserSessions
                .FirstOrDefaultAsync(us => 
                    us.UserId == userId && 
                    us.DeviceId == deviceId && 
                    us.IsActive);

            if (session != null)
            {
                session.LastActivity = DateTime.UtcNow;
                await context.SaveChangesAsync();

                logger.LogDebug("Last activity updated for user {UserId}, device {DeviceId}", userId, deviceId);
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error updating last activity for user {UserId}, device {DeviceId}", userId, deviceId);
            throw;
        }
    }

    public async Task<UserSession?> DeactivateAsync(long userId, string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
            throw new ArgumentException("Device ID cannot be empty", nameof(deviceId));

        try
        {
            var session = await context.UserSessions
                .FirstOrDefaultAsync(us => 
                    us.UserId == userId && 
                    us.DeviceId == deviceId && 
                    us.IsActive);

            if (session != null)
            {
                session.IsActive = false;
                session.LastActivity = DateTime.UtcNow;
                await context.SaveChangesAsync();

                logger.LogInformation("Session deactivated for user {UserId}, device {DeviceId}", userId, deviceId);
                return mapper.Map<UserSession>(session);
            }

            logger.LogWarning("No active session found to deactivate for user {UserId}, device {DeviceId}", userId, deviceId);
            return null;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error deactivating session for user {UserId}, device {DeviceId}", userId, deviceId);
            throw;
        }
    }

    public async Task<int> DeactivateAllAsync(long userId)
    {
        try
        {
            var activeSessions = await context.UserSessions
                .Where(us => us.UserId == userId && us.IsActive)
                .ToListAsync();

            foreach (var session in activeSessions)
            {
                session.IsActive = false;
                session.LastActivity = DateTime.UtcNow;
            }

            var deactivatedCount = await context.SaveChangesAsync();
            
            logger.LogInformation("Deactivated {Count} sessions for user {UserId}", deactivatedCount, userId);
            return deactivatedCount;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error deactivating all sessions for user {UserId}", userId);
            throw;
        }
    }

    public async Task<IReadOnlyCollection<UserSession>> GetActiveSessionsAsync(long userId)
    {
        try
        {
            var sessions = await context.UserSessions
                .Where(us => us.UserId == userId && us.IsActive)
                .OrderByDescending(us => us.LastActivity)
                .ToListAsync();

            return sessions.Select(mapper.Map<UserSession>).ToList();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error getting active sessions for user {UserId}", userId);
            throw;
        }
    }

    public async Task<UserSession?> GetByDeviceIdAsync(long userId, string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
            return null;

        try
        {
            var session = await context.UserSessions
                .FirstOrDefaultAsync(us => 
                    us.UserId == userId && 
                    us.DeviceId == deviceId);

            return session != null ? mapper.Map<UserSession>(session) : null;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error getting session for user {UserId}, device {DeviceId}", userId, deviceId);
            throw;
        }
    }

    public async Task<bool> UpdatePushTokenAsync(long userId, string deviceId, string pushToken)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
            throw new ArgumentException("Device ID cannot be empty", nameof(deviceId));

        try
        {
            var session = await context.UserSessions
                .FirstOrDefaultAsync(us => 
                    us.UserId == userId && 
                    us.DeviceId == deviceId && 
                    us.IsActive);

            if (session != null)
            {
                session.PushToken = pushToken;
                session.LastActivity = DateTime.UtcNow;
                await context.SaveChangesAsync();

                logger.LogInformation("Push token updated for user {UserId}, device {DeviceId}", userId, deviceId);
                return true;
            }

            logger.LogWarning("No active session found to update push token for user {UserId}, device {DeviceId}", userId, deviceId);
            return false;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error updating push token for user {UserId}, device {DeviceId}", userId, deviceId);
            throw;
        }
    }

    public async Task<int> DeleteExpiredAsync(TimeSpan expirationTime)
    {
        try
        {
            var expirationDate = DateTime.UtcNow.Subtract(expirationTime);
            
            var expiredSessions = await context.UserSessions
                .Where(us => us.LastActivity < expirationDate && us.IsActive)
                .ToListAsync();

            foreach (var session in expiredSessions)
            {
                session.IsActive = false;
            }

            var deletedCount = await context.SaveChangesAsync();
            
            logger.LogInformation("Marked {Count} expired sessions as inactive", deletedCount);
            return deletedCount;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error deleting expired sessions");
            throw;
        }
    }

    public async Task<int> GetActiveSessionsCountAsync(long userId)
    {
        try
        {
            return await context.UserSessions
                .CountAsync(us => us.UserId == userId && us.IsActive);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error getting active sessions count for user {UserId}", userId);
            throw;
        }
    }

    public async Task<bool> IsSessionActiveAsync(long userId, string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
            return false;

        try
        {
            return await context.UserSessions
                .AnyAsync(us => 
                    us.UserId == userId && 
                    us.DeviceId == deviceId && 
                    us.IsActive);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error checking session activity for user {UserId}, device {DeviceId}", userId, deviceId);
            return false;
        }
    }
}