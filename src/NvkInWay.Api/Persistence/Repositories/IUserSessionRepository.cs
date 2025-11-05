using NvkInWay.Api.Domain;

namespace NvkInWay.Api.Persistence.Repositories;

public interface IUserSessionRepository
{
    Task<UserSession> GetOrCreateAsync(long userId, string deviceId, string? deviceName = null);
    Task UpdateLastActivityAsync(long userId, string deviceId);
    Task<UserSession?> DeactivateAsync(long userId, string deviceId);
    Task<int> DeactivateAllAsync(long userId);
    Task<IEnumerable<UserSession>> GetActiveSessionsAsync(long userId);
    Task<UserSession?> GetByDeviceIdAsync(long userId, string deviceId);
    Task<bool> UpdatePushTokenAsync(long userId, string deviceId, string pushToken);
    Task<int> DeleteExpiredAsync(TimeSpan expirationTime);
    Task<int> GetActiveSessionsCountAsync(long userId);
    Task<bool> IsSessionActiveAsync(long userId, string deviceId);
}