using NvkInWay.Api.Domain;

namespace NvkInWay.Api.Services;

public interface IAuthService
{
    Task<JwtTokens> LoginAsync(string email, string password, string deviceId, string? deviceName = null);
    Task<JwtTokens> RefreshTokenAsync(string accessToken, string refreshToken, string deviceId);
    Task LogoutAsync(int userId, string deviceId);
    Task LogoutAllDevicesAsync(int userId);
    Task<bool> ValidateAccessTokenAsync(string accessToken);
    Task<IEnumerable<UserSession>> GetUserSessionsAsync(int userId);
    Task RevokeSessionAsync(int userId, string deviceId);
    Task<bool> IsValidRefreshTokenAsync(string refreshToken, int userId, string deviceId);
}