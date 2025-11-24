using MediatR;
using NvkInWay.Api.Domain;
using NvkInWay.Infrastructure;

namespace NvkInWay.Api.Services;

public interface IAuthService
{
    Task<JwtTokens> LoginAsync(string email, string password, string deviceId, string? deviceName = null);
    Task<JwtTokens> RefreshTokenAsync(string? accessToken, string? refreshToken, string? deviceId);
    Task LogoutAsync(int userId, string deviceId);
    Task LogoutAllDevicesAsync(int userId);
    Task<bool> ValidateAccessTokenAsync(string accessToken);
    Task<IReadOnlyCollection<UserSession>> GetUserSessionsAsync(int userId);
    Task RevokeSessionAsync(int userId, string deviceId);
    Task<bool> IsValidRefreshTokenAsync(string refreshToken, int userId, string deviceId);

    public Task<bool> SendUniqueVerificationCodeAsync(string email, CancellationToken cancellationToken = default);

    public Task<Result<Unit, ResultError>> ConfirmEmailAsync(string email, string code);
}