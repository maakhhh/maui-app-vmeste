using NvkInWay.Api.Domain;

namespace NvkInWay.Api.Persistence.Repositories;

internal interface IRefreshTokenRepository
{
    Task AddAsync(RefreshToken refreshToken, CancellationToken cancellationToken = default);
    Task<RefreshToken?> GetValidTokenAsync(long userId, string deviceId, string refreshToken, string jwtId);
    Task<RefreshToken?> GetValidTokenByValueAsync(long userId, string deviceId, string refreshToken);
    Task<int> RevokeAllForDeviceAsync(long userId, string deviceId);
    Task<int> RevokeAllForUserAsync(long userId);
    Task<int> DeleteExpiredAsync();
    Task<int> GetActiveTokensCountAsync(long userId);
    Task<bool> IsTokenRevokedAsync(string jwtId);
    Task<RefreshToken?> GetByJwtIdAsync(string jwtId);
    Task<IEnumerable<RefreshToken>> GetUserTokensAsync(long userId);
    Task RevokeTokenAsync(string jwtId, RevocationType revocationType);
}