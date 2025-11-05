using AutoMapper;
using Microsoft.EntityFrameworkCore;
using NvkInWay.Api.Domain;
using NvkInWay.Api.Persistence.DbContext;
using NvkInWay.Api.Persistence.Entities;

namespace NvkInWay.Api.Persistence.Repositories.Impl;

internal sealed class RefreshTokenRepository(ApplicationContext context, IMapper mapper, 
    ILogger<RefreshTokenRepository> logger) : IRefreshTokenRepository
{
    public async Task AddAsync(RefreshToken refreshToken, CancellationToken cancellationToken = default)
    {
        if (refreshToken == null)
            throw new ArgumentNullException(nameof(refreshToken));

        try
        {
            var entity = mapper.Map<RefreshTokenEntity>(refreshToken);
            context.RefreshTokens.Add(entity);
            await context.SaveChangesAsync(cancellationToken);

            refreshToken.Id = entity.Id;
            
            logger.LogDebug("Refresh token added for user {UserId}, device {DeviceId}", refreshToken.UserId, refreshToken.DeviceId);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error adding refresh token for user {UserId}", refreshToken.UserId);
            throw;
        }
    }

    public async Task<RefreshToken?> GetValidTokenAsync(long userId, string deviceId, string refreshToken, string jwtId)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
            throw new ArgumentException("Device ID cannot be empty", nameof(deviceId));
        if (string.IsNullOrWhiteSpace(refreshToken))
            throw new ArgumentException("Refresh token cannot be empty", nameof(refreshToken));
        if (string.IsNullOrWhiteSpace(jwtId))
            throw new ArgumentException("JWT ID cannot be empty", nameof(jwtId));

        try
        {
            var entity = await context.RefreshTokens
                .AsNoTracking()
                .FirstOrDefaultAsync(rt => 
                    rt.UserId == userId && 
                    rt.DeviceId == deviceId && 
                    rt.Token == refreshToken && 
                    rt.JwtId == jwtId && 
                    !rt.IsUsed && 
                    !rt.IsRevoked && 
                    rt.ExpiryDate > DateTime.UtcNow);

            return entity != null ? mapper.Map<RefreshToken>(entity) : null;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error getting valid refresh token for user {UserId}, device {DeviceId}", userId, deviceId);
            throw;
        }
    }

    public async Task<RefreshToken?> GetValidTokenByValueAsync(long userId, string deviceId, string refreshToken)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
            throw new ArgumentException("Device ID cannot be empty", nameof(deviceId));
        if (string.IsNullOrWhiteSpace(refreshToken))
            throw new ArgumentException("Refresh token cannot be empty", nameof(refreshToken));

        try
        {
            var entity = await context.RefreshTokens
                .AsNoTracking()
                .FirstOrDefaultAsync(rt => 
                    rt.UserId == userId && 
                    rt.DeviceId == deviceId && 
                    rt.Token == refreshToken && 
                    !rt.IsUsed && 
                    !rt.IsRevoked && 
                    rt.ExpiryDate > DateTime.UtcNow);

            return entity != null ? mapper.Map<RefreshToken>(entity) : null;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error getting valid refresh token by value for user {UserId}, device {DeviceId}", userId, deviceId);
            throw;
        }
    }

    public async Task<int> RevokeAllForDeviceAsync(long userId, string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
            throw new ArgumentException("Device ID cannot be empty", nameof(deviceId));

        try
        {
            var activeTokens = await context.RefreshTokens
                .Where(rt => 
                    rt.UserId == userId && 
                    rt.DeviceId == deviceId && 
                    !rt.IsRevoked && 
                    rt.ExpiryDate > DateTime.UtcNow)
                .ToListAsync();

            foreach (var token in activeTokens)
            {
                token.IsRevoked = true;
                token.RevokedAt = DateTime.UtcNow;
            }

            var revokedCount = await context.SaveChangesAsync();
            
            logger.LogInformation("Revoked {Count} refresh tokens for user {UserId}, device {DeviceId}", 
                revokedCount, userId, deviceId);
            
            return revokedCount;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error revoking refresh tokens for user {UserId}, device {DeviceId}", userId, deviceId);
            throw;
        }
    }

    public async Task<int> RevokeAllForUserAsync(long userId)
    {
        try
        {
            var activeTokens = await context.RefreshTokens
                .Where(rt => 
                    rt.UserId == userId && 
                    !rt.IsRevoked && 
                    rt.ExpiryDate > DateTime.UtcNow)
                .ToListAsync();

            foreach (var token in activeTokens)
            {
                token.IsRevoked = true;
                token.RevokedAt = DateTime.UtcNow;
            }

            var revokedCount = await context.SaveChangesAsync();
            
            logger.LogInformation("Revoked {Count} refresh tokens for user {UserId}", revokedCount, userId);
            
            return revokedCount;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error revoking all refresh tokens for user {UserId}", userId);
            throw;
        }
    }

    public async Task<int> DeleteExpiredAsync()
    {
        try
        {
            var expiredTokens = await context.RefreshTokens
                .Where(rt => rt.ExpiryDate <= DateTime.UtcNow)
                .ToListAsync();

            context.RefreshTokens.RemoveRange(expiredTokens);
            var deletedCount = await context.SaveChangesAsync();
            
            logger.LogInformation("Deleted {Count} expired refresh tokens", deletedCount);
            
            return deletedCount;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error deleting expired refresh tokens");
            throw;
        }
    }

    public async Task<int> GetActiveTokensCountAsync(long userId)
    {
        try
        {
            return await context.RefreshTokens
                .CountAsync(rt => 
                    rt.UserId == userId && 
                    !rt.IsRevoked && 
                    rt.ExpiryDate > DateTime.UtcNow);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error getting active tokens count for user {UserId}", userId);
            throw;
        }
    }

    public async Task<bool> IsTokenRevokedAsync(string jwtId)
    {
        if (string.IsNullOrWhiteSpace(jwtId))
            return false;

        try
        {
            return await context.RefreshTokens
                .AnyAsync(rt => 
                    rt.JwtId == jwtId && 
                    (rt.IsRevoked || rt.IsUsed));
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error checking if token is revoked for JWT ID {JwtId}", jwtId);
            return false;
        }
    }

    public async Task<RefreshToken?> GetByJwtIdAsync(string jwtId)
    {
        if (string.IsNullOrWhiteSpace(jwtId))
            return null;

        try
        {
            var entity = await context.RefreshTokens
                .AsNoTracking()
                .FirstOrDefaultAsync(rt => rt.JwtId == jwtId);

            return entity != null ? mapper.Map<RefreshToken>(entity) : null;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error getting refresh token by JWT ID {JwtId}", jwtId);
            throw;
        }
    }

    public async Task<IEnumerable<RefreshToken>> GetUserTokensAsync(long userId)
    {
        try
        {
            var entities = await context.RefreshTokens
                .AsNoTracking()
                .Where(rt => rt.UserId == userId)
                .OrderByDescending(rt => rt.CreatedAt)
                .ToListAsync();

            return entities.Select(mapper.Map<RefreshToken>);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error getting refresh tokens for user {UserId}", userId);
            throw;
        }
    }

    public async Task RevokeTokenAsync(string jwtId, RevocationType revocationType)
    {
        if (string.IsNullOrWhiteSpace(jwtId))
            throw new ArgumentException("JWT ID cannot be empty", nameof(jwtId));

        try
        {
            var token = await context.RefreshTokens
                .FirstOrDefaultAsync(rt => 
                    rt.JwtId == jwtId && 
                    !rt.IsRevoked && 
                    rt.ExpiryDate > DateTime.UtcNow);

            if (token != null)
            {
                token.IsRevoked = true;
                token.RevokedAt = DateTime.UtcNow;
                await context.SaveChangesAsync();

                logger.LogInformation("Refresh token revoked for JWT ID {JwtId}, reason: {Reason}", 
                    jwtId, revocationType);
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error revoking refresh token for JWT ID {JwtId}", jwtId);
            throw;
        }
    }
}