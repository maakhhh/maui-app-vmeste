using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using NvkInWay.Api.Domain;
using NvkInWay.Api.Exceptions;
using NvkInWay.Api.Persistence.DbContext;
using NvkInWay.Api.Persistence.Entities;
using NvkInWay.Api.Utils;
using NvkInWay.Infrastructure;

namespace NvkInWay.Api.Persistence.Repositories.Impl;

internal sealed class UserVerificationRepository(ApplicationContext applicationContext,
    ILogger<UserVerificationRepository> logger,
    IPasswordHasher passwordHasher)
    : IUserVerificationRepository
{
    public async Task<int> CountCreatedVerificationsInPeriodAsync(long userId, DateTimeOffset start, DateTimeOffset end, 
        CancellationToken cancellationToken = default)
    {
        var count = await applicationContext.Verifications
            .Where(x => x.UserId == userId
                        && x.VerificationCodeCreatedAt >= start 
                        && x.VerificationCodeCreatedAt <= end)
            .CountAsync(cancellationToken);
        
        return count;
    }
    
    public async Task<DateTimeOffset?> GetLastCreatedAtAsync(long userId, CancellationToken cancellationToken = default)
    {
        return await applicationContext.Verifications
            .Where(x => x.UserId == userId)
            .OrderByDescending(x => x.VerificationCodeCreatedAt)
            .Select(x => x.VerificationCodeCreatedAt)
            .FirstOrDefaultAsync(cancellationToken: cancellationToken);
    }

    public async Task<bool> ActualVerificationCodeExistsAsync(long userId, string code,
        CancellationToken cancellationToken = default)
    {
        var hashedCode = passwordHasher.HashPassword(code);

        var entity = await applicationContext.Verifications
            .Where(x => x.UserId == userId && x.UnconfirmedEmailCode == hashedCode 
                                           && x.NotActual == false)
            .OrderByDescending(x => x.VerificationCodeCreatedAt)
            .SingleOrDefaultAsync(cancellationToken);
        
        return entity != null;
    }

    public async Task<Result<bool, ResultError>> VerificationPassedCheckAsync(long userId, string code, TimeSpan verificationTimeout,
        CancellationToken cancellationToken = default)
    {
        var actualVerificationEntity = await applicationContext.Verifications
            .Where(x => x.UserId == userId 
                        && x.VerificationCodeExpiredAt > DateTimeOffset.UtcNow
                        && x.NotActual == false)
            .OrderByDescending(x => x.VerificationCodeCreatedAt)
            .SingleOrDefaultAsync(cancellationToken);
        
        if(actualVerificationEntity == null) 
            return new ResultError("confirm:not-actual", "Verification code is not actual");
        
        var lastAttemptSecondPassed = DateTimeOffset.UtcNow - actualVerificationEntity.LastVerificationAt;
        if(lastAttemptSecondPassed < verificationTimeout)
            throw new TooManyAttemptsException($"Verification timeout not passed, " +
                                               $"wait: '{verificationTimeout -  lastAttemptSecondPassed}'");
        
        actualVerificationEntity.LastVerificationAt = DateTimeOffset.UtcNow;
        await applicationContext.SaveChangesAsync(cancellationToken);
        
        return passwordHasher.VerifyPassword(code, actualVerificationEntity.UnconfirmedEmailCode);
    }

    public async Task CreateNewVerificationCodeAsync(User user, DateTimeOffset expiration, string code, 
        CancellationToken cancellationToken = default)
    {
        await applicationContext.Verifications
            .Where(x => x.Id == user.Id)
            .ExecuteUpdateAsync(x =>
                x.SetProperty(s => s.NotActual, true), cancellationToken);
        
        var entity = new UserVerificationEntity
        {
            UserId = user.Id,
            UnconfirmedEmail = user.Email,
            VerificationCodeCreatedAt = DateTimeOffset.UtcNow,
            VerificationCodeExpiredAt = expiration,
            UnconfirmedEmailCode = passwordHasher.HashPassword(code),
        };
        
        applicationContext.Add(entity);
        await applicationContext.SaveChangesAsync(cancellationToken);
    }

    public async Task SetUsersCodesNotActualAsync(long userId, CancellationToken cancellationToken = default)
    {
        await applicationContext.Verifications
            .Where(x => x.UserId == userId)
            .ExecuteUpdateAsync(x => x.SetProperty(s => s.NotActual, true), cancellationToken);
    }
}