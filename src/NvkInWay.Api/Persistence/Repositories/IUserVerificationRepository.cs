using NvkInWay.Api.Domain;

namespace NvkInWay.Api.Persistence.Repositories;

public interface IUserVerificationRepository
{
    public Task<int> CountCreatedVerificationsInPeriodAsync(long userId, DateTimeOffset start, DateTimeOffset end,
        CancellationToken cancellationToken = default);

    public Task<DateTimeOffset?> GetLastCreatedAtAsync(long userId, CancellationToken cancellationToken = default);
    
    public Task<bool> ActualVerificationCodeExistsAsync(long userId, string code, CancellationToken cancellationToken = default);
    
    public Task CreateNewVerificationCodeAsync(User user, DateTimeOffset expiration, string code,
        CancellationToken cancellationToken = default);
    
    public Task SetUsersCodesNotActualAsync(long userId, CancellationToken cancellationToken = default);

    public Task<bool> VerificationPassedCheckAsync(long userId, string code, TimeSpan verificationTimeout,
        CancellationToken cancellationToken = default);
}