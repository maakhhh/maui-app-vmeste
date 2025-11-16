using NvkInWay.Api.Domain;

namespace NvkInWay.Api.Persistence.Repositories;

public interface IUserRepository
{
    Task<User> CreateUserAsync(User user, CancellationToken cancellationToken = default);
    
    Task<User> GetUserByIdAsync(long id, CancellationToken cancellationToken = default);

    Task<User> GetByEmailAsync(string email, CancellationToken cancellationToken = default);

    Task DeleteUserAsync(User user, CancellationToken cancellationToken = default);
}