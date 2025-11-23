using AutoMapper;
using Microsoft.EntityFrameworkCore;
using NvkInWay.Api.Domain;
using NvkInWay.Api.Exceptions;
using NvkInWay.Api.Persistence.DbContext;
using NvkInWay.Api.Persistence.Entities;

namespace NvkInWay.Api.Persistence.Repositories.Impl;

internal sealed class UserRepository(ApplicationContext applicationContext, IMapper mapper) : IUserRepository
{
    public async Task<User> CreateUserAsync(User user, CancellationToken cancellationToken = default)
    {
        var entity = mapper.Map<UserEntity>(user);

        await applicationContext.Users.AddAsync(entity, cancellationToken);
        await applicationContext.SaveChangesAsync(cancellationToken);

        return mapper.Map<User>(entity);
    }

    public async Task<User> GetUserByIdAsync(long id, CancellationToken cancellationToken = default)
    {
        var user = await applicationContext.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        
        if (user == null)
        {
            throw new NotFoundException($"User with id: '{id}', not found");
        }

        return mapper.Map<User>(user);
    }

    public async Task<User> GetByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        var user = await applicationContext.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.Email == email, cancellationToken);
        
        if (user == null)
        {
            throw new NotFoundException($"User with email: '{email}', not found");
        }

        return mapper.Map<User>(user);
    }

    public async Task DeleteUserAsync(User user, CancellationToken cancellationToken = default)
    {
        var userEntity = await applicationContext.Users
            .FirstOrDefaultAsync(u => u.Id == user.Id, cancellationToken);

        if (userEntity == null)
        {
            throw new NotFoundException($"User with id: '{user.Id}', not found");
        }

        applicationContext.Users.Remove(userEntity);
        await applicationContext.SaveChangesAsync(cancellationToken);
    }

    public async Task UpdateUserAsync(User user, CancellationToken cancellationToken = default)
    {
        var entity = await applicationContext.Users
            .FirstOrDefaultAsync(x => x.Id == user.Id, cancellationToken);
        
        if (entity == null) throw new NotFoundException($"User with id: '{user.Id}', not found");
        
        var updated = mapper.Map(user, entity);
        await applicationContext.SaveChangesAsync(cancellationToken);
    }
}