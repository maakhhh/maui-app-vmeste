using MediatR;
using NvkInWay.Api.Persistence.Repositories;
using NvkInWay.Api.Utils;

namespace NvkInWay.Api.Application.User.Commands.Register;

public class RegisterCommandHandler(
    IUserRepository userRepository, 
    IPasswordHasher hasher,
    ILogger<RegisterCommandHandler> logger) 
    : IRequestHandler<RegisterCommand, Domain.User>
{
    public Task<Domain.User> Handle(RegisterCommand request, CancellationToken cancellationToken)
    {
        var user = new Domain.User
        {
            Email = request.Email,
            FirstName = request.FirstName,
            SecondName = request.SecondName,
            HashedPassword = hasher.HashPassword(request.Password),
            Age = request.Age,
            CreatedAt = DateTimeOffset.Now
        };

        var createdUser = userRepository.CreateUserAsync(user, cancellationToken);
        logger.LogInformation("Created user: {UserId}", user.Id);

        return createdUser;
    }
}