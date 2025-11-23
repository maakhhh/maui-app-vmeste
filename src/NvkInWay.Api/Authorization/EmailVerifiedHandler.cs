using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authorization;
using NvkInWay.Api.Persistence.Repositories;

namespace NvkInWay.Api.Authorization;

public class EmailVerifiedHandler(IUserRepository userRepository) : AuthorizationHandler<EmailVerifiedRequirement>
{
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        EmailVerifiedRequirement requirement)
    {
        var userIdClaim = context.User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        
        if (userIdClaim != null && long.TryParse(userIdClaim, out var userId))
        {
            var isVerified = await userRepository.IsUserVerifiedAsync(userId);
            if (isVerified)
            {
                context.Succeed(requirement);
            }
        }
    }
}