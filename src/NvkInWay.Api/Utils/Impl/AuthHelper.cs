using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using NvkInWay.Api.Exceptions;

namespace NvkInWay.Api.Utils.Impl;

public class AuthHelper : IAuthHelper
{
    public long GetUserId(ControllerBase controller)
    {
        if (controller == null)
            throw new ArgumentNullException(nameof(controller));

        var user = controller.HttpContext.User;
        
        if (user.Identity == null || !user.Identity.IsAuthenticated)
            throw new UnauthorizedException("User is not authenticated");

        var userIdClaim = user.FindFirst(ClaimTypes.NameIdentifier) ?? 
                         user.FindFirst(JwtRegisteredClaimNames.Sub) ??
                         user.FindFirst("sub");

        if (userIdClaim == null || string.IsNullOrEmpty(userIdClaim.Value))
        {
            throw new ApplicationException("Cannot get user ID from token claims.");
        }

        if (long.TryParse(userIdClaim.Value, out var userId))
        {
            return userId;
        }

        throw new ApplicationException($"Invalid user ID format: {userIdClaim.Value}");
    }
}