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

        var identity = controller.HttpContext.User.Identity as ClaimsIdentity;

        if (identity == null)
            throw new UnauthorizedException("User is not authenticated");

        var nameClaim = identity.FindFirst(JwtRegisteredClaimNames.Sub);
        if (nameClaim == null) throw new ApplicationException("Cannot get claim 'Name'.");

        return long.Parse(nameClaim.Value);
    }
}