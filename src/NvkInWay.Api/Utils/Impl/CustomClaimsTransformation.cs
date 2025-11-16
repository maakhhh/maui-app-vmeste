using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace NvkInWay.Api.Utils.Impl;

public class CustomClaimsTransformation : IClaimsTransformation
{
    public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        throw new NotImplementedException();
    }
}