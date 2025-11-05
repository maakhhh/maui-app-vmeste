using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using NvkInWay.Api.Domain;

namespace NvkInWay.Api.Services;

internal interface IJwtService
{
    JwtTokens GenerateToken(User user, string deviceId);
    ClaimsPrincipal? GetPrincipalFromToken(string token);
    ClaimsPrincipal? GetPrincipalFromExpiredToken(string token);
    string? GetJwtId(string token);
    DateTime? GetTokenExpiry(string token);
    bool IsTokenExpired(string token);
    string? GetUserIdFromToken(string token);
    string? GetDeviceIdFromToken(string token);
    Task<bool> ValidateTokenAsync(string token);
    JwtSecurityToken? ReadToken(string token);
    IEnumerable<Claim> GetTokenClaims(string token);
    void InvalidateToken(string jti);
}