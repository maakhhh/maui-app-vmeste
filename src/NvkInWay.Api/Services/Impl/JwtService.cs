using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NvkInWay.Api.Domain;
using NvkInWay.Api.Settings;

namespace NvkInWay.Api.Services.Impl;

internal sealed class JwtService : IJwtService
{
    private readonly JwtSettings jwtSettings;
    private readonly TokenValidationParameters tokenValidationParameters;
    private readonly ILogger<JwtService> logger;

    public JwtService(IOptions<JwtSettings> jwtSettings, TokenValidationParameters tokenValidationParameters,
        ILogger<JwtService> logger)
    {
        this.jwtSettings = jwtSettings.Value;
        this.tokenValidationParameters = tokenValidationParameters;
        this.logger = logger;
    }

    public JwtTokens GenerateToken(User user, string deviceId)
    {
        if (user == null) throw new ArgumentNullException(nameof(user));
        if (string.IsNullOrWhiteSpace(deviceId)) throw new ArgumentException("Device ID cannot be empty", nameof(deviceId));

        var accessTokenExpiry = DateTime.UtcNow.AddMinutes(jwtSettings.AccessTokenExpiryMinutes);
        var refreshTokenExpiry = DateTime.UtcNow.AddDays(jwtSettings.RefreshTokenExpiryDays);

        var jti = Guid.NewGuid().ToString();
        
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Jti, jti),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), 
                ClaimValueTypes.Integer64),
            new Claim(JwtRegisteredClaimNames.Exp, ((DateTimeOffset)accessTokenExpiry).ToUnixTimeSeconds().ToString(),
                ClaimValueTypes.Integer64),
            new Claim("first_name", user.FirstName),
            new Claim("last_name", user.SecondName),
            new Claim("device_id", deviceId),
            new Claim("token_type", "access")
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Secret));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: jwtSettings.Issuer,
            audience: jwtSettings.Audience,
            claims: claims,
            expires: accessTokenExpiry,
            signingCredentials: credentials);

        var accessToken = new JwtSecurityTokenHandler().WriteToken(token);
        var refreshToken = GenerateRefreshToken();

        logger.LogInformation("Tokens generated for user {UserId}, device {DeviceId}, jti {Jti}", 
            user.Id, deviceId, jti);

        return new JwtTokens
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            AccessTokenExpiry = accessTokenExpiry,
            RefreshTokenExpiry = refreshTokenExpiry
        };
    }

    public ClaimsPrincipal? GetPrincipalFromToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            logger.LogWarning("Token is null or empty");
            return null;
        }

        return ValidateToken(token, validateLifetime: true);
    }

    public ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            logger.LogWarning("Token is null or empty");
            return null;
        }

        return ValidateToken(token, validateLifetime: false);
    }

    public string? GetJwtId(string token)
    {
        try
        {
            var principal = GetPrincipalFromToken(token);
            if (principal == null)
            {
                logger.LogWarning("Cannot get JWT ID from invalid token");
                return null;
            }

            var jwtId = principal.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
            if (string.IsNullOrEmpty(jwtId))
            {
                logger.LogWarning("JWT ID claim not found in token");
            }
            
            return jwtId;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to get JWT ID from token");
            return null;
        }
    }

    public DateTime? GetTokenExpiry(string token)
    {
        try
        {
            var jwtToken = ReadToken(token);
            if (jwtToken == null) return null;

            return jwtToken.ValidTo;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to get token expiry");
            return null;
        }
    }

    public bool IsTokenExpired(string token)
    {
        var expiry = GetTokenExpiry(token);
        return expiry.HasValue && expiry.Value <= DateTime.UtcNow.Add(tokenValidationParameters.ClockSkew);
    }

    public string? GetUserIdFromToken(string token)
    {
        try
        {
            var principal = GetPrincipalFromToken(token);
            if (principal == null) return null;

            var userIdClaim = principal.FindFirst(JwtRegisteredClaimNames.Sub);
            if (userIdClaim == null)
            {
                logger.LogWarning("User ID claim (sub) not found in token");
                return null;
            }

            return userIdClaim.Value;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to get user ID from token");
            return null;
        }
    }

    public string? GetDeviceIdFromToken(string token)
    {
        try
        {
            var principal = GetPrincipalFromToken(token);
            if (principal == null) return null;

            var deviceId = principal.FindFirst("device_id")?.Value;
            if (string.IsNullOrEmpty(deviceId))
            {
                logger.LogWarning("Device ID claim not found in token");
            }

            return deviceId;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to get device ID from token");
            return null;
        }
    }

    private ClaimsPrincipal? ValidateToken(string token, bool validateLifetime)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            
            // Проверка формата токена
            if (!tokenHandler.CanReadToken(token) || token.Split('.').Length != 3)
            {
                logger.LogWarning("Invalid token format");
                return null;
            }

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = tokenValidationParameters.ValidateIssuerSigningKey,
                IssuerSigningKey = tokenValidationParameters.IssuerSigningKey,
                ValidateIssuer = tokenValidationParameters.ValidateIssuer,
                ValidIssuer = tokenValidationParameters.ValidIssuer,
                ValidateAudience = tokenValidationParameters.ValidateAudience,
                ValidAudience = tokenValidationParameters.ValidAudience,
                ValidateLifetime = validateLifetime,
                ClockSkew = validateLifetime ? tokenValidationParameters.ClockSkew : TimeSpan.Zero,
                RequireExpirationTime = true,
                RequireSignedTokens = true
            };

            var principal = tokenHandler.ValidateToken(token, validationParameters, out _);
            
            if (!ValidateCustomClaims(principal))
            {
                return null;
            }

            var userId = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            logger.LogDebug("Token validated successfully for user '{UserId}'", userId);

            return principal;
        }
        catch (SecurityTokenExpiredException ex)
        {
            logger.LogWarning(ex, "Token expired");
            throw;
        }
        catch (SecurityTokenInvalidSignatureException ex)
        {
            logger.LogWarning(ex, "Token signature validation failed");
            throw;
        }
        catch (SecurityTokenInvalidIssuerException ex)
        {
            logger.LogWarning(ex, "Token issuer validation failed. Expected: {Issuer}", tokenValidationParameters.ValidIssuer);
            throw;
        }
        catch (SecurityTokenInvalidAudienceException ex)
        {
            logger.LogWarning(ex, "Token audience validation failed. Expected: {Audience}", tokenValidationParameters.ValidAudience);
            throw;
        }
        catch (SecurityTokenNoExpirationException ex)
        {
            logger.LogWarning(ex, "Token has no expiration");
            throw;
        }
        catch (SecurityTokenNotYetValidException ex)
        {
            logger.LogWarning(ex, "Token is not yet valid");
            throw;
        }
        catch (ArgumentException ex)
        {
            logger.LogWarning(ex, "Token has invalid arguments");
            return null;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Token validation failed");
            return null;
        }
    }

    private bool ValidateCustomClaims(ClaimsPrincipal principal)
    {
        var deviceId = principal.FindFirst("device_id")?.Value;
        var tokenType = principal.FindFirst("token_type")?.Value;

        if (string.IsNullOrEmpty(deviceId))
        {
            logger.LogWarning("Missing device_id claim in token");
            return false;
        }

        if (tokenType != "access")
        {
            logger.LogWarning("Invalid token_type claim: {TokenType}. Expected: access", tokenType);
            return false;
        }

        // Дополнительная проверка на наличие обязательных claims
        var sub = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        if (string.IsNullOrEmpty(sub))
        {
            logger.LogWarning("Missing sub claim in token");
            return false;
        }

        var jti = principal.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
        if (string.IsNullOrEmpty(jti))
        {
            logger.LogWarning("Missing jti claim in token");
            return false;
        }

        return true;
    }

    public async Task<bool> ValidateTokenAsync(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            return false;

        try
        {
            // Асинхронная обертка для потенциально долгих операций
            return await Task.Run(() => 
            {
                var principal = GetPrincipalFromToken(token);
                return principal != null;
            });
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Async token validation failed");
            return false;
        }
    }

    public JwtSecurityToken? ReadToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            return null;

        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            
            if (!tokenHandler.CanReadToken(token))
                return null;

            return tokenHandler.ReadJwtToken(token);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to read JWT token");
            return null;
        }
    }

    public IEnumerable<Claim> GetTokenClaims(string token)
    {
        var jwtToken = ReadToken(token);
        return jwtToken?.Claims ?? Enumerable.Empty<Claim>();
    }

    public string? GetClaimValue(string token, string claimType)
    {
        try
        {
            var jwtToken = ReadToken(token);
            return jwtToken?.Claims.FirstOrDefault(c => c.Type == claimType)?.Value;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to get claim {ClaimType} from token", claimType);
            return null;
        }
    }

    private string GenerateRefreshToken()
    {
        try
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            
            var timestamp = BitConverter.GetBytes(DateTime.UtcNow.Ticks);
            var combined = new byte[randomNumber.Length + timestamp.Length];
            
            Buffer.BlockCopy(randomNumber, 0, combined, 0, randomNumber.Length);
            Buffer.BlockCopy(timestamp, 0, combined, randomNumber.Length, timestamp.Length);

            return Convert.ToBase64String(combined)
                .Replace('+', '-')
                .Replace('/', '_')
                .Replace("=", "");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to generate refresh token");
            throw new InvalidOperationException("Could not generate refresh token", ex);
        }
    }

    public void InvalidateToken(string jti)
    {
        if (string.IsNullOrWhiteSpace(jti))
        {
            logger.LogWarning("Cannot invalidate token with empty JTI");
            return;
        }

        // Здесь можно добавить логику для добавления токена в blacklist
        // или отправки события отзыва токена
        logger.LogInformation("Token invalidated: {Jti}", jti);
        
        // Пример: отправка события в систему отзывов токенов
        // await _eventBus.PublishAsync(new TokenInvalidatedEvent { Jti = jti });
    }
}