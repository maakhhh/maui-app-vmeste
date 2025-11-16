using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NvkInWay.Api.Domain;
using NvkInWay.Api.Settings;

namespace NvkInWay.Api.Services.Impl;

internal sealed class JwtService : IJwtService
{
    private readonly JwtSettings jwtSettings;
    private readonly ILogger<JwtService> logger;
    private readonly SymmetricSecurityKey signingKey;

    public JwtService(IOptions<JwtSettings> jwtSettings, ILogger<JwtService> logger)
    {
        this.jwtSettings = jwtSettings.Value;
        this.logger = logger;
        this.signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Value.Secret));
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

        var credentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

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
        return ValidateTokenWithRawParsing(token, validateLifetime: true);
    }

    public ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
    {
        return ValidateTokenWithRawParsing(token, validateLifetime: false);
    }

    public string? GetJwtId(string token)
    {
        try
        {
            var claims = ParseJwtPayloadRaw(token);
            return claims.GetValueOrDefault(JwtRegisteredClaimNames.Jti);
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
            var claims = ParseJwtPayloadRaw(token);
            var expClaim = claims.GetValueOrDefault(JwtRegisteredClaimNames.Exp);
            
            if (string.IsNullOrEmpty(expClaim) || !long.TryParse(expClaim, out var expTimestamp))
                return null;

            return DateTimeOffset.FromUnixTimeSeconds(expTimestamp).UtcDateTime;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to get token expiry");
            return null;
        }
    }

    public bool IsTokenExpired(string token)
    {
        try
        {
            var expiry = GetTokenExpiry(token);
            return expiry.HasValue && expiry.Value <= DateTime.UtcNow;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to check token expiration");
            return true;
        }
    }

    public string? GetUserIdFromToken(string token)
    {
        try
        {
            var claims = ParseJwtPayloadRaw(token);
            var userId = claims.GetValueOrDefault(JwtRegisteredClaimNames.Sub);
            
            if (string.IsNullOrEmpty(userId))
            {
                logger.LogWarning("User ID claim (sub) not found in token");
            }

            return userId;
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
            var claims = ParseJwtPayloadRaw(token);
            var deviceId = claims.GetValueOrDefault("device_id");
            
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

    /// <summary>
    /// Парсинг JWT payload на уровне raw JSON для получения ВСЕХ claims
    /// </summary>
    private Dictionary<string, string> ParseJwtPayloadRaw(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            return new Dictionary<string, string>();

        try
        {
            var parts = token.Split('.');
            if (parts.Length != 3)
            {
                logger.LogWarning("Invalid JWT format: expected 3 parts, got {Count}", parts.Length);
                return new Dictionary<string, string>();
            }

            var payload = parts[1];
            
            while (payload.Length % 4 != 0)
                payload += '=';

            payload = payload.Replace('-', '+').Replace('_', '/');
            var payloadBytes = Convert.FromBase64String(payload);
            var payloadJson = Encoding.UTF8.GetString(payloadBytes);

            var jsonDocument = JsonDocument.Parse(payloadJson);
            var claims = new Dictionary<string, string>();

            foreach (var property in jsonDocument.RootElement.EnumerateObject())
            {
                claims[property.Name] = property.Value.ValueKind switch
                {
                    JsonValueKind.String => property.Value.GetString() ?? string.Empty,
                    JsonValueKind.Number => property.Value.GetInt64().ToString(),
                    JsonValueKind.True => "true",
                    JsonValueKind.False => "false",
                    _ => property.Value.ToString()
                };
            }

            logger.LogDebug("Raw JWT payload parsed successfully. Claims count: {Count}", claims.Count);
            return claims;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to parse JWT payload raw");
            return new Dictionary<string, string>();
        }
    }

    /// <summary>
    /// Валидация токена с ручным парсингом payload
    /// </summary>
    private ClaimsPrincipal? ValidateTokenWithRawParsing(string token, bool validateLifetime)
    {
        try
        {
            // viteOkB: parsing payload вручную чтобы получить все claims
            var rawClaims = ParseJwtPayloadRaw(token);
            if (!rawClaims.Any())
            {
                logger.LogWarning("No claims found in token payload");
                return null;
            }

            LogDebugRawClaims(rawClaims);

            if (!ValidateCustomClaims(rawClaims))
            {
                return null;
            }

            // Шаг 3: Проверяем подпись стандартным способом
            if (!ValidateTokenSignature(token))
            {
                logger.LogWarning("Token signature validation failed");
                return null;
            }

            // Шаг 4: Проверяем issuer и audience из raw claims
            if (!ValidateIssuerAndAudience(rawClaims))
            {
                return null;
            }

            // Шаг 5: Проверяем срок действия
            if (validateLifetime && IsTokenExpiredBasedOnRawClaims(rawClaims))
            {
                logger.LogWarning("Token is expired");
                return null;
            }

            // Шаг 6: Создаем Principal со всеми claims
            var principal = CreatePrincipalFromRawClaims(rawClaims);

            var userId = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            logger.LogDebug("Token validated successfully for user '{UserId}'", userId);

            return principal;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Token validation failed");
            return null;
        }
    }

    /// <summary>
    /// Проверка подписи токена
    /// </summary>
    private bool ValidateTokenSignature(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signingKey,
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                ClockSkew = TimeSpan.Zero
            };

            tokenHandler.ValidateToken(token, validationParameters, out _);
            return true;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Token signature validation failed");
            return false;
        }
    }

    /// <summary>
    /// Проверка issuer и audience из raw claims
    /// </summary>
    private bool ValidateIssuerAndAudience(Dictionary<string, string> rawClaims)
    {
        // Проверяем issuer
        if (!rawClaims.TryGetValue("iss", out var issuer) || issuer != jwtSettings.Issuer)
        {
            logger.LogWarning("Token issuer validation failed. Expected: {Expected}, Actual: {Actual}", 
                jwtSettings.Issuer, issuer);
            return false;
        }

        // Проверяем audience
        if (!rawClaims.TryGetValue("aud", out var audience) || audience != jwtSettings.Audience)
        {
            logger.LogWarning("Token audience validation failed. Expected: {Expected}, Actual: {Actual}", 
                jwtSettings.Audience, audience);
            return false;
        }

        return true;
    }

    private bool IsTokenExpiredBasedOnRawClaims(Dictionary<string, string> rawClaims)
    {
        if (!rawClaims.TryGetValue("exp", out var expClaim) || string.IsNullOrEmpty(expClaim))
            return true;

        if (long.TryParse(expClaim, out var expTimestamp))
        {
            var expiry = DateTimeOffset.FromUnixTimeSeconds(expTimestamp).UtcDateTime;
            return expiry <= DateTime.UtcNow;
        }

        return true;
    }

    /// <summary>
    /// Создание ClaimsPrincipal из raw claims
    /// </summary>
    private ClaimsPrincipal CreatePrincipalFromRawClaims(Dictionary<string, string> rawClaims)
    {
        var claims = rawClaims.Select(kvp => new Claim(kvp.Key, kvp.Value)).ToList();
        
        var identity = new ClaimsIdentity(
            claims,
            "JWT",
            JwtRegisteredClaimNames.Sub,
            ClaimTypes.Role);
        
        return new ClaimsPrincipal(identity);
    }

    private bool ValidateCustomClaims(Dictionary<string, string> rawClaims)
    {
        if (!rawClaims.Any())
        {
            logger.LogWarning("No claims found in token");
            return false;
        }

        var deviceId = rawClaims.GetValueOrDefault("device_id");
        var tokenType = rawClaims.GetValueOrDefault("token_type");
        var sub = rawClaims.GetValueOrDefault("sub");
        var jti = rawClaims.GetValueOrDefault("jti");

        logger.LogDebug("Custom claims validation - DeviceId: {DeviceId}, TokenType: {TokenType}, Sub: {Sub}, Jti: {Jti}", 
            deviceId, tokenType, sub, jti);

        if (string.IsNullOrEmpty(deviceId))
        {
            logger.LogWarning("Missing device_id claim in JWT token");
            return false;
        }

        if (tokenType != "access")
        {
            logger.LogWarning("Invalid token_type claim in JWT: '{TokenType}'. Expected: access", tokenType);
            return false;
        }

        if (string.IsNullOrEmpty(sub))
        {
            logger.LogWarning("Missing sub claim in JWT token");
            return false;
        }

        if (string.IsNullOrEmpty(jti))
        {
            logger.LogWarning("Missing jti claim in JWT token");
            return false;
        }

        logger.LogInformation("Custom claims validation successful for user '{UserId}'", sub);
        return true;
    }

    private void LogDebugRawClaims(Dictionary<string, string> rawClaims)
    {
        if (logger.IsEnabled(LogLevel.Debug))
        {
            logger.LogDebug("Raw JWT claims ({Count}):", rawClaims.Count);
            foreach (var claim in rawClaims)
            {
                logger.LogDebug("  {Type} = {Value}", claim.Key, claim.Value);
            }
        }
    }

    public async Task<bool> ValidateTokenAsync(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            return false;

        try
        {
            return await Task.Run(() => GetPrincipalFromToken(token) != null);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Async token validation failed");
            return false;
        }
    }

    public JwtSecurityToken? ReadToken(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            return tokenHandler.CanReadToken(token) ? tokenHandler.ReadJwtToken(token) : null;
        }
        catch
        {
            return null;
        }
    }

    public IEnumerable<Claim> GetTokenClaims(string token)
    {
        var rawClaims = ParseJwtPayloadRaw(token);
        return rawClaims.Select(kvp => new Claim(kvp.Key, kvp.Value));
    }

    public string? GetClaimValue(string token, string claimType)
    {
        var rawClaims = ParseJwtPayloadRaw(token);
        return rawClaims.GetValueOrDefault(claimType);
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

        logger.LogInformation("Token invalidated: {Jti}", jti);
    }
}