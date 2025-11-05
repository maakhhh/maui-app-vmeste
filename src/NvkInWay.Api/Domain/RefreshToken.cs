namespace NvkInWay.Api.Domain;

internal sealed class RefreshToken
{
    public long Id { get; set; }
    public long UserId { get; set; }
    public string Token { get; set; } = string.Empty;
    public string JwtId { get; set; } = string.Empty;
    public bool IsUsed { get; set; }
    public bool IsRevoked { get; set; }
    public DateTimeOffset RevokedAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiryDate { get; set; }
    public string DeviceId { get; set; } = string.Empty;
    public string? DeviceName { get; set; }

    public User User { get; set; } = null!;
}