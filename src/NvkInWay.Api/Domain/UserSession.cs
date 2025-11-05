namespace NvkInWay.Api.Domain;

public sealed class UserSession
{
    public long Id { get; set; }
    public long UserId { get; set; }
    public string DeviceId { get; set; } = string.Empty;
    public string? PushToken { get; set; }
    public string? AppVersion { get; set; }
    public string? OsVersion { get; set; }
    public DateTime LastActivity { get; set; }
    public DateTime CreatedAt { get; set; }
    public bool IsActive { get; set; } = true;

    public User User { get; set; } = null!;
}