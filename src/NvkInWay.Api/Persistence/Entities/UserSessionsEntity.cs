using NvkInWay.Api.Persistence.Entities.Base;

namespace NvkInWay.Api.Persistence.Entities;

public class UserSessionsEntity : EntityBase
{
    public long UserId { get; set; }
    public string DeviceId { get; set; } = string.Empty;
    public string? PushToken { get; set; }
    public string? AppVersion { get; set; }
    public string? OsVersion { get; set; }
    public DateTime LastActivity { get; set; }
    public DateTime CreatedAt { get; set; }
    public bool IsActive { get; set; } = true;

    public UserEntity User { get; set; } = null!;
}