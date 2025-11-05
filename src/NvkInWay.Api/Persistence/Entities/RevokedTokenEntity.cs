using NvkInWay.Api.Domain;
using NvkInWay.Api.Persistence.Entities.Base;

namespace NvkInWay.Api.Persistence.Entities;

public class RevokedTokenEntity : EntityBase
{
    public string JwtId { get; set; } = string.Empty;
    
    public long UserId { get; set; }
    
    public string? TokenHash { get; set; }
    
    public DateTime ExpiryDate { get; set; }
    
    public DateTime RevokedAt { get; set; }
    
    public RevocationTypeValue RevocationType { get; set; }
    
    public string? Reason { get; set; }
    
    public string? DeviceId { get; set; }

    public UserEntity User { get; set; } = null;
}