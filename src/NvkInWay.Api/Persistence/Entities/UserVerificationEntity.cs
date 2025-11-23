using NvkInWay.Api.Persistence.Entities.Base;

namespace NvkInWay.Api.Persistence.Entities;

public sealed class UserVerificationEntity : EntityBase
{
    public required long UserId { get; set; }
    
    public required string UnconfirmedEmail { get; set; }
    
    public required DateTimeOffset VerificationCodeCreatedAt { get; set; }
    
    public required DateTimeOffset VerificationCodeExpiredAt { get; set; }

    public required string UnconfirmedEmailCode { get; set; }
    
    public string? VerificationCode { get; set; }

    public DateTimeOffset? LastVerificationAt { get; set; }
    
    public UserEntity User { get; set; } = null!;

    public bool NotActual { get; set; }
}