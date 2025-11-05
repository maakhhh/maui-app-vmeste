using NvkInWay.Api.Persistence.Entities.Base;

namespace NvkInWay.Api.Persistence.Entities;

public sealed class UserEntity : EntityBase
{
    public required string Email { get; set; }
    
    public required string FirstName { get; set; }
    
    public required string SecondName { get; set; }
    
    public int Age { get; set; }
    
    public required string HashedPassword { get; set; }
    
    public DateTimeOffset CreatedAt { get; set; }
    
    public DateTimeOffset UpdatedAt { get; set; }
    
    public bool IsDeleted { get; set; }
    
    public bool IsBlocked { get; set; }
    
    public bool IsVerified { get; set; }
}