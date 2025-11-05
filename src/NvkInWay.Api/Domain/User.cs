namespace NvkInWay.Api.Domain;

public class User
{
    public long Id { get; set; }
    
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