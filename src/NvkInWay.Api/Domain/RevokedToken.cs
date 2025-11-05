namespace NvkInWay.Api.Domain;

internal sealed class RevokedToken
{
    public long Id { get; set; }

    public string JwtId { get; set; } = string.Empty;
    
    public long UserId { get; set; }
    
    public string? TokenHash { get; set; }
    
    public DateTime ExpiryDate { get; set; }
    
    public DateTime RevokedAt { get; set; }
    
    public RevocationType RevocationType { get; set; }
    
    public string? Reason { get; set; }
    
    public string? DeviceId { get; set; }

    public User User { get; set; } = null;
}