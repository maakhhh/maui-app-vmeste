namespace NvkInWay.Api.V1.Models;

public class V1LoginRequest
{
    public required string Email { get; set; }
    
    public required string Password { get; set; }
}