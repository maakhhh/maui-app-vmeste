namespace NvkInWay.Api.V1.Models;

public class V1LoginRequest
{
    public required string Email { get; set; }
    
    public required string Password { get; set; }
    
    public required string DeviceId { get; set; }
    
    public required string DeviceName { get; set; } //TODO (viteOkB): на будуще на fingrerprint перевести
}