namespace NvkInWay.Api.Settings;

public sealed class EmailVerificationOptions
{
    public required int MaxCreatedVerificationCount { get; set; }
    
    public required TimeSpan RecreateTimeout { get; set; }
    
    public required TimeSpan VerificationTimeout { get; set; }
    
    public required int VerificationCodeLength { get; set; }
    
    public required TimeSpan CodeExpiration { get; set; }
    
    public required string AppName { get; set; }
}