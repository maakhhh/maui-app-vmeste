namespace NvkInWay.Api.Settings;

public sealed class EmailConfigurationOptions
{
    public string EmailHost { get; set; }
    
    public int EmailHostPort { get; set; }
    public string EmailAddress { get; set; }
    
    public string Password { get; set; }
    
    public string SecureSocketOptions { get; set; }
}