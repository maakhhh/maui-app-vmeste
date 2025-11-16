using JetBrains.Annotations;

namespace NvkInWay.Api.V1.Models;

[PublicAPI]
public class V1RegisterUserDto
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string FirstName { get; set; } = string.Empty;
    public string SecondName { get; set; } = string.Empty;
    
    public int Age { get; set; }
}