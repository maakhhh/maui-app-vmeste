namespace NvkInWay.Api.V1.Models;

public class V1UserDto
{
    public long Id { get; set; }
    
    public required string Email { get; set; }
    
    public required string FirstName { get; set; }
    
    public required string SecondName { get; set; }
    
    public int Age { get; set; }
}