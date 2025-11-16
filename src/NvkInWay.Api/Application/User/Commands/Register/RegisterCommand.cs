using MediatR;

namespace NvkInWay.Api.Application.User.Commands.Register;

public class RegisterCommand(
    string email,
    string firstName,
    string secondName,
    string password,
    int age) : IRequest<Domain.User>
{
    public string Email { get; } = email;
    
    public string FirstName { get; } = firstName;

    public string SecondName { get; } = secondName;

    public string Password { get; } = password;

    public int Age { get; } = age;
}