using FluentValidation;

namespace NvkInWay.Api.Application.User.Commands.Register;

public class RegisterCommandValidator : AbstractValidator<RegisterCommand>
{
    public RegisterCommandValidator()
    {
        RuleFor(x => x.Email).EmailAddress();
        RuleFor(x => x.FirstName).NotEmpty();
        RuleFor(x => x.SecondName).NotEmpty();

        RuleFor(x => x.Age)
            .GreaterThanOrEqualTo(17)
            .LessThanOrEqualTo(80);

        RuleFor(x => x.Password)
            .NotEmpty()
            .Length(8, 100);
    }
}