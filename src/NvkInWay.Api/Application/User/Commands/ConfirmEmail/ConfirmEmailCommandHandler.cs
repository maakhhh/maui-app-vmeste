using MediatR;

namespace NvkInWay.Api.Application.User.Commands.ConfirmEmail;

public class ConfirmEmailCommandHandler : IRequestHandler<ConfirmEmailCommand>
{
    public Task Handle(ConfirmEmailCommand request, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}