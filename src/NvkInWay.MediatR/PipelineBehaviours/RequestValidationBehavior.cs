using FluentValidation;
using JetBrains.Annotations;
using MediatR;

namespace NvkInWay.MediatR.PipelineBehaviours;

[UsedImplicitly]
internal sealed class RequestValidationBehavior<TRequest, TResponse>(IEnumerable<IValidator<TRequest>> validators)
    : IPipelineBehavior<TRequest, TResponse>
    where TRequest : IBaseRequest
{
    public Task<TResponse> Handle(TRequest request, RequestHandlerDelegate<TResponse> next,
                                  CancellationToken cancellationToken)
    {
        var context = new ValidationContext<TRequest>(request);

        var failures = validators
            .Select(v => v.Validate(context))
            .SelectMany(r => r.Errors)
            .Where(failure => failure != null)
            .ToArray();

        if (failures.Length > 0)
        {
            throw new ValidationException(failures);
        }

        return next(cancellationToken);
    }
}
