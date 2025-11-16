using System.Reflection;
using MediatR;
using Microsoft.Extensions.Logging;

namespace NvkInWay.MediatR.PipelineBehaviours;

public class RequestLoggingBehaviour<TRequest, TResponse>(ILogger<RequestLoggingBehaviour<TRequest, TResponse>> logger)
    : IPipelineBehavior<TRequest, TResponse> where TRequest : IBaseRequest
{
    private readonly PropertyInfo[] propertyInfos = typeof(TRequest)
        .GetProperties(BindingFlags.Public | BindingFlags.Instance);
    
    public async Task<TResponse> Handle(TRequest request, RequestHandlerDelegate<TResponse> next, CancellationToken cancellationToken)
    {
        var properties = propertyInfos.Select(p
            => $"'{p.Name}'={p.GetValue(request) ?? "null"}").ToArray();
        
        logger.LogInformation("Request '{RequestName}', properties: [{RequestProperties}]", 
            typeof(TRequest).Name, properties);

        return await next(cancellationToken);
    }
}