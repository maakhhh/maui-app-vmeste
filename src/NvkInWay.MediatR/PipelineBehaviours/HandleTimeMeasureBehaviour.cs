using System.Diagnostics;
using JetBrains.Annotations;
using MediatR;
using Microsoft.Extensions.Logging;

namespace NvkInWay.MediatR.PipelineBehaviours;

[UsedImplicitly]
public class HandleTimeMeasureBehaviour<TRequest, TResponse>(
    ILogger<HandleTimeMeasureBehaviour<TRequest, TResponse>> logger)
    : IPipelineBehavior<TRequest, TResponse> where TRequest : IBaseRequest
{
    public async Task<TResponse> Handle(TRequest request, RequestHandlerDelegate<TResponse> next, CancellationToken cancellationToken)
    {
        var sw = Stopwatch.StartNew();
        logger.LogInformation("Begin request {RequestName}", typeof(TRequest).Name);

        try
        {
            var response = await next(cancellationToken);
            sw.Stop();

            logger.LogInformation("End request {RequestName}, elapsed : {Elapsed}", typeof(TRequest).Name, sw.Elapsed);
            return response;
        }
        catch (Exception)
        {
            logger.LogInformation("End request {RequestName}, elapsed : {Elapsed}", typeof(TRequest).Name, sw.Elapsed);
            throw;
        }
    }
}