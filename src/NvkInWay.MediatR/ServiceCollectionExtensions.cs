using System.Reflection;
using FluentValidation;
using MediatR;
using Microsoft.Extensions.DependencyInjection;
using NvkInWay.MediatR.PipelineBehaviours;

namespace NvkInWay.MediatR;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddMediatRFromAssembly(this IServiceCollection services, Assembly assembly)
    {
        services.AddMediatR(m => m.RegisterServicesFromAssembly(assembly));
        
        services.AddSingleton(typeof(IPipelineBehavior<,>), typeof(RequestValidationBehavior<,>));
        services.AddSingleton(typeof(IPipelineBehavior<,>), typeof(RequestLoggingBehaviour<,>));
        services.AddSingleton(typeof(IPipelineBehavior<,>), typeof(HandleTimeMeasureBehaviour<,>));
        services.AddValidatorsFromAssembly(assembly, ServiceLifetime.Singleton);

        return services;
    }
}