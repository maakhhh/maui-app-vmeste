using FluentValidation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using NvkInWay.Api.Exceptions;
using NvkInWay.Api.V1;

namespace NvkInWay.Api.Filters;

public sealed class CustomExceptionFilter(
    IWebHostEnvironment environment, ILogger<CustomExceptionFilter> logger) : IAsyncExceptionFilter
{
    public async Task OnExceptionAsync(ExceptionContext context)
    {
        var exception = context.Exception;
        
        await Task.Run(() =>
        {
            var (status, error) = exception switch
            {
                NotFoundException => (404, new ErrorResponse
                {
                    Error = "Not Found",
                    Message = exception.Message
                }),
                ValidationException ex => (400, new ErrorResponse
                {
                    Error = "Bad Request",
                    Message = "Validation failed",
                    Errors = ExtractValidationErrors(ex)
                }),
                TooManyAttemptsException => (429, new ErrorResponse
                {
                    Error = "Too Many Requests",
                    Message = exception.Message
                }),
                UnauthorizedException => (401, new ErrorResponse
                {
                    Error = "Unauthorized",
                    Message = exception.Message
                }),
                _ => (500, new ErrorResponse
                { 
                    Error = "Internal Server Error",
                    Message = environment.IsDevelopment() ? exception.Message : "An error occurred"
                })
            };

            context.Result = new ObjectResult(error)
            {
                StatusCode = status,
            };
            context.ExceptionHandled = true;

            if (status >= 500)
            {
                logger.LogError(context.Exception, "Unhandled exception: {Message}", exception.Message);
            }
        });
    }
    
    private static string[] ExtractValidationErrors(ValidationException ex)
    {
        if (ex.Errors == null || !ex.Errors.Any())
            return Array.Empty<string>();

        return ex.Errors
            .Select(error => $"{error.PropertyName}: {error.ErrorMessage}")
            .ToArray();
    }
}