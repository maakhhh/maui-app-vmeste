namespace NvkInWay.Api.V1;

public class ErrorResponse
{
    public required string Error { get; set; }
    public required string Message { get; set; }
    public string[] Errors { get; set; } = [];
}