namespace NvkInWay.Api.V1.Models;

public class V1ConfirmEmailRequest
{
    public string Email { get; set; } = string.Empty;
    public string ConfirmationCode { get; set; } = string.Empty;
    public string DeviceId { get; set; } = string.Empty;
}