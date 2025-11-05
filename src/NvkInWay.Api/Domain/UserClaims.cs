namespace NvkInWay.Api.Domain;

internal sealed class UserClaims
{
    public long UserId { get; set; }

    public string Email { get; set; } = string.Empty;

    public string[] Roles { get; set; } = [];
}