using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NvkInWay.Api.Domain;
using NvkInWay.Api.Persistence.Repositories;
using NvkInWay.Api.Services;
using NvkInWay.Api.Utils;
using NvkInWay.Api.V1.Models;

namespace NvkInWay.Api.V1.Controllers;

[ApiController]
[Route("api/v1/auth")]
public sealed class AuthController(IAuthService authService, ILogger<AuthController> logger)
    : ControllerBase
{
    [Authorize]
    [HttpPost("confirm-email")]
    public async Task<ActionResult> ConfirmEmail([FromBody] V1ConfirmEmailRequest request)
    {
        await authService.ConfirmEmailAsync(request.Email, request.ConfirmationCode);
        
        return NoContent();
    }
    
    [Authorize]
    [HttpPost("send-confirmation")]
    public async Task<ActionResult> SendConfirmation([FromBody] V1SendConfirmationEmailRequest emailRequest,
        CancellationToken cancellationToken)
    {
        await authService.SendUniqueVerificationCodeAsync(emailRequest.Email, cancellationToken);
        
        return NoContent();
    }
    
    [HttpPost("login")]
    public async Task<ActionResult> Login([FromBody] V1LoginRequest request)
    {
        var tokens = await authService.LoginAsync(request.Email, request.Password, 
            request.DeviceId, request.DeviceName);

        return Ok(tokens);
    }

    [HttpPost("refresh")]
    public async Task<ActionResult> Refresh(V1RefreshTokenDto dto)
    {
        var accessToken = dto.AccessToken.Replace("Bearer ", "");
        var tokens = await authService.RefreshTokenAsync(accessToken, dto.RefreshToken, dto.DeviceId);

        return Ok(tokens);
    }

    [HttpPost("logout")]
    [Authorize]
    public async Task<ActionResult> Logout()
    {
        var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);
        var deviceId = User.FindFirst("device_id")!.Value;

        await authService.LogoutAsync(userId, deviceId);

        return Ok(new { message = "Logged out successfully" });
    }

    [HttpGet("sessions")]
    [Authorize]
    public async Task<ActionResult<IEnumerable<UserSession>>> GetSessions()
    {
        var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);
        var sessions = await authService.GetUserSessionsAsync(userId);
        
        return Ok(sessions);
    }
}