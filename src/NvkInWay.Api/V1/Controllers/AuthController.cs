using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NvkInWay.Api.Domain;
using NvkInWay.Api.Services;
using NvkInWay.Api.V1.Models;

namespace NvkInWay.Api.V1.Controllers;

[ApiController]
[Route("api/v1/auth")]
public sealed class AuthController : ControllerBase
{
    private readonly IAuthService authService;
    private readonly ILogger<AuthController> logger;

    public AuthController(IAuthService authService, ILogger<AuthController> logger)
    {
        this.authService = authService;
        this.logger = logger;
    }

    [HttpPost("register")]
    public async Task<ActionResult> Register([FromBody] V1RegisterUserDto request)
    {
        throw new NotImplementedException();
    }
    
    [HttpPost("confirm-email")]
    public async Task<ActionResult> ConfirmEmail([FromBody] V1ConfirmEmailRequest request)
    {
        throw new NotImplementedException();
    }
    
    [HttpPost("resend-confirmation")]
    public async Task<ActionResult> ResendConfirmation([FromBody] V1ResendConfirmationEmailRequest emailRequest)
    {
        throw new NotImplementedException();
    }
    
    [HttpPost("login")]
    public async Task<ActionResult> Login([FromBody] V1LoginRequest request)
    {
        throw new NotImplementedException();
    }

    [HttpPost("refresh")]
    public async Task<ActionResult> Refresh()
    {
        var deviceId = Request.Headers["X-Device-Id"].FirstOrDefault();
        var authorizationHeader = Request.Headers["Authorization"].FirstOrDefault();
        var refreshToken = Request.Headers["X-Refresh-Token"].FirstOrDefault();

        throw new NotImplementedException();
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