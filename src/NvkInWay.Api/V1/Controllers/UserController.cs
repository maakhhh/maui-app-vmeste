using AutoMapper;
using MediatR;
using Microsoft.AspNetCore.Mvc;
using NvkInWay.Api.Application.User.Commands.Register;
using NvkInWay.Api.V1.Models;

namespace NvkInWay.Api.V1.Controllers;

[ApiController]
[Route("api/v1/user")]
public class UserController(IMediator mediator, IMapper mapper, ILogger<UserController> logger)
{
    [HttpPost("register")]
    public async Task<ActionResult<V1UserDto>> Register([FromBody] V1RegisterUserDto request)
    {
        var command = new RegisterCommand(request.Email, request.FirstName, 
            request.SecondName, request.Password, request.Age);
        
        var user = await mediator.Send(command);
        var dto = mapper.Map<V1UserDto>(user);

        return new ActionResult<V1UserDto>(dto);
    }
}