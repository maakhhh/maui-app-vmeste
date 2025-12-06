using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NvkInWay.Api.Domain;
using NvkInWay.Api.Services;
using NvkInWay.Api.Utils;
using NvkInWay.Api.V1.Models;

namespace NvkInWay.Api.V1.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
public class TripController(IAuthHelper authHelper, ITripService tripService, IUserService userService, IMapper mapper) 
    : ControllerBase
{
    [Authorize]
    [HttpDelete("{tripId:long}")]
    public async Task<ActionResult> DeleteTrip([FromRoute] long tripId)
    {
        var user = await GetCurrentUser();
        
        await tripService.DeleteTrip(tripId, user);

        return Ok();
    }
    
    [Authorize]
    [HttpPost("{tripId:long}")]
    public async Task<ActionResult<V1TripDto>> UpdateTrip([FromRoute] long tripId, [FromBody] V1CreateTripDto tripRequest)
    {
        var user = await GetCurrentUser();
        
        var updatedTrip = await tripService.UpdateTrip(tripId, user, tripRequest);
        return mapper.Map<V1TripDto>(updatedTrip);
    }
    
    [Authorize]
    [HttpPost("")]
    public async Task<ActionResult<V1TripDto>> CreateTrip(V1CreateTripDto tripRequest)
    {
        var user = await GetCurrentUser();
        
        var createdTrip = await tripService.CreateTrip(tripRequest, user);
        
        return mapper.Map<V1TripDto>(createdTrip);
    }
    
    [Authorize]
    [HttpPost("/{tripId:long}/join")]
    public async Task<ActionResult> JoinToTrip([FromRoute] long tripId)
    {
        var user = await GetCurrentUser();
        
        await tripService.AddPassengerToTrip(tripId, user);
        
        return NoContent();
    }

    [Authorize]
    [HttpPost("/{tripId:long}/{passengerId:long}/approve")]
    public async Task<ActionResult> ApproveTripPassenger([FromRoute] long tripId, [FromRoute] long passengerId)
    {
        var user = await GetCurrentUser();
        
        await tripService.ApprovePassengerToTrip(tripId, passengerId, user);
        
        return NoContent();
    }

    [Authorize]
    [HttpGet("")]
    public async Task<ActionResult<List<V1TripDto>>> GetTrips([FromQuery] DateTimeOffset date)
    {
        return mapper.Map<List<V1TripDto>>(await tripService.GetTrips(date));
    }

    private async Task<User> GetCurrentUser()
    {
        var userId = authHelper.GetUserId(this);
        return await userService.GetUserById(userId);
    }
}