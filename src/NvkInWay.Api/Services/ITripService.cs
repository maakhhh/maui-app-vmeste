using NvkInWay.Api.Domain;
using NvkInWay.Api.V1.Models;

namespace NvkInWay.Api.Services;

public interface ITripService
{
    Task AddPassengerToTrip(long tripId, User user);
    
    Task ApprovePassengerToTrip(long tripId, long passengerId, User user);
    
    Task<Trip> CreateTrip(V1CreateTripDto tripRequest, User user);
    
    Task<Trip> UpdateTrip(long tripId, User user, V1CreateTripDto tripRequest);
    
    Task DeleteTrip(long tripId, User user);

    Task<List<Trip>> GetTrips(DateTimeOffset date);
}