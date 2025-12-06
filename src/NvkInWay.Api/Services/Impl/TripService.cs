using System.ComponentModel.DataAnnotations;
using AutoMapper;
using NvkInWay.Api.Domain;
using NvkInWay.Api.Exceptions;
using NvkInWay.Api.Persistence.Repositories;
using NvkInWay.Api.V1.Models;

namespace NvkInWay.Api.Services.Impl;

internal sealed class TripService(
    ITripRepository tripRepository,
    ITripPassengerRepository passengerRepository,
    IMapper mapper) 
    : ITripService
{
    public async Task AddPassengerToTrip(long tripId, User user)
    {
        await tripRepository.GetTripByIdAsync(tripId);
        await passengerRepository.CreateTripPassengerAsync(new TripPassenger
        {
            TripId = tripId,
            PassengerId = user.Id,
            Passenger = user
        });
    }

    public async Task ApprovePassengerToTrip(long tripId, long passengerId, User user)
    {
        var trip = await tripRepository.GetTripByIdAsync(tripId);
        var passenger = await passengerRepository.GetTripPassengerByIdAsync(passengerId);
        
        if (trip.CreatorId != user.Id)
            throw new UnauthorizedAccessException($"You do not have access to trip {trip.Id}");
        
        if (passenger.IsApproved)
            throw new ValidationException($"Passenger {passenger.Id} is already approved");

        passenger.IsApproved = true;

        await passengerRepository.UpdateTripPassengerAsync(passenger);
    }

    public async Task<Trip> CreateTrip(V1CreateTripDto tripRequest, User user)
    {
        var trip = mapper.Map<Trip>(tripRequest);
        
        trip.CreatorId = user.Id;
        trip.CreatedAt = DateTimeOffset.Now;
        trip.UpdatedAt = DateTimeOffset.Now;
        
        return await tripRepository.CreateTripAsync(trip);
    }

    public async Task<Trip> UpdateTrip(long tripId, User user, V1CreateTripDto tripRequest)
    {
        var trip = await tripRepository.GetTripByIdAsync(tripId);
        
        if (trip.CreatorId != user.Id)
            throw new UnauthorizedAccessException($"You do not have access to trip {trip.Id}");
        
        if (trip.IsClosed)
            throw new ValidationException($"Trip {tripId} is closed");
        
        if (trip.IsDeleted)
            throw new NotFoundException($"Trip {tripId} is deleted");
        
        if (trip.IsEnded)
            throw new ValidationException($"Trip {tripId} is ended");
        
        mapper.Map(tripRequest, trip);
        trip.UpdatedAt = DateTimeOffset.Now;
        return await tripRepository.UpdateTripAsync(trip);
    }

    public async Task DeleteTrip(long tripId, User user)
    {
        var trip = await tripRepository.GetTripByIdAsync(tripId);
        
        if (trip.CreatorId != user.Id)
            throw new UnauthorizedAccessException($"You do not have access to trip {trip.Id}");
        
        trip.IsDeleted = true;
        trip.UpdatedAt = DateTimeOffset.Now;
        await tripRepository.UpdateTripAsync(trip);
    }

    public async Task<List<Trip>> GetTrips(DateTimeOffset date)
    {
        var trips = await tripRepository.GetAllTripsAsync();
        return trips.Where(t => t.CreatedAt == date && !t.IsDeleted).ToList();
    }
}