using NvkInWay.Api.Persistence.Entities.Base;

namespace NvkInWay.Api.Persistence.Entities;

public class DriveEntity : EntityBase
{
    // todo: или айдишник просто хранить? (вопрос по бд)
    public UserEntity? Driver { get; set; }
    
    public required string From { get; set; }
    
    public required string To { get; set; }
    
    public DateTime Start { get; set; }
    
    public DateTime End { get; set; }
    
    // todo: или айдишники?
    public List<UserEntity> Passengers { get; set; } = [];
    
    public int MaxPassengersCount { get; set; }
    
    public int PriceForPlace { get; set; }
    
    public bool TaxiEnabled { get; set; }
    
    public string? CarModel { get; set; }
    
    public string? CarNumber { get; set; }
}