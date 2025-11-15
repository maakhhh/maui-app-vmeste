namespace NvkInWay.Api.Domain;

public class Drive
{
    // todo: или айдишник просто хранить? (вопрос по бд)
    public User? Driver { get; set; }
    
    public required string From { get; set; }
    
    public required string To { get; set; }
    
    public DateTime Start { get; set; }
    
    public DateTime End { get; set; }
    
    // todo: или айдишники?
    public List<User> Passengers { get; set; } = [];
    
    public int MaxPassengersCount { get; set; }
    
    public int PriceForPlace { get; set; }
    
    public bool TaxiEnabled { get; set; }
    
    public string? CarModel { get; set; }
    
    public string? CarNumber { get; set; }
}