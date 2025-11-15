using NvkInWay.Api.Domain;

namespace NvkInWay.Api.Persistence.Repositories;

public interface IDriveRepository
{
    Task DeleteDriveAsync(Drive drive);
}