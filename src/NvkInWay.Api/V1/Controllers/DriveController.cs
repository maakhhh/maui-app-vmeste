using Microsoft.AspNetCore.Mvc;
using NvkInWay.Api.Services;
using NvkInWay.Api.V1.Models;

namespace NvkInWay.Api.V1.Controllers;

[ApiController]
[Route("api/v1/drives")]
public class DriveController : ControllerBase
{
    private readonly IDriveService driveService;
    private readonly ILogger<DriveController> logger;

    public DriveController(IDriveService driveService, ILogger<DriveController> logger)
    {
        this.driveService = driveService;
        this.logger = logger;
    }

    [HttpGet]
    public async Task<ActionResult<List<V1DriveGetResponse>>> GetAllDrives()
    {
        throw new NotImplementedException();
    }
    
    
}