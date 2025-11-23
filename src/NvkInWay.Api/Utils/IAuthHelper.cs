using Microsoft.AspNetCore.Mvc;

namespace NvkInWay.Api.Utils;

public interface IAuthHelper
{
    long GetUserId(ControllerBase controller);
}