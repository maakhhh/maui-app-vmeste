using AutoMapper;
using NvkInWay.Api.Domain;
using NvkInWay.Api.V1.Models;

namespace NvkInWay.Api.V1;

public class DtoMappingProfile : Profile
{
    public DtoMappingProfile()
    {
        CreateMap<User, V1UserDto>();
    }
}