using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace NvkInWay.Api.Persistence.Converters;

public class DateTimeOffsetToUtcConverter()
    : ValueConverter<DateTimeOffset, DateTimeOffset>(
        v => v.ToUniversalTime(),
        v => v);