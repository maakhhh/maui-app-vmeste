namespace NvkInWay.Api.Exceptions;

public class TooManyAttemptsException(string message) : Exception(message);