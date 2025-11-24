using System.Diagnostics.CodeAnalysis;
using JetBrains.Annotations;

namespace NvkInWay.Infrastructure;

public readonly struct Result<TValue, TError>
    where TError : ResultError
{
    private readonly TValue? value;

    private readonly TError? error;

    private Result(TValue? value, TError? error)
    {
        this.value = value;
        this.error = error;
    }

    public static Result<TValue, TError> Success([DisallowNull] TValue value)
    {
        ArgumentNullException.ThrowIfNull(value);

        return new Result<TValue, TError>(value, null);
    }

    public static Result<TValue, TError> Error([DisallowNull] TError error)
    {
        ArgumentNullException.ThrowIfNull(error);

        return new Result<TValue, TError>(default, error);
    }

    [MemberNotNullWhen(true, "value")]
    [MemberNotNullWhen(false, "error")]
    public bool HasValue
    {
        [MemberNotNullWhen(true, "value"), MemberNotNullWhen(false, "error")]
        get => error == null;
    }

    [MemberNotNullWhen(false, "value")]
    [MemberNotNullWhen(true, "error")]
    public bool HasError
    {
        [MemberNotNullWhen(false, "value"), MemberNotNullWhen(true, "error")]
        get => error != null;
    }

    [ContractAnnotation("onSuccess:null => halt; onError:null => halt")]
    public T Match<T>(Func<TValue?, T> onSuccess, Func<TError, T> onError)
    {
        ArgumentNullException.ThrowIfNull(onSuccess, nameof(onSuccess));
        ArgumentNullException.ThrowIfNull(onError, nameof(onError));

        return !HasValue ? onError(error) : onSuccess(value);
    }

    [ContractAnnotation("onSuccess:null => halt; onError:null => halt")]
    public async Task<T> MatchAsync<T>(Func<TValue, Task<T>> onSuccess, Func<TError, Task<T>> onError)
    {
        ArgumentNullException.ThrowIfNull(onSuccess, nameof(onSuccess));
        ArgumentNullException.ThrowIfNull(onError, nameof(onError));
        T obj;
        if (HasValue)
            obj = await onSuccess(value).ConfigureAwait(false);
        else
            obj = await onError(error).ConfigureAwait(false);
        return obj;
    }

    [ContractAnnotation("null => halt")]
    public Result<TValue, TError> ExecuteIfHasValue(
      Action<TValue> onSuccess)
    {
        ArgumentNullException.ThrowIfNull(onSuccess, nameof(onSuccess));
        if (HasValue)
            onSuccess(value);
        return this;
    }

    [ContractAnnotation("null => halt")]
    public async Task<Result<TValue, TError>> ExecuteIfHasValueAsync(
      Func<TValue, Task> onSuccess)
    {
        ArgumentNullException.ThrowIfNull(onSuccess, nameof(onSuccess));
        if (HasValue)
            await onSuccess(value).ConfigureAwait(false);
        return this;
    }

    [ContractAnnotation("null => halt")]
    public Result<TValue, TError> ExecuteIfHasError(Action<TError> onError)
    {
        ArgumentNullException.ThrowIfNull(onError, nameof(onError));
        if (HasError)
            onError(error);
        return this;
    }

    [ContractAnnotation("null => halt")]
    public async Task<Result<TValue, TError>> ExecuteIfHasErrorAsync(
      Func<TError, Task> onError)
    {
        ArgumentNullException.ThrowIfNull(onError, nameof(onError));
        if (HasError)
            await onError(error).ConfigureAwait(false);
        return this;
    }

    public TValue? ValueOrDefault()
    {
        return Match<TValue>(v => v!, _ => default!);
    }

    public TValue ValueOrThrow()
    {
        return Match(((Func<TValue, TValue>)(v => v))!,
          e => throw new ResultException(e));
    }

    public TError? ErrorOrDefault()
    {
        return Match<TError>((Func<TValue, TError>)(_ => null),
          e => e);
    }

    public void Deconstruct(out TValue? val, out TError? err)
    {
        val = value;
        err = error;
    }

    public override string ToString()
    {
        if (HasValue)
        {
            return $"HasValue: true, value: '{value}'";
        }

        if (!HasError)
        {
            throw new ArgumentOutOfRangeException(nameof(Result<TValue, TError>), "Result must contain a value or an error");
        }

        return $"HasError: true, error: '{error}'";
    }

    public Task<Result<TValue, TError>> AsTask()
    {
        return Task.FromResult(this);
    }

    public ValueTask<Result<TValue, TError>> AsValueTask()
    {
        return new ValueTask<Result<TValue, TError>>(this);
    }

    public static implicit operator TError?(in Result<TValue, TError> result)
    {
        return result.error;
    }

    public static implicit operator TValue?(in Result<TValue, TError> result)
    {
        return result.value;
    }

    public static implicit operator Result<TValue, TError>([DisallowNull] in TError resultError)
    {
        return Error(resultError);
    }

    public static implicit operator Result<TValue, TError>([DisallowNull] in TValue value)
    {
        return Success(value);
    }

    public static implicit operator Task<Result<TValue, TError>>(in Result<TValue, TError> result)
    {
        return result.AsTask();
    }

    public static implicit operator ValueTask<Result<TValue, TError>>(in Result<TValue, TError> result)
    {
        return result.AsValueTask();
    }
}