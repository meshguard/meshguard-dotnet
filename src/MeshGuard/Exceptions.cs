using System.Text.Json.Serialization;

namespace MeshGuard;

/// <summary>
/// Base exception for all MeshGuard errors.
/// </summary>
public class MeshGuardException : Exception
{
    /// <summary>
    /// Trace ID for request correlation.
    /// </summary>
    public string? TraceId { get; }

    public MeshGuardException(string message, string? traceId = null) 
        : base(message)
    {
        TraceId = traceId;
    }

    public MeshGuardException(string message, Exception innerException, string? traceId = null)
        : base(message, innerException)
    {
        TraceId = traceId;
    }
}

/// <summary>
/// Raised when authentication fails (401).
/// </summary>
public class AuthenticationException : MeshGuardException
{
    public AuthenticationException(string message = "Invalid or expired token", string? traceId = null)
        : base(message, traceId)
    {
    }
}

/// <summary>
/// Raised when an action is denied by policy (403).
/// </summary>
public class PolicyDeniedException : MeshGuardException
{
    /// <summary>
    /// The action that was denied.
    /// </summary>
    public string Action { get; }

    /// <summary>
    /// The policy that denied the action.
    /// </summary>
    public string? Policy { get; }

    /// <summary>
    /// The specific rule that matched.
    /// </summary>
    public string? Rule { get; }

    /// <summary>
    /// Human-readable reason for denial.
    /// </summary>
    public string Reason { get; }

    public PolicyDeniedException(
        string action,
        string? policy = null,
        string? rule = null,
        string? reason = null,
        string? traceId = null)
        : base(BuildMessage(action, policy, rule, reason), traceId)
    {
        Action = action;
        Policy = policy;
        Rule = rule;
        Reason = reason ?? "Access denied by policy";
    }

    private static string BuildMessage(string action, string? policy, string? rule, string? reason)
    {
        var message = $"Action '{action}' denied";
        if (policy is not null)
            message += $" by policy '{policy}'";
        if (rule is not null)
            message += $" (rule: {rule})";
        message += $": {reason ?? "Access denied by policy"}";
        return message;
    }
}

/// <summary>
/// Raised when rate limit is exceeded (429).
/// </summary>
public class RateLimitException : MeshGuardException
{
    public RateLimitException(string message = "Rate limit exceeded", string? traceId = null)
        : base(message, traceId)
    {
    }
}

/// <summary>
/// Legacy exception alias for backwards compatibility.
/// Use <see cref="PolicyDeniedException"/> instead.
/// </summary>
[Obsolete("Use PolicyDeniedException instead")]
public class MeshGuardDeniedException : PolicyDeniedException
{
    public PermissionRequest Request { get; }

    public MeshGuardDeniedException(string? reason, PermissionRequest request)
        : base(request.Action, policy: null, rule: null, reason)
    {
        Request = request;
    }
}
