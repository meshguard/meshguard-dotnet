using Xunit;

namespace MeshGuard.Tests;

public class ExceptionTests
{
    [Fact]
    public void MeshGuardException_ContainsMessage()
    {
        var ex = new MeshGuardException("Test error");
        Assert.Equal("Test error", ex.Message);
    }

    [Fact]
    public void MeshGuardException_ContainsTraceId()
    {
        var ex = new MeshGuardException("Test error", "trace-123");
        Assert.Equal("trace-123", ex.TraceId);
    }

    [Fact]
    public void AuthenticationException_HasDefaultMessage()
    {
        var ex = new AuthenticationException();
        Assert.Contains("Invalid or expired token", ex.Message);
    }

    [Fact]
    public void AuthenticationException_AcceptsCustomMessage()
    {
        var ex = new AuthenticationException("Custom auth error", "trace-456");
        Assert.Equal("Custom auth error", ex.Message);
        Assert.Equal("trace-456", ex.TraceId);
    }

    [Fact]
    public void RateLimitException_HasDefaultMessage()
    {
        var ex = new RateLimitException();
        Assert.Contains("Rate limit exceeded", ex.Message);
    }

    [Fact]
    public void PolicyDeniedException_ContainsAction()
    {
        var ex = new PolicyDeniedException("read:contacts");
        Assert.Equal("read:contacts", ex.Action);
        Assert.Contains("read:contacts", ex.Message);
    }

    [Fact]
    public void PolicyDeniedException_ContainsAllFields()
    {
        var ex = new PolicyDeniedException(
            action: "write:secrets",
            policy: "security-policy",
            rule: "no-secrets-rule",
            reason: "Secrets are protected",
            traceId: "trace-789"
        );

        Assert.Equal("write:secrets", ex.Action);
        Assert.Equal("security-policy", ex.Policy);
        Assert.Equal("no-secrets-rule", ex.Rule);
        Assert.Equal("Secrets are protected", ex.Reason);
        Assert.Equal("trace-789", ex.TraceId);
        
        // Check message formatting
        Assert.Contains("write:secrets", ex.Message);
        Assert.Contains("security-policy", ex.Message);
        Assert.Contains("no-secrets-rule", ex.Message);
        Assert.Contains("Secrets are protected", ex.Message);
    }

    [Fact]
    public void PolicyDeniedException_HasDefaultReason()
    {
        var ex = new PolicyDeniedException("test:action");
        Assert.Equal("Access denied by policy", ex.Reason);
    }

    [Fact]
    public void PolicyDeniedException_IsBaseException()
    {
        var ex = new PolicyDeniedException("test:action");
        Assert.IsAssignableFrom<MeshGuardException>(ex);
        Assert.IsAssignableFrom<Exception>(ex);
    }

    [Fact]
    public void AllExceptions_AreMeshGuardException()
    {
        Assert.IsAssignableFrom<MeshGuardException>(new AuthenticationException());
        Assert.IsAssignableFrom<MeshGuardException>(new RateLimitException());
        Assert.IsAssignableFrom<MeshGuardException>(new PolicyDeniedException("test"));
    }

    [Fact]
    public void Exceptions_CanBeCaughtAsMeshGuardException()
    {
        try
        {
            throw new PolicyDeniedException("test:action", reason: "Denied");
        }
        catch (MeshGuardException ex)
        {
            Assert.NotNull(ex);
            Assert.Contains("test:action", ex.Message);
        }
    }
}
