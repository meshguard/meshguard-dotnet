using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using RichardSzalay.MockHttp;
using Xunit;

namespace MeshGuard.Tests;

public class MeshGuardClientTests
{
    private readonly MockHttpMessageHandler _mockHttp;
    private readonly MeshGuardClient _client;
    private readonly MeshGuardOptions _options;

    public MeshGuardClientTests()
    {
        _mockHttp = new MockHttpMessageHandler();
        _options = new MeshGuardOptions
        {
            GatewayUrl = "https://test.meshguard.app",
            AgentToken = "test-agent-token",
            AdminToken = "test-admin-token",
        };
        
        var httpClient = _mockHttp.ToHttpClient();
        httpClient.BaseAddress = new Uri(_options.GatewayUrl);
        
        // Use reflection to inject mock HTTP client
        _client = new MeshGuardClient(_options);
        var field = typeof(MeshGuardClient).GetField("_http", 
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        field?.SetValue(_client, httpClient);
    }

    // -------------------------------------------------------------------------
    // CheckAsync Tests
    // -------------------------------------------------------------------------

    [Fact]
    public async Task CheckAsync_WhenAllowed_ReturnsPolicyDecision()
    {
        // Arrange
        _mockHttp
            .When("/proxy/check")
            .Respond("application/json", JsonSerializer.Serialize(new
            {
                allowed = true,
                policy = "default-policy"
            }));

        // Act
        var decision = await _client.CheckAsync("read:contacts");

        // Assert
        Assert.True(decision.Allowed);
        Assert.Equal("allow", decision.Decision);
        Assert.Equal("read:contacts", decision.Action);
        Assert.Equal("default-policy", decision.Policy);
    }

    [Fact]
    public async Task CheckAsync_WhenDenied_ReturnsDenyDecision()
    {
        // Arrange
        _mockHttp
            .When("/proxy/check")
            .Respond(HttpStatusCode.Forbidden, "application/json", JsonSerializer.Serialize(new
            {
                action = "write:secrets",
                policy = "security-policy",
                rule = "no-secrets",
                message = "Access to secrets is denied"
            }));

        // Act
        var decision = await _client.CheckAsync("write:secrets");

        // Assert
        Assert.False(decision.Allowed);
        Assert.Equal("deny", decision.Decision);
        Assert.Equal("write:secrets", decision.Action);
        Assert.Equal("security-policy", decision.Policy);
        Assert.Equal("no-secrets", decision.Rule);
        Assert.Contains("denied", decision.Reason ?? "");
    }

    // -------------------------------------------------------------------------
    // EnforceAsync Tests
    // -------------------------------------------------------------------------

    [Fact]
    public async Task EnforceAsync_WhenAllowed_ReturnsDecision()
    {
        // Arrange
        _mockHttp
            .When("/proxy/check")
            .Respond("application/json", JsonSerializer.Serialize(new { allowed = true }));

        // Act
        var decision = await _client.EnforceAsync("read:contacts");

        // Assert
        Assert.True(decision.Allowed);
    }

    [Fact]
    public async Task EnforceAsync_WhenDenied_ThrowsPolicyDeniedException()
    {
        // Arrange
        _mockHttp
            .When("/proxy/check")
            .Respond(HttpStatusCode.Forbidden, "application/json", JsonSerializer.Serialize(new
            {
                action = "delete:everything",
                message = "Dangerous action denied"
            }));

        // Act & Assert
        var ex = await Assert.ThrowsAsync<PolicyDeniedException>(
            () => _client.EnforceAsync("delete:everything"));
        
        Assert.Equal("delete:everything", ex.Action);
        Assert.Contains("Dangerous action denied", ex.Message);
    }

    // -------------------------------------------------------------------------
    // GovernAsync Tests
    // -------------------------------------------------------------------------

    [Fact]
    public async Task GovernAsync_WhenAllowed_ExecutesFunction()
    {
        // Arrange
        _mockHttp
            .When("/proxy/check")
            .Respond("application/json", JsonSerializer.Serialize(new { allowed = true }));

        var executed = false;

        // Act
        await _client.GovernAsync("read:contacts", async () =>
        {
            executed = true;
            await Task.CompletedTask;
        });

        // Assert
        Assert.True(executed);
    }

    [Fact]
    public async Task GovernAsync_WhenAllowed_ReturnsResult()
    {
        // Arrange
        _mockHttp
            .When("/proxy/check")
            .Respond("application/json", JsonSerializer.Serialize(new { allowed = true }));

        // Act
        var result = await _client.GovernAsync("read:contacts", async () =>
        {
            await Task.CompletedTask;
            return 42;
        });

        // Assert
        Assert.Equal(42, result);
    }

    [Fact]
    public async Task GovernAsync_WhenDenied_DoesNotExecuteFunction()
    {
        // Arrange
        _mockHttp
            .When("/proxy/check")
            .Respond(HttpStatusCode.Forbidden, "application/json", "{}");

        var executed = false;

        // Act & Assert
        await Assert.ThrowsAsync<PolicyDeniedException>(async () =>
        {
            await _client.GovernAsync("write:secrets", async () =>
            {
                executed = true;
                await Task.CompletedTask;
            });
        });

        Assert.False(executed);
    }

    // -------------------------------------------------------------------------
    // Health Tests
    // -------------------------------------------------------------------------

    [Fact]
    public async Task GetHealthAsync_ReturnsHealthStatus()
    {
        // Arrange
        _mockHttp
            .When("/health")
            .Respond("application/json", JsonSerializer.Serialize(new
            {
                status = "healthy",
                version = "1.0.0",
                mode = "production"
            }));

        // Act
        var health = await _client.GetHealthAsync();

        // Assert
        Assert.Equal("healthy", health.Status);
        Assert.Equal("1.0.0", health.Version);
        Assert.Equal("production", health.Mode);
    }

    [Fact]
    public async Task IsHealthyAsync_WhenHealthy_ReturnsTrue()
    {
        // Arrange
        _mockHttp
            .When("/health")
            .Respond("application/json", JsonSerializer.Serialize(new { status = "healthy" }));

        // Act
        var isHealthy = await _client.IsHealthyAsync();

        // Assert
        Assert.True(isHealthy);
    }

    [Fact]
    public async Task IsHealthyAsync_WhenUnhealthy_ReturnsFalse()
    {
        // Arrange
        _mockHttp
            .When("/health")
            .Respond("application/json", JsonSerializer.Serialize(new { status = "degraded" }));

        // Act
        var isHealthy = await _client.IsHealthyAsync();

        // Assert
        Assert.False(isHealthy);
    }

    [Fact]
    public async Task IsHealthyAsync_WhenError_ReturnsFalse()
    {
        // Arrange
        _mockHttp
            .When("/health")
            .Respond(HttpStatusCode.ServiceUnavailable);

        // Act
        var isHealthy = await _client.IsHealthyAsync();

        // Assert
        Assert.False(isHealthy);
    }

    // -------------------------------------------------------------------------
    // Admin: ListAgents Tests
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ListAgentsAsync_ReturnsAgents()
    {
        // Arrange
        _mockHttp
            .When("/admin/agents")
            .Respond("application/json", JsonSerializer.Serialize(new
            {
                agents = new[]
                {
                    new { id = "agent-1", name = "Bot One", trustTier = "verified", tags = new[] { "support" } },
                    new { id = "agent-2", name = "Bot Two", trustTier = "sandboxed", tags = Array.Empty<string>() }
                }
            }));

        // Act
        var agents = await _client.ListAgentsAsync();

        // Assert
        Assert.Equal(2, agents.Count);
        Assert.Equal("agent-1", agents[0].Id);
        Assert.Equal("Bot One", agents[0].Name);
        Assert.Equal("verified", agents[0].TrustTier);
        Assert.Contains("support", agents[0].Tags);
    }

    [Fact]
    public async Task ListAgentsAsync_WithoutAdminToken_Throws()
    {
        // Arrange
        var options = new MeshGuardOptions
        {
            GatewayUrl = "https://test.meshguard.app",
            AdminToken = null, // No admin token
        };
        var client = new MeshGuardClient(options);

        // Act & Assert
        await Assert.ThrowsAsync<AuthenticationException>(
            () => client.ListAgentsAsync());
    }

    // -------------------------------------------------------------------------
    // Admin: CreateAgent Tests
    // -------------------------------------------------------------------------

    [Fact]
    public async Task CreateAgentAsync_ReturnsAgentWithToken()
    {
        // Arrange
        _mockHttp
            .When("/admin/agents")
            .Respond("application/json", JsonSerializer.Serialize(new
            {
                id = "new-agent",
                name = "New Bot",
                trustTier = "verified",
                token = "secret-token-123",
                tags = new[] { "new" }
            }));

        // Act
        var agent = await _client.CreateAgentAsync(new CreateAgentOptions
        {
            Name = "New Bot",
            TrustTier = "verified",
            Tags = new List<string> { "new" }
        });

        // Assert
        Assert.Equal("new-agent", agent.Id);
        Assert.Equal("New Bot", agent.Name);
        Assert.Equal("secret-token-123", agent.Token);
    }

    // -------------------------------------------------------------------------
    // Admin: RevokeAgent Tests
    // -------------------------------------------------------------------------

    [Fact]
    public async Task RevokeAgentAsync_Succeeds()
    {
        // Arrange
        _mockHttp
            .When("/admin/agents/agent-to-revoke")
            .Respond(HttpStatusCode.OK);

        // Act & Assert (should not throw)
        await _client.RevokeAgentAsync("agent-to-revoke");
    }

    // -------------------------------------------------------------------------
    // Admin: ListPolicies Tests
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ListPoliciesAsync_ReturnsPolicies()
    {
        // Arrange
        _mockHttp
            .When("/admin/policies")
            .Respond("application/json", JsonSerializer.Serialize(new
            {
                policies = new[]
                {
                    new { id = "policy-1", name = "Security Policy", active = true },
                    new { id = "policy-2", name = "Rate Limit Policy", active = false }
                }
            }));

        // Act
        var policies = await _client.ListPoliciesAsync();

        // Assert
        Assert.Equal(2, policies.Count);
        Assert.Equal("policy-1", policies[0].Id);
        Assert.Equal("Security Policy", policies[0].Name);
        Assert.True(policies[0].Active);
    }

    // -------------------------------------------------------------------------
    // Admin: GetAuditLog Tests
    // -------------------------------------------------------------------------

    [Fact]
    public async Task GetAuditLogAsync_ReturnsEntries()
    {
        // Arrange
        _mockHttp
            .When("/admin/audit*")
            .Respond("application/json", JsonSerializer.Serialize(new
            {
                entries = new[]
                {
                    new { id = "entry-1", action = "read:contacts", result = "allow", agentId = "bot-1" },
                    new { id = "entry-2", action = "write:secrets", result = "deny", agentId = "bot-2" }
                }
            }));

        // Act
        var entries = await _client.GetAuditLogAsync(new AuditLogOptions { Limit = 10 });

        // Assert
        Assert.Equal(2, entries.Count);
        Assert.Equal("entry-1", entries[0].Id);
        Assert.Equal("read:contacts", entries[0].Action);
        Assert.Equal("allow", entries[0].Result);
    }

    // -------------------------------------------------------------------------
    // Error Handling Tests
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Request_On401_ThrowsAuthenticationException()
    {
        // Arrange
        _mockHttp
            .When("/proxy/check")
            .Respond(HttpStatusCode.Unauthorized);

        // Act & Assert
        await Assert.ThrowsAsync<AuthenticationException>(
            () => _client.CheckAsync("any:action"));
    }

    [Fact]
    public async Task Request_On429_ThrowsRateLimitException()
    {
        // Arrange
        _mockHttp
            .When("/proxy/test")
            .Respond(HttpStatusCode.TooManyRequests);

        // Act & Assert
        await Assert.ThrowsAsync<RateLimitException>(
            () => _client.GetAsync("test", "test:action"));
    }

    [Fact]
    public async Task Request_On500_ThrowsMeshGuardException()
    {
        // Arrange
        _mockHttp
            .When("/proxy/test")
            .Respond(HttpStatusCode.InternalServerError, "text/plain", "Internal error");

        // Act & Assert
        var ex = await Assert.ThrowsAsync<MeshGuardException>(
            () => _client.GetAsync("test", "test:action"));
        
        Assert.Contains("500", ex.Message);
    }

    // -------------------------------------------------------------------------
    // TraceId Tests
    // -------------------------------------------------------------------------

    [Fact]
    public void Client_HasTraceId()
    {
        // Assert
        Assert.NotNull(_client.TraceId);
        Assert.NotEmpty(_client.TraceId);
    }

    [Fact]
    public void Client_UsesProvidedTraceId()
    {
        // Arrange
        var options = new MeshGuardOptions
        {
            GatewayUrl = "https://test.meshguard.app",
            TraceId = "custom-trace-id-123"
        };
        var client = new MeshGuardClient(options);

        // Assert
        Assert.Equal("custom-trace-id-123", client.TraceId);
    }
}
