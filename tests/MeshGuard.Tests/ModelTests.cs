using System.Text.Json;
using Xunit;

namespace MeshGuard.Tests;

public class ModelTests
{
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
    };

    [Fact]
    public void MeshGuardOptions_HasDefaults()
    {
        var options = new MeshGuardOptions();
        
        Assert.Equal("https://dashboard.meshguard.app", options.GatewayUrl);
        Assert.Equal(30, options.TimeoutSeconds);
    }

    [Fact]
    public void PolicyDecision_SerializesCorrectly()
    {
        var decision = new PolicyDecision
        {
            Allowed = true,
            Action = "read:contacts",
            Decision = "allow",
            Policy = "default",
            TraceId = "trace-123"
        };

        var json = JsonSerializer.Serialize(decision, _jsonOptions);
        var parsed = JsonSerializer.Deserialize<PolicyDecision>(json, _jsonOptions);

        Assert.NotNull(parsed);
        Assert.True(parsed.Allowed);
        Assert.Equal("read:contacts", parsed.Action);
        Assert.Equal("allow", parsed.Decision);
    }

    [Fact]
    public void PolicyDecision_DeserializesFromApi()
    {
        var json = @"{
            ""allowed"": false,
            ""action"": ""write:secrets"",
            ""decision"": ""deny"",
            ""policy"": ""security-policy"",
            ""rule"": ""no-secrets"",
            ""reason"": ""Access denied"",
            ""traceId"": ""abc123""
        }";

        var decision = JsonSerializer.Deserialize<PolicyDecision>(json, _jsonOptions);

        Assert.NotNull(decision);
        Assert.False(decision.Allowed);
        Assert.Equal("write:secrets", decision.Action);
        Assert.Equal("deny", decision.Decision);
        Assert.Equal("security-policy", decision.Policy);
        Assert.Equal("no-secrets", decision.Rule);
        Assert.Equal("Access denied", decision.Reason);
    }

    [Fact]
    public void Agent_SerializesCorrectly()
    {
        var agent = new Agent
        {
            Id = "agent-1",
            Name = "Test Bot",
            TrustTier = "verified",
            Tags = new List<string> { "support", "internal" },
            OrgId = "org-123"
        };

        var json = JsonSerializer.Serialize(agent, _jsonOptions);
        var parsed = JsonSerializer.Deserialize<Agent>(json, _jsonOptions);

        Assert.NotNull(parsed);
        Assert.Equal("agent-1", parsed.Id);
        Assert.Equal("Test Bot", parsed.Name);
        Assert.Equal("verified", parsed.TrustTier);
        Assert.Equal(2, parsed.Tags.Count);
        Assert.Contains("support", parsed.Tags);
    }

    [Fact]
    public void CreateAgentOptions_HasDefaults()
    {
        var options = new CreateAgentOptions { Name = "Test" };
        
        Assert.Equal("Test", options.Name);
        Assert.Equal("verified", options.TrustTier);
        Assert.NotNull(options.Tags);
        Assert.Empty(options.Tags);
    }

    [Fact]
    public void AuditEntry_SerializesCorrectly()
    {
        var entry = new AuditEntry
        {
            Id = "entry-1",
            Timestamp = "2024-01-15T10:30:00Z",
            AgentId = "agent-1",
            Action = "read:contacts",
            Result = "allow",
            Resource = "contacts-db"
        };

        var json = JsonSerializer.Serialize(entry, _jsonOptions);
        var parsed = JsonSerializer.Deserialize<AuditEntry>(json, _jsonOptions);

        Assert.NotNull(parsed);
        Assert.Equal("entry-1", parsed.Id);
        Assert.Equal("agent-1", parsed.AgentId);
        Assert.Equal("read:contacts", parsed.Action);
        Assert.Equal("allow", parsed.Result);
    }

    [Fact]
    public void AuditLogOptions_HasDefaults()
    {
        var options = new AuditLogOptions();
        
        Assert.Equal(50, options.Limit);
        Assert.Null(options.Decision);
        Assert.Null(options.AgentId);
        Assert.Null(options.Action);
    }

    [Fact]
    public void Policy_SerializesCorrectly()
    {
        var policy = new Policy
        {
            Id = "policy-1",
            Name = "Security Policy",
            Description = "Protects sensitive resources",
            Active = true
        };

        var json = JsonSerializer.Serialize(policy, _jsonOptions);
        var parsed = JsonSerializer.Deserialize<Policy>(json, _jsonOptions);

        Assert.NotNull(parsed);
        Assert.Equal("policy-1", parsed.Id);
        Assert.Equal("Security Policy", parsed.Name);
        Assert.True(parsed.Active);
    }

    [Fact]
    public void HealthStatus_DeserializesFromApi()
    {
        var json = @"{
            ""status"": ""healthy"",
            ""version"": ""1.2.3"",
            ""mode"": ""production""
        }";

        var health = JsonSerializer.Deserialize<HealthStatus>(json, _jsonOptions);

        Assert.NotNull(health);
        Assert.Equal("healthy", health.Status);
        Assert.Equal("1.2.3", health.Version);
        Assert.Equal("production", health.Mode);
    }

    [Fact]
    public void PermissionRequest_SerializesWithCamelCase()
    {
        var request = new PermissionRequest
        {
            AgentId = "agent-1",
            Action = "read:contacts",
            Resource = "contacts-db",
            DelegatedBy = "admin-agent"
        };

        var json = JsonSerializer.Serialize(request, _jsonOptions);

        Assert.Contains("\"agentId\"", json);
        Assert.Contains("\"action\"", json);
        Assert.Contains("\"resource\"", json);
        Assert.Contains("\"delegatedBy\"", json);
    }
}
