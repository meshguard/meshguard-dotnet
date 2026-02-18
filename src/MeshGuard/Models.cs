using System.Text.Json.Serialization;

namespace MeshGuard;

/// <summary>
/// Configuration options for the MeshGuard client.
/// </summary>
public class MeshGuardOptions
{
    /// <summary>
    /// MeshGuard gateway URL. Falls back to MESHGUARD_GATEWAY_URL env var.
    /// </summary>
    public string GatewayUrl { get; set; } = 
        Environment.GetEnvironmentVariable("MESHGUARD_GATEWAY_URL") 
        ?? "https://dashboard.meshguard.app";

    /// <summary>
    /// Agent JWT token for proxy operations. Falls back to MESHGUARD_AGENT_TOKEN env var.
    /// </summary>
    public string? AgentToken { get; set; } = 
        Environment.GetEnvironmentVariable("MESHGUARD_AGENT_TOKEN");

    /// <summary>
    /// Admin token for management APIs. Falls back to MESHGUARD_ADMIN_TOKEN env var.
    /// </summary>
    public string? AdminToken { get; set; } = 
        Environment.GetEnvironmentVariable("MESHGUARD_ADMIN_TOKEN");

    /// <summary>
    /// Request timeout in seconds. Default: 30.
    /// </summary>
    public int TimeoutSeconds { get; set; } = 30;

    /// <summary>
    /// Optional trace ID for request correlation. Auto-generated if omitted.
    /// </summary>
    public string? TraceId { get; set; }

    /// <summary>
    /// Legacy API key property. Use AgentToken or AdminToken instead.
    /// </summary>
    [Obsolete("Use AgentToken or AdminToken instead")]
    public string? ApiKey 
    { 
        get => AgentToken; 
        set => AgentToken = value; 
    }
}

/// <summary>
/// Request to check if an action is allowed by policy.
/// </summary>
public class PermissionRequest
{
    /// <summary>
    /// Agent performing the action.
    /// </summary>
    [JsonPropertyName("agentId")]
    public string AgentId { get; set; } = string.Empty;

    /// <summary>
    /// Action to check (e.g., "read:contacts", "write:email").
    /// </summary>
    [JsonPropertyName("action")]
    public string Action { get; set; } = string.Empty;

    /// <summary>
    /// Optional resource identifier.
    /// </summary>
    [JsonPropertyName("resource")]
    public string? Resource { get; set; }

    /// <summary>
    /// Optional context for policy evaluation.
    /// </summary>
    [JsonPropertyName("context")]
    public object? Context { get; set; }

    /// <summary>
    /// Agent ID that delegated authority for this action.
    /// </summary>
    [JsonPropertyName("delegatedBy")]
    public string? DelegatedBy { get; set; }
}

/// <summary>
/// Result of a policy evaluation.
/// </summary>
public class PolicyDecision
{
    /// <summary>
    /// Whether the action is allowed.
    /// </summary>
    [JsonPropertyName("allowed")]
    public bool Allowed { get; set; }

    /// <summary>
    /// The action that was checked.
    /// </summary>
    [JsonPropertyName("action")]
    public string Action { get; set; } = string.Empty;

    /// <summary>
    /// The decision result: "allow" or "deny".
    /// </summary>
    [JsonPropertyName("decision")]
    public string Decision { get; set; } = "deny";

    /// <summary>
    /// The policy that produced this decision.
    /// </summary>
    [JsonPropertyName("policy")]
    public string? Policy { get; set; }

    /// <summary>
    /// The specific rule that matched.
    /// </summary>
    [JsonPropertyName("rule")]
    public string? Rule { get; set; }

    /// <summary>
    /// Human-readable reason for the decision.
    /// </summary>
    [JsonPropertyName("reason")]
    public string? Reason { get; set; }

    /// <summary>
    /// Trace ID for request correlation.
    /// </summary>
    [JsonPropertyName("traceId")]
    public string? TraceId { get; set; }

    /// <summary>
    /// Trust tier of the agent.
    /// </summary>
    [JsonPropertyName("trustTier")]
    public string? TrustTier { get; set; }
}

/// <summary>
/// Legacy permission result. Use <see cref="PolicyDecision"/> instead.
/// </summary>
[Obsolete("Use PolicyDecision instead")]
public class PermissionResult
{
    [JsonPropertyName("allowed")]
    public bool Allowed { get; set; }

    [JsonPropertyName("reason")]
    public string? Reason { get; set; }

    [JsonPropertyName("policy")]
    public string? Policy { get; set; }

    [JsonPropertyName("trustTier")]
    public string? TrustTier { get; set; }
}

/// <summary>
/// Audit log entry.
/// </summary>
public class AuditEntry
{
    /// <summary>
    /// Unique entry ID.
    /// </summary>
    [JsonPropertyName("id")]
    public string? Id { get; set; }

    /// <summary>
    /// Timestamp of the entry.
    /// </summary>
    [JsonPropertyName("timestamp")]
    public string? Timestamp { get; set; }

    /// <summary>
    /// Agent that performed the action.
    /// </summary>
    [JsonPropertyName("agentId")]
    public string AgentId { get; set; } = string.Empty;

    /// <summary>
    /// Action that was evaluated.
    /// </summary>
    [JsonPropertyName("action")]
    public string Action { get; set; } = string.Empty;

    /// <summary>
    /// Result of the action: "allow" or "deny".
    /// </summary>
    [JsonPropertyName("result")]
    public string Result { get; set; } = "allow";

    /// <summary>
    /// Optional resource identifier.
    /// </summary>
    [JsonPropertyName("resource")]
    public string? Resource { get; set; }

    /// <summary>
    /// Additional details about the action.
    /// </summary>
    [JsonPropertyName("details")]
    public object? Details { get; set; }

    /// <summary>
    /// Agent that delegated authority.
    /// </summary>
    [JsonPropertyName("delegatedBy")]
    public string? DelegatedBy { get; set; }

    /// <summary>
    /// Policy that was evaluated.
    /// </summary>
    [JsonPropertyName("policy")]
    public string? Policy { get; set; }
}

/// <summary>
/// Options for creating an agent.
/// </summary>
public class CreateAgentOptions
{
    /// <summary>
    /// Agent display name.
    /// </summary>
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Trust tier. Default: "verified".
    /// </summary>
    [JsonPropertyName("trustTier")]
    public string TrustTier { get; set; } = "verified";

    /// <summary>
    /// Tags to assign to the agent.
    /// </summary>
    [JsonPropertyName("tags")]
    public List<string> Tags { get; set; } = new();

    /// <summary>
    /// Description of the agent.
    /// </summary>
    [JsonPropertyName("description")]
    public string? Description { get; set; }
}

/// <summary>
/// Legacy agent registration class. Use <see cref="CreateAgentOptions"/> instead.
/// </summary>
[Obsolete("Use CreateAgentOptions instead")]
public class AgentRegistration
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("trustTier")]
    public string TrustTier { get; set; } = "sandboxed";

    [JsonPropertyName("description")]
    public string? Description { get; set; }
}

/// <summary>
/// A MeshGuard agent identity.
/// </summary>
public class Agent
{
    /// <summary>
    /// Unique agent identifier.
    /// </summary>
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// Display name.
    /// </summary>
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Trust tier (e.g., "verified", "untrusted", "sandboxed").
    /// </summary>
    [JsonPropertyName("trustTier")]
    public string TrustTier { get; set; } = string.Empty;

    /// <summary>
    /// Tags associated with this agent.
    /// </summary>
    [JsonPropertyName("tags")]
    public List<string> Tags { get; set; } = new();

    /// <summary>
    /// Organization ID.
    /// </summary>
    [JsonPropertyName("orgId")]
    public string? OrgId { get; set; }

    /// <summary>
    /// Agent token (only returned on creation).
    /// </summary>
    [JsonPropertyName("token")]
    public string? Token { get; set; }
}

/// <summary>
/// Legacy agent info class. Use <see cref="Agent"/> instead.
/// </summary>
[Obsolete("Use Agent instead")]
public class AgentInfo
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("token")]
    public string? Token { get; set; }

    [JsonPropertyName("trustTier")]
    public string TrustTier { get; set; } = string.Empty;
}

/// <summary>
/// Gateway health status.
/// </summary>
public class HealthStatus
{
    /// <summary>
    /// Health status: "healthy" or other.
    /// </summary>
    [JsonPropertyName("status")]
    public string Status { get; set; } = "unknown";

    /// <summary>
    /// Gateway version.
    /// </summary>
    [JsonPropertyName("version")]
    public string? Version { get; set; }

    /// <summary>
    /// Gateway mode.
    /// </summary>
    [JsonPropertyName("mode")]
    public string? Mode { get; set; }
}

/// <summary>
/// A policy definition.
/// </summary>
public class Policy
{
    /// <summary>
    /// Unique policy ID.
    /// </summary>
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// Policy name.
    /// </summary>
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Policy description.
    /// </summary>
    [JsonPropertyName("description")]
    public string? Description { get; set; }

    /// <summary>
    /// Whether the policy is active.
    /// </summary>
    [JsonPropertyName("active")]
    public bool Active { get; set; } = true;

    /// <summary>
    /// Policy rules (raw JSON).
    /// </summary>
    [JsonPropertyName("rules")]
    public object? Rules { get; set; }
}

/// <summary>
/// Options for querying the audit log.
/// </summary>
public class AuditLogOptions
{
    /// <summary>
    /// Maximum number of entries to return. Default: 50.
    /// </summary>
    public int Limit { get; set; } = 50;

    /// <summary>
    /// Filter by decision ("allow" or "deny").
    /// </summary>
    public string? Decision { get; set; }

    /// <summary>
    /// Filter by agent ID.
    /// </summary>
    public string? AgentId { get; set; }

    /// <summary>
    /// Filter by action.
    /// </summary>
    public string? Action { get; set; }
}
