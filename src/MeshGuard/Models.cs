using System.Text.Json.Serialization;

namespace MeshGuard;

public class MeshGuardOptions
{
    public string GatewayUrl { get; set; } = "https://dashboard.meshguard.app";
    public string ApiKey { get; set; } = string.Empty;
    public int TimeoutSeconds { get; set; } = 30;
}

public class PermissionRequest
{
    [JsonPropertyName("agentId")]
    public string AgentId { get; set; } = string.Empty;

    [JsonPropertyName("action")]
    public string Action { get; set; } = string.Empty;

    [JsonPropertyName("resource")]
    public string? Resource { get; set; }

    [JsonPropertyName("context")]
    public object? Context { get; set; }

    [JsonPropertyName("delegatedBy")]
    public string? DelegatedBy { get; set; }
}

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

public class AuditEntry
{
    [JsonPropertyName("agentId")]
    public string AgentId { get; set; } = string.Empty;

    [JsonPropertyName("action")]
    public string Action { get; set; } = string.Empty;

    [JsonPropertyName("result")]
    public string Result { get; set; } = "allow";

    [JsonPropertyName("resource")]
    public string? Resource { get; set; }

    [JsonPropertyName("details")]
    public object? Details { get; set; }

    [JsonPropertyName("delegatedBy")]
    public string? DelegatedBy { get; set; }
}

public class AgentRegistration
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("trustTier")]
    public string TrustTier { get; set; } = "sandboxed";

    [JsonPropertyName("description")]
    public string? Description { get; set; }
}

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

public class HealthStatus
{
    [JsonPropertyName("status")]
    public string Status { get; set; } = "unknown";

    [JsonPropertyName("version")]
    public string? Version { get; set; }

    [JsonPropertyName("mode")]
    public string? Mode { get; set; }
}

public class MeshGuardDeniedException : Exception
{
    public PermissionRequest Request { get; }

    public MeshGuardDeniedException(string? reason, PermissionRequest request)
        : base($"MeshGuard denied: {reason ?? "no reason provided"}")
    {
        Request = request;
    }
}
