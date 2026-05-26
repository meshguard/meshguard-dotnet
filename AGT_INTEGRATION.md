# Using AGT With meshguard-dotnet

MeshGuard supports direct .NET SDK governance, Semantic Kernel filters, and AGT-native governance in the same control plane. AGT is an additional policy enforcement path for teams that use Microsoft Agent Governance Toolkit in part of their fleet.

## Direct .NET SDK Pattern

```csharp
var result = await client.CheckPermissionAsync(new PermissionRequest
{
    AgentId = "customer-support-bot",
    Action = "send:email",
    Resource = "customer-emails"
});
```

## Semantic Kernel Pattern

```csharp
builder.Services.AddMeshGuardGovernance(options =>
{
    options.GatewayUrl = "https://dashboard.meshguard.app";
    options.ApiKey = Environment.GetEnvironmentVariable("MESHGUARD_API_KEY")!;
    options.AgentId = "copilot-assistant";
});
```

## AGT-Compatible Path

1. Keep existing `MeshGuardClient` and Semantic Kernel filters in place.
2. Add AGT instrumentation where it fits a new or existing Microsoft-agent workflow.
3. Use AGT-compatible policy YAML when you want shared policy files across .NET SDK, Semantic Kernel, and AGT paths.
4. Point all paths at the same MeshGuard PDP, audit log, and operator console.
5. Choose the enforcement path per agent, framework, and deployment architecture.
