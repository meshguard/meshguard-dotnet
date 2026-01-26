# MeshGuard .NET SDK

The official .NET SDK for [MeshGuard](https://meshguard.app) — the governance control plane for AI agents.

Includes first-class support for **Microsoft Semantic Kernel**.

[![NuGet](https://img.shields.io/nuget/v/MeshGuard.svg)](https://www.nuget.org/packages/MeshGuard)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Installation

```bash
dotnet add package MeshGuard
dotnet add package MeshGuard.SemanticKernel
```

## Quick Start

```csharp
using MeshGuard;

var client = new MeshGuardClient(new MeshGuardOptions
{
    GatewayUrl = "https://dashboard.meshguard.app",
    ApiKey = Environment.GetEnvironmentVariable("MESHGUARD_API_KEY")!
});

// Check if an action is allowed
var result = await client.CheckPermissionAsync(new PermissionRequest
{
    AgentId = "customer-support-bot",
    Action = "send:email",
    Resource = "customer-emails",
    Context = new { department = "support" }
});

if (result.Allowed)
{
    // Proceed with the action
    await SendEmail(to, subject, body);
    
    // Log the action
    await client.LogAuditAsync(new AuditEntry
    {
        AgentId = "customer-support-bot",
        Action = "send:email",
        Result = "allow",
        Details = new { to, subject }
    });
}
```

## Semantic Kernel Integration

Add governance to any Semantic Kernel agent:

```csharp
using Microsoft.SemanticKernel;
using MeshGuard.SemanticKernel;

var builder = Kernel.CreateBuilder();
builder.AddOpenAIChatCompletion("gpt-4", apiKey);

// Add MeshGuard governance filter
builder.Services.AddMeshGuardGovernance(options =>
{
    options.GatewayUrl = "https://dashboard.meshguard.app";
    options.ApiKey = Environment.GetEnvironmentVariable("MESHGUARD_API_KEY")!;
    options.AgentId = "copilot-assistant";
    options.DefaultTrustTier = "verified";
});

var kernel = builder.Build();

// Every function call is now governed by MeshGuard policies
// Denied actions throw MeshGuardDeniedException
var result = await kernel.InvokePromptAsync("Send an email to the CEO about Q4 results");
```

### Semantic Kernel Filter

MeshGuard integrates via Semantic Kernel's [function invocation filter](https://learn.microsoft.com/en-us/semantic-kernel/concepts/enterprise-readiness/filters):

```csharp
public class MeshGuardFilter : IFunctionInvocationFilter
{
    private readonly MeshGuardClient _client;
    private readonly string _agentId;

    public async Task OnFunctionInvocationAsync(
        FunctionInvocationContext context, 
        Func<FunctionInvocationContext, Task> next)
    {
        // Check permission before execution
        var result = await _client.CheckPermissionAsync(new PermissionRequest
        {
            AgentId = _agentId,
            Action = $"invoke:{context.Function.PluginName}.{context.Function.Name}",
            Resource = context.Function.PluginName,
            Context = context.Arguments
        });

        if (!result.Allowed)
        {
            throw new MeshGuardDeniedException(result.Reason);
        }

        // Execute the function
        await next(context);

        // Audit log
        await _client.LogAuditAsync(new AuditEntry
        {
            AgentId = _agentId,
            Action = $"invoke:{context.Function.PluginName}.{context.Function.Name}",
            Result = "allow"
        });
    }
}
```

## Policy Example

```yaml
# policies/copilot-governance.yaml
name: copilot-governance
description: Governance policy for Microsoft Copilot agents
rules:
  - action: "invoke:EmailPlugin.*"
    effect: deny
    condition:
      trust_tier: { below: "trusted" }
    reason: "Email access requires trusted tier"

  - action: "invoke:FilePlugin.ReadFile"
    effect: deny
    condition:
      resource: { matches: "*/executive/*" }
      role: { not_in: ["executive", "admin"] }
    reason: "Executive files restricted"

  - action: "invoke:*"
    effect: allow
    rate_limit:
      max: 100
      window: "1m"
```

## Features

- ✅ **Policy Enforcement** — Check permissions before any agent action
- ✅ **Audit Logging** — Complete trail of every action
- ✅ **Semantic Kernel Filter** — Drop-in governance for SK agents
- ✅ **Delegation Chains** — Track who authorized what
- ✅ **Trust Tiers** — Granular agent classification
- ✅ **Rate Limiting** — Prevent runaway agents
- ✅ **Async/Await** — Fully asynchronous API
- ✅ **.NET 8+** — Modern .NET support

## Documentation

- [MeshGuard Docs](https://docs.meshguard.app)
- [Learning Center](https://learn.meshguard.app)
- [Governing Microsoft Copilot](https://learn.meshguard.app/guides/governing-microsoft-copilot)
- [API Reference](https://docs.meshguard.app/api/overview)

## License

MIT — see [LICENSE](LICENSE) for details.
