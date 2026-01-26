using Microsoft.SemanticKernel;
using MeshGuard;

namespace MeshGuard.SemanticKernel;

/// <summary>
/// Semantic Kernel function invocation filter that enforces MeshGuard governance policies.
/// Every function call is checked against MeshGuard before execution and audit-logged after.
/// </summary>
public class MeshGuardFilter : IFunctionInvocationFilter
{
    private readonly MeshGuardClient _client;
    private readonly MeshGuardGovernanceOptions _options;

    public MeshGuardFilter(MeshGuardClient client, MeshGuardGovernanceOptions options)
    {
        _client = client;
        _options = options;
    }

    public async Task OnFunctionInvocationAsync(
        FunctionInvocationContext context,
        Func<FunctionInvocationContext, Task> next)
    {
        var action = $"invoke:{context.Function.PluginName}.{context.Function.Name}";
        var resource = context.Function.PluginName;

        // Check permission before execution
        var request = new PermissionRequest
        {
            AgentId = _options.AgentId,
            Action = action,
            Resource = resource,
            Context = new
            {
                plugin = context.Function.PluginName,
                function_name = context.Function.Name,
                arguments = context.Arguments?.ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value?.ToString()
                ),
                trust_tier = _options.DefaultTrustTier,
            }
        };

        var result = await _client.CheckPermissionAsync(request);

        if (!result.Allowed)
        {
            // Log the denial
            await _client.LogAuditAsync(new AuditEntry
            {
                AgentId = _options.AgentId,
                Action = action,
                Resource = resource,
                Result = "deny",
                Details = new { reason = result.Reason, policy = result.Policy }
            });

            if (_options.ThrowOnDenied)
            {
                throw new MeshGuardDeniedException(result.Reason, request);
            }

            // Skip function execution
            return;
        }

        // Execute the function
        await next(context);

        // Audit log the allowed action
        await _client.LogAuditAsync(new AuditEntry
        {
            AgentId = _options.AgentId,
            Action = action,
            Resource = resource,
            Result = "allow",
            Details = new
            {
                plugin = context.Function.PluginName,
                function_name = context.Function.Name,
            }
        });
    }
}
