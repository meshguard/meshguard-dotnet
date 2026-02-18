using Microsoft.SemanticKernel;

namespace MeshGuard.SemanticKernel;

/// <summary>
/// Semantic Kernel function invocation filter that enforces MeshGuard governance policies.
/// </summary>
/// <remarks>
/// This filter intercepts all function invocations in the Semantic Kernel and checks
/// them against MeshGuard policies before execution. If the action is denied,
/// a <see cref="PolicyDeniedException"/> is thrown.
/// </remarks>
/// <example>
/// <code>
/// // Add filter via dependency injection
/// builder.Services.AddMeshGuardGovernance(options =>
/// {
///     options.GatewayUrl = "https://dashboard.meshguard.app";
///     options.AgentToken = Environment.GetEnvironmentVariable("MESHGUARD_AGENT_TOKEN")!;
///     options.AgentId = "my-copilot-agent";
/// });
/// 
/// // Or add manually
/// kernel.FunctionInvocationFilters.Add(new MeshGuardFilter(client, "my-agent-id"));
/// </code>
/// </example>
public class MeshGuardFilter : IFunctionInvocationFilter
{
    private readonly MeshGuardClient _client;
    private readonly string _agentId;
    private readonly MeshGuardFilterOptions _filterOptions;

    /// <summary>
    /// Creates a new MeshGuard governance filter.
    /// </summary>
    /// <param name="client">MeshGuard client instance.</param>
    /// <param name="agentId">Agent ID to use for policy checks.</param>
    /// <param name="options">Optional filter configuration.</param>
    public MeshGuardFilter(
        MeshGuardClient client, 
        string agentId,
        MeshGuardFilterOptions? options = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _agentId = agentId ?? throw new ArgumentNullException(nameof(agentId));
        _filterOptions = options ?? new MeshGuardFilterOptions();
    }

    /// <summary>
    /// Invoked before and after a function is executed.
    /// </summary>
    public async Task OnFunctionInvocationAsync(
        FunctionInvocationContext context,
        Func<FunctionInvocationContext, Task> next)
    {
        var pluginName = context.Function.PluginName ?? "unknown";
        var functionName = context.Function.Name;
        var action = FormatAction(pluginName, functionName);

        // Check permission before execution
        var decision = await _client.CheckAsync(action);

        if (!decision.Allowed)
        {
            if (_filterOptions.ThrowOnDeny)
            {
                throw new PolicyDeniedException(
                    action: action,
                    policy: decision.Policy,
                    rule: decision.Rule,
                    reason: decision.Reason ?? "Function invocation denied by MeshGuard policy"
                );
            }
            
            // Skip execution if not throwing
            return;
        }

        // Execute the function
        await next(context);

        // Log audit entry if enabled
        if (_filterOptions.AuditEnabled)
        {
            await _client.LogAuditAsync(new AuditEntry
            {
                AgentId = _agentId,
                Action = action,
                Result = "allow",
                Resource = pluginName,
                Details = new
                {
                    function = functionName,
                    plugin = pluginName,
                    traceId = _client.TraceId,
                }
            });
        }
    }

    private string FormatAction(string pluginName, string functionName)
    {
        return _filterOptions.ActionFormat
            .Replace("{plugin}", pluginName)
            .Replace("{function}", functionName);
    }
}

/// <summary>
/// Configuration options for the MeshGuard Semantic Kernel filter.
/// </summary>
public class MeshGuardFilterOptions
{
    /// <summary>
    /// Whether to throw <see cref="PolicyDeniedException"/> when a function is denied.
    /// If false, the function is silently skipped. Default: true.
    /// </summary>
    public bool ThrowOnDeny { get; set; } = true;

    /// <summary>
    /// Whether to log audit entries for allowed function invocations.
    /// Default: true.
    /// </summary>
    public bool AuditEnabled { get; set; } = true;

    /// <summary>
    /// Format string for the action name. Supports {plugin} and {function} placeholders.
    /// Default: "invoke:{plugin}.{function}"
    /// </summary>
    public string ActionFormat { get; set; } = "invoke:{plugin}.{function}";
}
