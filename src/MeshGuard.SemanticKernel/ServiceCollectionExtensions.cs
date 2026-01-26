using Microsoft.Extensions.DependencyInjection;
using Microsoft.SemanticKernel;
using MeshGuard;

namespace MeshGuard.SemanticKernel;

/// <summary>
/// Extension methods for adding MeshGuard governance to Semantic Kernel.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Add MeshGuard governance to the Semantic Kernel pipeline.
    /// All function invocations will be checked against MeshGuard policies.
    /// </summary>
    public static IServiceCollection AddMeshGuardGovernance(
        this IServiceCollection services,
        Action<MeshGuardGovernanceOptions> configure)
    {
        var options = new MeshGuardGovernanceOptions();
        configure(options);

        var client = new MeshGuardClient(new MeshGuardOptions
        {
            GatewayUrl = options.GatewayUrl,
            ApiKey = options.ApiKey,
            TimeoutSeconds = options.TimeoutSeconds,
        });

        services.AddSingleton(client);
        services.AddSingleton(options);
        services.AddSingleton<IFunctionInvocationFilter>(
            sp => new MeshGuardFilter(client, options));

        return services;
    }
}

/// <summary>
/// Configuration options for MeshGuard governance in Semantic Kernel.
/// </summary>
public class MeshGuardGovernanceOptions
{
    /// <summary>MeshGuard gateway URL.</summary>
    public string GatewayUrl { get; set; } = "https://dashboard.meshguard.app";

    /// <summary>MeshGuard API key for authentication.</summary>
    public string ApiKey { get; set; } = string.Empty;

    /// <summary>Agent ID for audit logging and policy evaluation.</summary>
    public string AgentId { get; set; } = string.Empty;

    /// <summary>Default trust tier for this agent.</summary>
    public string DefaultTrustTier { get; set; } = "sandboxed";

    /// <summary>Whether to throw an exception when an action is denied.</summary>
    public bool ThrowOnDenied { get; set; } = true;

    /// <summary>HTTP timeout in seconds.</summary>
    public int TimeoutSeconds { get; set; } = 30;
}
