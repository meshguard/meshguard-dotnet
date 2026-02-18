using Microsoft.Extensions.DependencyInjection;
using Microsoft.SemanticKernel;

namespace MeshGuard.SemanticKernel;

/// <summary>
/// Extension methods for configuring MeshGuard governance with Semantic Kernel.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds MeshGuard governance to the Semantic Kernel service collection.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Configuration action.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <example>
    /// <code>
    /// var builder = Kernel.CreateBuilder();
    /// builder.AddOpenAIChatCompletion("gpt-4", apiKey);
    /// 
    /// builder.Services.AddMeshGuardGovernance(options =>
    /// {
    ///     options.GatewayUrl = "https://dashboard.meshguard.app";
    ///     options.AgentToken = Environment.GetEnvironmentVariable("MESHGUARD_AGENT_TOKEN")!;
    ///     options.AgentId = "copilot-assistant";
    ///     options.DefaultTrustTier = "verified";
    /// });
    /// 
    /// var kernel = builder.Build();
    /// </code>
    /// </example>
    public static IServiceCollection AddMeshGuardGovernance(
        this IServiceCollection services,
        Action<MeshGuardGovernanceOptions> configure)
    {
        var options = new MeshGuardGovernanceOptions();
        configure(options);

        // Register the MeshGuard client
        services.AddSingleton<MeshGuardClient>(sp =>
        {
            return new MeshGuardClient(new MeshGuardOptions
            {
                GatewayUrl = options.GatewayUrl,
                AgentToken = options.AgentToken,
                AdminToken = options.AdminToken,
                TimeoutSeconds = options.TimeoutSeconds,
            });
        });

        // Register the filter
        services.AddSingleton<IFunctionInvocationFilter>(sp =>
        {
            var client = sp.GetRequiredService<MeshGuardClient>();
            return new MeshGuardFilter(client, options.AgentId, new MeshGuardFilterOptions
            {
                ThrowOnDeny = options.ThrowOnDeny,
                AuditEnabled = options.AuditEnabled,
                ActionFormat = options.ActionFormat,
            });
        });

        return services;
    }

    /// <summary>
    /// Adds MeshGuard governance to the Kernel builder.
    /// </summary>
    /// <param name="builder">The kernel builder.</param>
    /// <param name="configure">Configuration action.</param>
    /// <returns>The kernel builder for chaining.</returns>
    public static IKernelBuilder AddMeshGuardGovernance(
        this IKernelBuilder builder,
        Action<MeshGuardGovernanceOptions> configure)
    {
        builder.Services.AddMeshGuardGovernance(configure);
        return builder;
    }
}

/// <summary>
/// Configuration options for MeshGuard governance with Semantic Kernel.
/// </summary>
public class MeshGuardGovernanceOptions
{
    /// <summary>
    /// MeshGuard gateway URL. Required.
    /// </summary>
    public string GatewayUrl { get; set; } = "https://dashboard.meshguard.app";

    /// <summary>
    /// Agent JWT token for policy checks. Required.
    /// </summary>
    public string AgentToken { get; set; } = string.Empty;

    /// <summary>
    /// Admin token for management operations. Optional.
    /// </summary>
    public string? AdminToken { get; set; }

    /// <summary>
    /// Agent ID to use for policy checks and audit logging. Required.
    /// </summary>
    public string AgentId { get; set; } = string.Empty;

    /// <summary>
    /// Default trust tier for the agent. Used in policy evaluation context.
    /// </summary>
    public string DefaultTrustTier { get; set; } = "verified";

    /// <summary>
    /// Request timeout in seconds. Default: 30.
    /// </summary>
    public int TimeoutSeconds { get; set; } = 30;

    /// <summary>
    /// Whether to throw exceptions on policy denial. Default: true.
    /// </summary>
    public bool ThrowOnDeny { get; set; } = true;

    /// <summary>
    /// Whether to log audit entries. Default: true.
    /// </summary>
    public bool AuditEnabled { get; set; } = true;

    /// <summary>
    /// Action format string. Default: "invoke:{plugin}.{function}".
    /// </summary>
    public string ActionFormat { get; set; } = "invoke:{plugin}.{function}";
}
