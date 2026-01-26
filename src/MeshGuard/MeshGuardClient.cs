using System.Net.Http.Json;
using System.Text.Json;

namespace MeshGuard;

/// <summary>
/// MeshGuard governance client — check permissions, log audit events, manage agents.
/// </summary>
public class MeshGuardClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly MeshGuardOptions _options;

    public MeshGuardClient(MeshGuardOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _http = new HttpClient
        {
            BaseAddress = new Uri(options.GatewayUrl.TrimEnd('/')),
            Timeout = TimeSpan.FromSeconds(options.TimeoutSeconds)
        };
        _http.DefaultRequestHeaders.Add("X-API-Key", options.ApiKey);
    }

    /// <summary>
    /// Check if an action is allowed by the governance policy.
    /// </summary>
    public async Task<PermissionResult> CheckPermissionAsync(
        PermissionRequest request, 
        CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/proxy/check", request, ct);
        
        if (!response.IsSuccessStatusCode)
        {
            var error = await response.Content.ReadAsStringAsync(ct);
            return new PermissionResult 
            { 
                Allowed = false, 
                Reason = $"Gateway error: {response.StatusCode} — {error}" 
            };
        }

        return await response.Content.ReadFromJsonAsync<PermissionResult>(ct) 
            ?? new PermissionResult { Allowed = false, Reason = "Empty response" };
    }

    /// <summary>
    /// Enforce permission — throws MeshGuardDeniedException if denied.
    /// </summary>
    public async Task EnforceAsync(PermissionRequest request, CancellationToken ct = default)
    {
        var result = await CheckPermissionAsync(request, ct);
        if (!result.Allowed)
        {
            throw new MeshGuardDeniedException(result.Reason, request);
        }
    }

    /// <summary>
    /// Log an audit entry.
    /// </summary>
    public async Task LogAuditAsync(AuditEntry entry, CancellationToken ct = default)
    {
        await _http.PostAsJsonAsync("/proxy/audit", entry, ct);
    }

    /// <summary>
    /// Register an agent with the gateway.
    /// </summary>
    public async Task<AgentInfo> RegisterAgentAsync(
        AgentRegistration registration, 
        CancellationToken ct = default)
    {
        var response = await _http.PostAsJsonAsync("/admin/agents", registration, ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<AgentInfo>(ct)
            ?? throw new InvalidOperationException("Failed to register agent");
    }

    /// <summary>
    /// Get gateway health status.
    /// </summary>
    public async Task<HealthStatus> GetHealthAsync(CancellationToken ct = default)
    {
        var response = await _http.GetFromJsonAsync<HealthStatus>("/health", ct);
        return response ?? new HealthStatus { Status = "unknown" };
    }

    public void Dispose() => _http.Dispose();
}
