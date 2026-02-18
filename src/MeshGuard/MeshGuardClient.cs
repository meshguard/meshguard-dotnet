using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace MeshGuard;

/// <summary>
/// Client for the MeshGuard governance gateway.
/// </summary>
/// <example>
/// <code>
/// var client = new MeshGuardClient(new MeshGuardOptions
/// {
///     GatewayUrl = "https://dashboard.meshguard.app",
///     AgentToken = Environment.GetEnvironmentVariable("MESHGUARD_AGENT_TOKEN"),
/// });
///
/// // Check if an action is allowed
/// var decision = await client.CheckAsync("read:contacts");
/// if (decision.Allowed)
/// {
///     // proceed
/// }
///
/// // Or enforce (throws on deny)
/// await client.EnforceAsync("read:contacts");
///
/// // Or govern a function
/// var result = await client.GovernAsync("read:contacts", async () =>
/// {
///     return await FetchContactsAsync();
/// });
/// </code>
/// </example>
public class MeshGuardClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly MeshGuardOptions _options;
    private readonly string _traceId;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
    };

    /// <summary>
    /// Creates a new MeshGuard client.
    /// </summary>
    /// <param name="options">Client configuration options.</param>
    public MeshGuardClient(MeshGuardOptions? options = null)
    {
        _options = options ?? new MeshGuardOptions();
        _traceId = _options.TraceId ?? Guid.NewGuid().ToString();
        
        _http = new HttpClient
        {
            BaseAddress = new Uri(_options.GatewayUrl.TrimEnd('/')),
            Timeout = TimeSpan.FromSeconds(_options.TimeoutSeconds)
        };
    }

    /// <summary>
    /// The trace ID used for request correlation.
    /// </summary>
    public string TraceId => _traceId;

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    private void AddAuthHeaders(HttpRequestMessage request, bool useAdmin = false)
    {
        request.Headers.Add("X-MeshGuard-Trace-ID", _traceId);
        
        if (useAdmin)
        {
            if (string.IsNullOrEmpty(_options.AdminToken))
                throw new AuthenticationException("Admin token required for this operation", _traceId);
            request.Headers.Add("X-Admin-Token", _options.AdminToken);
        }
        else if (!string.IsNullOrEmpty(_options.AgentToken))
        {
            request.Headers.Authorization = 
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _options.AgentToken);
        }
    }

    private async Task<T> HandleResponseAsync<T>(
        HttpResponseMessage response, 
        CancellationToken ct)
    {
        var statusCode = (int)response.StatusCode;

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            throw new AuthenticationException("Invalid or expired token", _traceId);
        }

        if (response.StatusCode == HttpStatusCode.Forbidden)
        {
            var errorData = await TryReadJsonAsync<Dictionary<string, object?>>(response, ct);
            throw new PolicyDeniedException(
                action: errorData?.GetValueOrDefault("action")?.ToString() ?? "unknown",
                policy: errorData?.GetValueOrDefault("policy")?.ToString(),
                rule: errorData?.GetValueOrDefault("rule")?.ToString(),
                reason: errorData?.GetValueOrDefault("message")?.ToString() ?? "Access denied by policy",
                traceId: _traceId
            );
        }

        if (response.StatusCode == HttpStatusCode.TooManyRequests)
        {
            throw new RateLimitException(traceId: _traceId);
        }

        if (!response.IsSuccessStatusCode)
        {
            var text = await response.Content.ReadAsStringAsync(ct);
            throw new MeshGuardException($"Request failed: {statusCode} {text}", _traceId);
        }

        var result = await response.Content.ReadFromJsonAsync<T>(JsonOptions, ct);
        return result ?? throw new MeshGuardException("Empty response from gateway", _traceId);
    }

    private async Task HandleResponseAsync(HttpResponseMessage response, CancellationToken ct)
    {
        var statusCode = (int)response.StatusCode;

        if (response.StatusCode == HttpStatusCode.Unauthorized)
            throw new AuthenticationException("Invalid or expired token", _traceId);

        if (response.StatusCode == HttpStatusCode.Forbidden)
        {
            var errorData = await TryReadJsonAsync<Dictionary<string, object?>>(response, ct);
            throw new PolicyDeniedException(
                action: errorData?.GetValueOrDefault("action")?.ToString() ?? "unknown",
                policy: errorData?.GetValueOrDefault("policy")?.ToString(),
                rule: errorData?.GetValueOrDefault("rule")?.ToString(),
                reason: errorData?.GetValueOrDefault("message")?.ToString() ?? "Access denied by policy",
                traceId: _traceId
            );
        }

        if (response.StatusCode == HttpStatusCode.TooManyRequests)
            throw new RateLimitException(traceId: _traceId);

        if (!response.IsSuccessStatusCode)
        {
            var text = await response.Content.ReadAsStringAsync(ct);
            throw new MeshGuardException($"Request failed: {statusCode} {text}", _traceId);
        }
    }

    private async Task<T?> TryReadJsonAsync<T>(HttpResponseMessage response, CancellationToken ct)
        where T : class
    {
        try
        {
            return await response.Content.ReadFromJsonAsync<T>(JsonOptions, ct);
        }
        catch
        {
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Core Governance
    // -------------------------------------------------------------------------

    /// <summary>
    /// Check if an action is allowed by policy.
    /// Returns a <see cref="PolicyDecision"/> — never throws on deny.
    /// </summary>
    /// <param name="action">Action to check (e.g., "read:contacts", "write:email").</param>
    /// <param name="resource">Optional resource identifier.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Policy decision with allowed status and details.</returns>
    public async Task<PolicyDecision> CheckAsync(
        string action, 
        string? resource = null, 
        CancellationToken ct = default)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/proxy/check");
        AddAuthHeaders(request);
        request.Headers.Add("X-MeshGuard-Action", action);
        if (resource is not null)
            request.Headers.Add("X-MeshGuard-Resource", resource);

        try
        {
            var response = await _http.SendAsync(request, ct);

            if (response.StatusCode == HttpStatusCode.Forbidden)
            {
                var errorData = await TryReadJsonAsync<Dictionary<string, object?>>(response, ct);
                return new PolicyDecision
                {
                    Allowed = false,
                    Action = action,
                    Decision = "deny",
                    Policy = errorData?.GetValueOrDefault("policy")?.ToString(),
                    Rule = errorData?.GetValueOrDefault("rule")?.ToString(),
                    Reason = errorData?.GetValueOrDefault("message")?.ToString(),
                    TraceId = _traceId,
                };
            }

            var data = await HandleResponseAsync<Dictionary<string, object?>>(response, ct);
            return new PolicyDecision
            {
                Allowed = true,
                Action = action,
                Decision = "allow",
                Policy = data.GetValueOrDefault("policy")?.ToString(),
                TraceId = _traceId,
            };
        }
        catch (PolicyDeniedException ex)
        {
            return new PolicyDecision
            {
                Allowed = false,
                Action = action,
                Decision = "deny",
                Policy = ex.Policy,
                Rule = ex.Rule,
                Reason = ex.Reason,
                TraceId = _traceId,
            };
        }
    }

    /// <summary>
    /// Enforce policy — throws <see cref="PolicyDeniedException"/> if the action is denied.
    /// </summary>
    /// <param name="action">Action to check.</param>
    /// <param name="resource">Optional resource identifier.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Policy decision if allowed.</returns>
    /// <exception cref="PolicyDeniedException">Thrown if action is denied.</exception>
    public async Task<PolicyDecision> EnforceAsync(
        string action, 
        string? resource = null, 
        CancellationToken ct = default)
    {
        var decision = await CheckAsync(action, resource, ct);
        if (!decision.Allowed)
        {
            throw new PolicyDeniedException(
                action: action,
                policy: decision.Policy,
                rule: decision.Rule,
                reason: decision.Reason,
                traceId: _traceId
            );
        }
        return decision;
    }

    /// <summary>
    /// Execute a function only if the action is allowed by policy.
    /// </summary>
    /// <typeparam name="T">Return type of the function.</typeparam>
    /// <param name="action">Action to check.</param>
    /// <param name="fn">Function to execute if allowed.</param>
    /// <param name="resource">Optional resource identifier.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Result of the function.</returns>
    /// <exception cref="PolicyDeniedException">Thrown if action is denied.</exception>
    /// <example>
    /// <code>
    /// var contacts = await client.GovernAsync("read:contacts", async () =>
    /// {
    ///     return await db.Contacts.ToListAsync();
    /// });
    /// </code>
    /// </example>
    public async Task<T> GovernAsync<T>(
        string action,
        Func<Task<T>> fn,
        string? resource = null,
        CancellationToken ct = default)
    {
        await EnforceAsync(action, resource, ct);
        return await fn();
    }

    /// <summary>
    /// Execute an action only if allowed by policy.
    /// </summary>
    /// <param name="action">Action to check.</param>
    /// <param name="fn">Action to execute if allowed.</param>
    /// <param name="resource">Optional resource identifier.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="PolicyDeniedException">Thrown if action is denied.</exception>
    public async Task GovernAsync(
        string action,
        Func<Task> fn,
        string? resource = null,
        CancellationToken ct = default)
    {
        await EnforceAsync(action, resource, ct);
        await fn();
    }

    // -------------------------------------------------------------------------
    // Legacy Permission Check (backward compatible)
    // -------------------------------------------------------------------------

    /// <summary>
    /// Check if an action is allowed by the governance policy.
    /// </summary>
    /// <param name="request">Permission request details.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Permission result.</returns>
    [Obsolete("Use CheckAsync(action, resource) instead")]
    public async Task<PermissionResult> CheckPermissionAsync(
        PermissionRequest request, 
        CancellationToken ct = default)
    {
        var decision = await CheckAsync(request.Action, request.Resource, ct);
#pragma warning disable CS0618
        return new PermissionResult
        {
            Allowed = decision.Allowed,
            Reason = decision.Reason,
            Policy = decision.Policy,
            TrustTier = decision.TrustTier,
        };
#pragma warning restore CS0618
    }

    /// <summary>
    /// Enforce permission — throws MeshGuardDeniedException if denied.
    /// </summary>
    [Obsolete("Use EnforceAsync(action, resource) instead")]
    public async Task EnforceAsync(PermissionRequest request, CancellationToken ct = default)
    {
#pragma warning disable CS0618
        var result = await CheckPermissionAsync(request, ct);
        if (!result.Allowed)
        {
            throw new MeshGuardDeniedException(result.Reason, request);
        }
#pragma warning restore CS0618
    }

    // -------------------------------------------------------------------------
    // Proxy Requests
    // -------------------------------------------------------------------------

    /// <summary>
    /// Make a governed request through the MeshGuard proxy.
    /// </summary>
    /// <param name="method">HTTP method.</param>
    /// <param name="path">Path to proxy (appended to /proxy/).</param>
    /// <param name="action">MeshGuard action for policy evaluation.</param>
    /// <param name="content">Optional request content.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>HTTP response.</returns>
    public async Task<HttpResponseMessage> RequestAsync(
        HttpMethod method,
        string path,
        string action,
        HttpContent? content = null,
        CancellationToken ct = default)
    {
        var normalizedPath = path.TrimStart('/');
        var request = new HttpRequestMessage(method, $"/proxy/{normalizedPath}")
        {
            Content = content
        };
        AddAuthHeaders(request);
        request.Headers.Add("X-MeshGuard-Action", action);

        var response = await _http.SendAsync(request, ct);
        await HandleResponseAsync(response, ct);
        return response;
    }

    /// <summary>
    /// GET request through the governance proxy.
    /// </summary>
    public Task<HttpResponseMessage> GetAsync(
        string path, 
        string action, 
        CancellationToken ct = default)
        => RequestAsync(HttpMethod.Get, path, action, null, ct);

    /// <summary>
    /// POST request through the governance proxy.
    /// </summary>
    public Task<HttpResponseMessage> PostAsync(
        string path, 
        string action, 
        HttpContent? content = null, 
        CancellationToken ct = default)
        => RequestAsync(HttpMethod.Post, path, action, content, ct);

    /// <summary>
    /// POST JSON request through the governance proxy.
    /// </summary>
    public Task<HttpResponseMessage> PostJsonAsync<T>(
        string path, 
        string action, 
        T body, 
        CancellationToken ct = default)
        => RequestAsync(HttpMethod.Post, path, action, JsonContent.Create(body, options: JsonOptions), ct);

    /// <summary>
    /// PUT request through the governance proxy.
    /// </summary>
    public Task<HttpResponseMessage> PutAsync(
        string path, 
        string action, 
        HttpContent? content = null, 
        CancellationToken ct = default)
        => RequestAsync(HttpMethod.Put, path, action, content, ct);

    /// <summary>
    /// PUT JSON request through the governance proxy.
    /// </summary>
    public Task<HttpResponseMessage> PutJsonAsync<T>(
        string path, 
        string action, 
        T body, 
        CancellationToken ct = default)
        => RequestAsync(HttpMethod.Put, path, action, JsonContent.Create(body, options: JsonOptions), ct);

    /// <summary>
    /// DELETE request through the governance proxy.
    /// </summary>
    public Task<HttpResponseMessage> DeleteAsync(
        string path, 
        string action, 
        CancellationToken ct = default)
        => RequestAsync(HttpMethod.Delete, path, action, null, ct);

    // -------------------------------------------------------------------------
    // Health & Info
    // -------------------------------------------------------------------------

    /// <summary>
    /// Check gateway health status.
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Health status.</returns>
    public async Task<HealthStatus> GetHealthAsync(CancellationToken ct = default)
    {
        var response = await _http.GetAsync("/health", ct);
        return await response.Content.ReadFromJsonAsync<HealthStatus>(JsonOptions, ct)
            ?? new HealthStatus { Status = "unknown" };
    }

    /// <summary>
    /// Quick boolean health check.
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>True if gateway is healthy.</returns>
    public async Task<bool> IsHealthyAsync(CancellationToken ct = default)
    {
        try
        {
            var health = await GetHealthAsync(ct);
            return health.Status == "healthy";
        }
        catch
        {
            return false;
        }
    }

    // -------------------------------------------------------------------------
    // Audit Logging
    // -------------------------------------------------------------------------

    /// <summary>
    /// Log an audit entry.
    /// </summary>
    /// <param name="entry">Audit entry to log.</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task LogAuditAsync(AuditEntry entry, CancellationToken ct = default)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/proxy/audit")
        {
            Content = JsonContent.Create(entry, options: JsonOptions)
        };
        AddAuthHeaders(request);
        await _http.SendAsync(request, ct);
    }

    /// <summary>
    /// Get audit log entries (requires admin token).
    /// </summary>
    /// <param name="options">Query options.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>List of audit entries.</returns>
    public async Task<List<AuditEntry>> GetAuditLogAsync(
        AuditLogOptions? options = null, 
        CancellationToken ct = default)
    {
        options ??= new AuditLogOptions();
        
        var queryParams = new List<string> { $"limit={options.Limit}" };
        if (options.Decision is not null)
            queryParams.Add($"decision={Uri.EscapeDataString(options.Decision)}");
        if (options.AgentId is not null)
            queryParams.Add($"agentId={Uri.EscapeDataString(options.AgentId)}");
        if (options.Action is not null)
            queryParams.Add($"action={Uri.EscapeDataString(options.Action)}");

        var query = string.Join("&", queryParams);
        var request = new HttpRequestMessage(HttpMethod.Get, $"/admin/audit?{query}");
        AddAuthHeaders(request, useAdmin: true);

        var response = await _http.SendAsync(request, ct);
        var data = await HandleResponseAsync<AuditLogResponse>(response, ct);
        return data.Entries;
    }

    // -------------------------------------------------------------------------
    // Admin: Agents
    // -------------------------------------------------------------------------

    /// <summary>
    /// List all agents (requires admin token).
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>List of agents.</returns>
    public async Task<List<Agent>> ListAgentsAsync(CancellationToken ct = default)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/admin/agents");
        AddAuthHeaders(request, useAdmin: true);

        var response = await _http.SendAsync(request, ct);
        var data = await HandleResponseAsync<AgentsResponse>(response, ct);
        return data.Agents;
    }

    /// <summary>
    /// Create a new agent (requires admin token).
    /// </summary>
    /// <param name="options">Agent creation options.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Created agent with token.</returns>
    public async Task<Agent> CreateAgentAsync(
        CreateAgentOptions options, 
        CancellationToken ct = default)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/admin/agents")
        {
            Content = JsonContent.Create(options, options: JsonOptions)
        };
        AddAuthHeaders(request, useAdmin: true);

        var response = await _http.SendAsync(request, ct);
        return await HandleResponseAsync<Agent>(response, ct);
    }

    /// <summary>
    /// Register an agent with the gateway.
    /// </summary>
    [Obsolete("Use CreateAgentAsync instead")]
    public async Task<AgentInfo> RegisterAgentAsync(
        AgentRegistration registration, 
        CancellationToken ct = default)
    {
#pragma warning disable CS0618
        var agent = await CreateAgentAsync(new CreateAgentOptions
        {
            Name = registration.Name,
            TrustTier = registration.TrustTier,
            Description = registration.Description,
        }, ct);

        return new AgentInfo
        {
            Id = agent.Id,
            Name = agent.Name,
            Token = agent.Token,
            TrustTier = agent.TrustTier,
        };
#pragma warning restore CS0618
    }

    /// <summary>
    /// Update an existing agent (requires admin token).
    /// </summary>
    /// <param name="agentId">Agent ID to update.</param>
    /// <param name="updates">Fields to update.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Updated agent.</returns>
    public async Task<Agent> UpdateAgentAsync(
        string agentId,
        CreateAgentOptions updates,
        CancellationToken ct = default)
    {
        var request = new HttpRequestMessage(HttpMethod.Put, $"/admin/agents/{Uri.EscapeDataString(agentId)}")
        {
            Content = JsonContent.Create(updates, options: JsonOptions)
        };
        AddAuthHeaders(request, useAdmin: true);

        var response = await _http.SendAsync(request, ct);
        return await HandleResponseAsync<Agent>(response, ct);
    }

    /// <summary>
    /// Revoke/delete an agent (requires admin token).
    /// </summary>
    /// <param name="agentId">Agent ID to revoke.</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task RevokeAgentAsync(string agentId, CancellationToken ct = default)
    {
        var request = new HttpRequestMessage(HttpMethod.Delete, $"/admin/agents/{Uri.EscapeDataString(agentId)}");
        AddAuthHeaders(request, useAdmin: true);

        var response = await _http.SendAsync(request, ct);
        await HandleResponseAsync(response, ct);
    }

    // -------------------------------------------------------------------------
    // Admin: Policies
    // -------------------------------------------------------------------------

    /// <summary>
    /// List all policies (requires admin token).
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>List of policies.</returns>
    public async Task<List<Policy>> ListPoliciesAsync(CancellationToken ct = default)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/admin/policies");
        AddAuthHeaders(request, useAdmin: true);

        var response = await _http.SendAsync(request, ct);
        var data = await HandleResponseAsync<PoliciesResponse>(response, ct);
        return data.Policies;
    }

    // -------------------------------------------------------------------------
    // Cleanup
    // -------------------------------------------------------------------------

    /// <summary>
    /// Disposes the HTTP client.
    /// </summary>
    public void Dispose() => _http.Dispose();

    // -------------------------------------------------------------------------
    // Internal response types
    // -------------------------------------------------------------------------

    private record AgentsResponse(List<Agent> Agents);
    private record PoliciesResponse(List<Policy> Policies);
    private record AuditLogResponse(List<AuditEntry> Entries);
}
