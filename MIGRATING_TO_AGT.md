# Migrating From meshguard-dotnet To AGT + MeshGuard

The .NET SDK and Semantic Kernel filter remain supported for existing customers. New Microsoft-aligned agent governance should evaluate AGT as the in-process policy enforcement point and MeshGuard as the fleet control plane.

## Recommended Path

1. Keep existing `MeshGuardClient` and Semantic Kernel filters in place.
2. Convert policies to AGT-compatible YAML.
3. Configure MeshGuard PDP/audit for the same tenant.
4. Compare decisions in audit export before moving production traffic.

