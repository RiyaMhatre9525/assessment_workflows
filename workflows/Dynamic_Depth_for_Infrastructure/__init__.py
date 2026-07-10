"""
Dynamic_Depth_for_Infrastructure workflow package.

Assesses infrastructure security maturity by collecting evidence from
SCM platforms (GitHub, Azure DevOps) and cloud providers (Azure).

Maturity model (fail-fast, 5 levels):
    Level 1 - Baseline (auto-pass, N/A)
    Level 2 - Exposed Services, Network Segmentation, Cloud Configuration
    Level 3 - Unauthorized Installation, Weak Password
    Level 4 - Load Testing
    Level 5 - Unused Resources

See README.md in this directory for the full API contract.
"""
