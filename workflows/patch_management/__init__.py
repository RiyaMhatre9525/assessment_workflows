"""
patch_management workflow package.

Assesses Patch Management maturity for a project by inspecting evidence
collected from SCM platforms (GitHub, Azure DevOps) and, where credentials
permit, cloud container registries (currently Azure).

Maturity model (fail-fast, 5 levels):
    Level 1 - Patch Policy, Automated Pull Requests
    Level 2 - Automated Merge, Nightly Base Image Builds,
              Reduction of Attack Surface, Maximum Lifetime of Images
    Level 3 - Automated Deployment
    Level 4 - Short Maximum Lifetime for Images
    Level 5 - Not Applicable (placeholder, always passes)

See README.md in this directory for the full API contract.
"""
