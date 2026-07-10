"""
Static_Depth_for_Infrastructure workflow package.

Assesses the Static Security Maturity of Infrastructure across 5 progressive
levels, by analyzing source code repositories (build artifacts, secrets,
Infrastructure-as-Code) and cloud infrastructure configuration through a
provider-adapter pattern.

Unlike the application-focused workflows in this backend, Level 1 here has
real controls to evaluate (no baseline "N/A" level) and Level 5 has no
defined checks — it always passes once every prior level has fully passed.

Reporting convention: `maturity_level` in the final result is the level the
workflow was evaluating when it stopped (whether that level itself passed or
failed) — matching this workflow's explicit spec: "Return the current
maturity level along with detailed findings."
"""
