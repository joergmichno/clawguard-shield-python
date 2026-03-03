"""
ClawGuard Shield — Python SDK

Scan text for prompt injections, data exfiltration, and social engineering
with a single function call.

Usage:
    from clawguard_shield import Shield

    shield = Shield("cgs_your_api_key")
    result = shield.scan("Ignore all previous instructions")

    if not result.clean:
        print(f"Threat detected! Risk: {result.risk_score}/10")
        for finding in result.findings:
            print(f"  - {finding.pattern_name} ({finding.severity})")
"""

from clawguard_shield.client import Shield, ShieldError, ScanResult, Finding

__version__ = "0.1.0"
__all__ = ["Shield", "ShieldError", "ScanResult", "Finding", "__version__"]
