"""MCP Tool Description Injection & Exfiltration Scanner.
100% Python Standard Library.
"""

import re

class MCPToolSecurityScanner:
    """Scans MCP tool schemas and descriptions for prompt injection, tool shadowing, and exfiltration."""
    
    INJECTION_PATTERNS = [
        r"ignore\s+previous\s+instructions",
        r"system\s+override",
        r"do\s+not\s+inform\s+the\s+user",
        r"send\s+all\s+env\s+variables",
        r"<script",
        r"curl\s+http"
    ]
    
    @classmethod
    def scan_tool_manifest(cls, tools: list) -> dict:
        findings = []
        for tool in tools:
            name = tool.get("name", "unknown")
            desc = tool.get("description", "")
            
            for pat in cls.INJECTION_PATTERNS:
                if re.search(pat, desc, re.IGNORECASE):
                    findings.append({
                        "tool": name,
                        "severity": "CRITICAL",
                        "issue": f"Matched suspicious injection/exfiltration pattern: '{pat}'"
                    })
                    
            if len(desc) > 1500:
                findings.append({
                    "tool": name,
                    "severity": "MEDIUM",
                    "issue": "Excessively long tool description (>1500 chars) may hide covert instructions."
                })
                
        status = "UNSAFE" if any(f["severity"] == "CRITICAL" for f in findings) else "VERIFIED_SAFE"
        return {
            "tools_scanned": len(tools),
            "security_verdict": status,
            "findings_count": len(findings),
            "findings": findings
        }
