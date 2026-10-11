"""MCP server for MCP Tool Security Scanner."""
import sys
import json
from client import MCPToolSecurityScanner

def handle_request(req):
    method = req.get("method")
    if method == "tools/list":
        return {
            "tools": [{
                "name": "scan_mcp_tool_manifest",
                "description": "Audits MCP tool definitions for prompt injection and exfiltration risks",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "tools": {"type": "array"}
                    },
                    "required": ["tools"]
                }
            }]
        }
    elif method == "tools/call":
        params = req.get("params", {})
        if params.get("name") == "scan_mcp_tool_manifest":
            tools = params.get("arguments", {}).get("tools", [])
            res = MCPToolSecurityScanner.scan_tool_manifest(tools)
            return {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}
    return {"error": "Method not found"}

if __name__ == "__main__":
    for line in sys.stdin:
        if line.strip():
            print(json.dumps(handle_request(json.loads(line))))
            sys.stdout.flush()
