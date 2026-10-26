---
"ssh-mcp": patch
---

Raise the MCP HTTP session limit to 512 and evict the least recently used idle session under capacity pressure. Preserve in-flight requests and count pending initializations against the limit. Expose session counts and reclamation counters on the authenticated status endpoint.
