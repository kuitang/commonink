# Subagent Note 09 - Security/Performance Audit Pass 2 (Delta)

## Security delta findings
- Consent persistence not wired in runtime path (high).
- Public note placeholder rendering in public endpoint (medium).
- Active OAuth middleware path lacks explicit audience enforcement layer (medium).
- MCP CORS wildcard with Authorization allowed (medium).

## Performance delta findings
- MCP server rebuilt per request (high).
- DEK/key lookup path repeated on every authenticated request (medium).
- Unbounded user DB connection cache (medium).
- Synchronous publish S3 upload on request path (medium).

## Consolidation output generated
- `docs/SECURITY_AUDIT.md`
- `docs/PERFORMANCE_AUDIT.md`
