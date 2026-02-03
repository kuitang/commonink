# About common.ink

**Secure notes for AI agents and humans.**

## What is common.ink?

common.ink is a note-taking service designed from the ground up to work seamlessly with AI agents while maintaining strong security and privacy guarantees for human users.

## Key Features

### End-to-End Encryption
Every user gets their own isolated SQLCipher database with AES-256-GCM encryption. Your notes are encrypted at rest and protected by envelope encryption with rotating keys.

### MCP Integration
Native support for the [Model Context Protocol](https://modelcontextprotocol.io) allows AI assistants like Claude to securely read, write, and manage your notes with your explicit permission.

### OAuth 2.1 Provider
Full OAuth 2.1 compliance with Dynamic Client Registration (DCR) means any compatible AI agent or application can integrate with common.ink securely.

### Public Note Sharing
Share individual notes publicly via unique URLs while keeping the rest of your notes private.

### Full-Text Search
Powered by SQLite FTS5, search across all your notes instantly.

## For Developers

common.ink provides:
- **REST API** for programmatic note management
- **MCP Endpoint** for AI agent integration
- **Personal Access Tokens** for CLI and automation
- **OAuth 2.1** for third-party app integration

See our [API Documentation](/docs/api) for details.

## Architecture

- **Go 1.25** backend with standard library HTTP server
- **SQLCipher** for encrypted per-user databases
- **Tailwind CSS** for responsive UI
- **Tigris** S3-compatible storage for public notes
- **Fly.io** for global edge deployment

## Open Source

common.ink is built with open-source technologies and follows security best practices:
- No tracking pixels or third-party analytics
- Minimal JavaScript (no frameworks)
- WCAG 2.1 accessible design

## Contact

- **Support:** support@common.ink
- **Security:** security@common.ink
- **General:** hello@common.ink
