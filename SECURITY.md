# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in TESSERA, please report it responsibly.

**Do NOT:** Open a public GitHub issue for security vulnerabilities.

**DO:** Email security concerns privately to the maintainers.

We aim to acknowledge reports within 48 hours and provide a timeline for fixes.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | ✅ Current       |

Older versions may not be supported - please upgrade.

## Security Best Practices When Using TESSERA

1. **Local scanning only** - TESSERA scans local topology files; never expose scan endpoints publicly
2. **API keys** - Use strong API keys (16+ characters) for server endpoints
3. **Database** - The local SQLite database (`~/.tessera/scans.db`) contains scan metadata; protect accordingly
4. **Topology files** - Treat your topology YAML files as sensitive - they document your system's architecture

## Scope

TESSERA is a static analysis tool for topology graphs. It does NOT:
- Execute code from scanned systems
- Make network requests to target systems
- Store credentials remotely

## Credit

We appreciate responsible disclosure and will credit reporters in fixes (if desired).