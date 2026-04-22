# Sample pre-commit configuration for TESSERA
#
# Copy this to your project's .pre-commit-config.yaml
# Or add to existing configuration

repos:
  # TESSERA Security Scanner
  - repo: https://github.com/Devaretanmay/TESSERA
    rev: v2.0.0
    hooks:
      - id: tessera-scan
        name: TESSERA Security Scan
        description: Scan YAML topology files for security vulnerabilities
        types: [yaml]
        files: '\.yaml$'
        # Optional: fail on specific severities
        # args: ['--fail-on-severity', 'high']
        # Optional: specify output format
        # args: ['--format', 'sarif']
