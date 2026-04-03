# mcpaudit

Security scanner for MCP server Python code. Finds vulnerabilities before they reach production.

```bash
pip install mcpaudit
mcpaudit ./my-mcp-server
```

## What it finds

| Rule | CWE | Severity |
|------|-----|----------|
| Shell injection — user input to `subprocess`/`os.system` without sanitization | CWE-78 | high |
| Code injection — user input to `eval()`/`exec()` | CWE-95 | high |
| SQL injection — user input in raw `cursor.execute()` queries | CWE-89 | high |
| Path traversal — file operations without path boundary validation | CWE-22 | high/medium |
| SSRF — user input as HTTP request URL (including `Session().get()`) | CWE-918 | high/medium |
| Hardcoded secrets — API keys and credentials in source code | CWE-798 | high |
| Prompt injection — user-fetched content returned to the LLM | CWE-020 | medium |
| Unsafe deserialization — user input to `pickle.loads`, `yaml.load` | CWE-502 | high/medium |
| Template injection — user input to `jinja2.Template()` or `env.from_string()` | CWE-94 | high/medium |
| XML injection (XXE) — user input to `ET.fromstring()` or `lxml.etree.fromstring()` | CWE-611 | high/medium |
| LDAP injection — user input in LDAP search filters without escaping | CWE-90 | high/medium |
| Log injection — user input as the log message (enables log forging) | CWE-117 | high/medium |

Severity is **high** for confirmed MCP tool handlers (`@mcp.tool`), **medium** for unknown context.

## Usage

```bash
# Scan a directory
mcpaudit ./path/to/server

# Output as JSON for CI/CD
mcpaudit ./path/to/server --format json

# Output as SARIF for GitHub Code Scanning
mcpaudit ./path/to/server --format sarif --output-file results.sarif

# Only show high and critical findings
mcpaudit ./path/to/server --min-severity high

# Run only specific rules
mcpaudit ./path/to/server --rules shell_injection,path_traversal

# Exit code 0 even when findings exist (for reporting without blocking)
mcpaudit ./path/to/server --no-exit-code

# Include test files (excluded by default)
mcpaudit ./path/to/server --no-default-excludes

# Exclude generated code
mcpaudit ./path/to/server --exclude '**/generated/**'

# Write output to a file
mcpaudit ./path/to/server --format json --output-file findings.json
```

## Baseline mode (CI onboarding)

Establish a baseline from an existing codebase so CI only fails on *new* findings:

```bash
# First run: saves current findings as baseline, exits 0
mcpaudit ./src --baseline baseline.json

# Subsequent runs: only reports findings NOT in baseline
mcpaudit ./src --baseline baseline.json
```

Commit `baseline.json` to your repo. From that point on, the scanner blocks only regressions.

## Config file

Generate a project config:

```bash
mcpaudit init
```

This creates `.mcpaudit.toml` in the current directory:

```toml
[mcpaudit]
min_severity = "low"
format = "text"
exclude = [
    "**/generated/**",
    "**/vendor/**",
]
rules = []   # empty = all rules
```

CLI flags always override the config file.

## Suppressing findings

Add a comment to suppress a finding on a specific line:

```python
result = eval(expr)           # mcpaudit: ignore
result = eval(expr)           # mcpaudit: ignore[CWE-95]
cursor.execute(query)         # mcpaudit: ignore[CWE-89]
```

CWE-specific suppression only silences that CWE on that line; other rules still apply.

## GitHub Actions

### Run tests in CI

```yaml
- name: Run mcpaudit
  run: mcpaudit ./src --format sarif --output-file mcpaudit.sarif --no-exit-code

- name: Upload to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcpaudit.sarif
```

### Block PRs on new findings

```yaml
- name: mcpaudit (baseline diff)
  run: mcpaudit ./src --baseline baseline.json
```

## How it works

mcpaudit parses Python source with the `ast` module and traces data flow from MCP tool
parameters to dangerous sinks. It classifies each function as:

- **tool** — decorated with `@mcp.tool` or `@server.call_tool` → findings reported as **high**
- **unknown** — no classifier signal → findings reported as **medium**
- **safe** — CLI code, `@classmethod`, utils directories, test functions → **not flagged**

Import aliases are tracked — `import subprocess as sp; sp.run(cmd, shell=True)` is detected.
Session-based HTTP calls are tracked — `requests.Session().get(url)` is detected.

No external API calls. Runs fully offline.

## License

MIT
