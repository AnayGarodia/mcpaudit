# mcpaudit

Find security vulnerabilities in MCP server Python code before you deploy them.

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
| SSRF — user input as HTTP request URL | CWE-918 | high/medium |
| Hardcoded secrets — API keys and credentials in source code | CWE-798 | high |
| Prompt injection — user-fetched content returned to the LLM | CWE-020 | medium |
| Unsafe deserialization — user input to `pickle.loads`, `yaml.load` | CWE-502 | high/medium |

Severity is **high** for confirmed MCP tool handlers (`@mcp.tool`), **medium** for functions of unknown context.

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
```

## Suppressing findings

Add a comment to suppress a specific finding on that line:

```python
result = eval(expr)  # mcpaudit: ignore
result = eval(expr)  # mcpaudit: ignore[CWE-95]
```

## GitHub Actions (SARIF upload)

```yaml
- name: Run mcpaudit
  run: mcpaudit ./src --format sarif --output-file mcpaudit.sarif --no-exit-code

- name: Upload results to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcpaudit.sarif
```

## How it works

mcpaudit parses Python source with the `ast` module and traces data flow from MCP tool parameters to dangerous sinks. It classifies each function as:

- **tool** — decorated with `@mcp.tool` or `@server.call_tool` → findings reported as **high**
- **unknown** — no classifier signal → findings reported as **medium**
- **safe** — CLI code, `@classmethod`, utils directories, test functions → **not flagged**

No external API calls. Runs fully offline.

## License

MIT
