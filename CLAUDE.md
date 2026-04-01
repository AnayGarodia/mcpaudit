# mcpaudit — MCP Server Static Analysis Tool

## What this is
A CLI tool that scans MCP server Python source code for security vulnerabilities.
It parses ASTs, traces data flow from tool input parameters to dangerous sinks,
and reports findings with severity and CWE classifications.

## Tech stack
- Python 3.10+
- ast module (stdlib) for Python parsing
- click for CLI
- rich for terminal output formatting

## Project structure
- src/mcpaudit/models.py — `Finding` dataclass (file_path, line, severity, cwe_id, description, remediation, rule_id, snippet)
- src/mcpaudit/rules/_taint.py — `TaintVisitor` base class: taint propagation + context classification
- src/mcpaudit/rules/ — one file per vulnerability class; all inherit `TaintVisitor`
- src/mcpaudit/scanner.py — orchestrates rules; populates snippet; applies suppression; `_RULES` list
- src/mcpaudit/cli.py — CLI entry point
- tests/fixtures/ — small Python files with known vulnerabilities for testing

## Architecture decisions
- Each rule is a function `check_<rule>(tree, file_path) -> list[Finding]`
- All taint-tracking rules inherit `TaintVisitor` from `_taint.py`
- `TaintVisitor` classifies each function as "tool" / "safe" / "unknown":
  - "tool" → HIGH severity, from `@mcp.tool` / `@server.call_tool` decorators or name keywords
  - "safe" → NOT flagged, from CLI decorators, `@classmethod`, safe directories, `test_` prefix
  - "unknown" → MEDIUM severity, default
- Safe path directories (not flagged): cli, commands, config, utilities, utils, transports, providers, preprocessing, models, middleware, auth
- Inline suppression: `# mcpaudit: ignore` or `# mcpaudit: ignore[CWE-XX]` on the triggering line
- No external API calls — everything runs offline
- Zero non-stdlib dependencies for core scanning (click and rich are CLI-only)

## Commands
- `python -m pytest tests/` — run tests (335 tests as of last session)
- `python -m mcpaudit ./path` — run scanner

## Rules (8 total)
| Rule file | CWE | Detects |
|-----------|-----|---------|
| shell_injection.py | CWE-78 | subprocess/os.system with shell=True and tainted input |
| code_injection.py | CWE-95 | eval()/exec() with tainted input |
| sql_injection.py | CWE-89 | cursor/conn/db.execute() with tainted raw query (no params) |
| path_traversal.py | CWE-22 | open()/Path()/os.path.join() with tainted path |
| ssrf.py | CWE-918 | requests/httpx/urllib with tainted URL |
| hardcoded_secrets.py | CWE-798 | API keys/passwords as string literals |
| prompt_injection.py | CWE-020 | user-fetched content or instruction strings returned to LLM |
| unsafe_deserialization.py | CWE-502 | pickle.loads/marshal.loads/yaml.load without SafeLoader |

## Adding a new rule
1. Create `src/mcpaudit/rules/<name>.py` — subclass `TaintVisitor`, implement `visit_Call`
2. Set `rule_id="<name>"` on every `Finding` created
3. Register it in `scanner.py`'s `_RULES` list
4. Add `tests/fixtures/<name>_vulnerable.py` and `<name>_safe.py`
5. Add `tests/test_<name>.py` — test vulnerable fixture count, safe fixture empty, inline edge cases

## Finding fields
```python
Finding(
    file_path=str,      # absolute or relative path
    line=int,           # 1-indexed line number
    severity=str,       # "low" | "medium" | "high" | "critical"
    cwe_id=str,         # e.g. "CWE-78"
    rule_id=str,        # e.g. "shell_injection"  ← used for --rules filter and SARIF ruleId
    description=str,    # human-readable explanation
    remediation=str,    # how to fix
    snippet=str,        # source line, auto-populated by scanner.py
)
```

## CLI options
```
mcpaudit <path>
  --min-severity low|medium|high|critical   filter by severity
  --format text|json|sarif                  output format
  --output-file <path>                      write output to file
  --rules <rule1,rule2>                     run only specific rules
  --exclude <glob>                          add extra exclude patterns
  --no-default-excludes                     disable test-file exclusions
  --exit-code / --no-exit-code              control exit code on findings
```

## Code style
- Type hints on all function signatures
- Docstrings on all public functions
- No classes unless genuinely needed — prefer functions
- f-strings over .format()
