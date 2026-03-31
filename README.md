# mcpaudit

Find security vulnerabilities in MCP servers before you deploy them.
```bash
pip install mcpaudit
mcpaudit ./my-mcp-server
```

[screenshot/GIF goes here when you have one]

## What it finds

- **Shell injection** — tool inputs passed to subprocess/os.system without sanitization (CWE-78)
- **Path traversal** — file operations without path boundary validation (CWE-22)  
- **Tool description injection** — hidden instructions embedded in tool metadata

## Usage
```bash
# Scan a local MCP server
mcpaudit ./path/to/server

# Output as JSON (for CI/CD)
mcpaudit ./path/to/server --format json

# Exit code 1 if critical findings (use in CI)
mcpaudit ./path/to/server --fail-on critical
```

## Install
```bash
pip install mcpaudit
```

## Results from scanning popular MCP servers

[This section is your launch content — add it in week 2]

## License

MIT
```

That's it for now. Don't add badges, contributor guidelines, or a code of conduct until the tool actually works. Those are signals of a mature project — on a brand new repo they look like decoration.

**Project structure:**
```
mcpaudit/
├── README.md
├── LICENSE
├── pyproject.toml
├── src/
│   └── mcpaudit/
│       ├── __init__.py
│       ├── cli.py          # argparse/click entry point
│       ├── scanner.py      # orchestrates rules against files
│       ├── rules/
│       │   ├── __init__.py
│       │   ├── shell_injection.py
│       │   ├── path_traversal.py
│       │   └── description_injection.py
│       └── report.py       # formats output (table, JSON, SARIF)
└── tests/
    ├── fixtures/
    │   ├── safe_server.py
    │   └── vulnerable_server.py
    └── test_rules.py
