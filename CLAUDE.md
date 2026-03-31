# mcpaudit — MCP Server Static Analysis Tool

## What this is
A CLI tool that scans MCP server Python source code for security vulnerabilities.
It parses ASTs, traces data flow from tool input parameters to dangerous sinks,
and reports findings with severity and CWE classifications.

## Tech stack
- Python 3.11+
- ast module (stdlib) for Python parsing
- click for CLI
- rich for terminal output formatting

## Project structure
- src/mcpaudit/rules/ — each file is one detection rule
- src/mcpaudit/scanner.py — orchestrates rules against parsed files
- src/mcpaudit/cli.py — CLI entry point
- tests/fixtures/ — small Python files with known vulnerabilities for testing

## Architecture decisions
- Each rule is a function that takes an ast.Module and returns a list of Finding objects
- No external API calls — everything runs offline
- Zero non-stdlib dependencies for core scanning (click and rich are CLI-only)

## Commands
- `python -m pytest tests/` — run tests
- `python -m mcpaudit ./path` — run scanner

## Rules
- Keep rules simple: one file, one vulnerability class
- Every rule must have test fixtures (a vulnerable file and a safe file)
- Use ast.NodeVisitor for traversal, not manual recursion
- Findings must include: file path, line number, severity (low/medium/high/critical), 
  CWE ID, description, and remediation suggestion

## Code style
- Type hints on all function signatures
- Docstrings on all public functions
- No classes unless genuinely needed — prefer functions
- f-strings over .format()
