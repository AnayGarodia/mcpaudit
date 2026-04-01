"""
Vulnerable MCP tool handler: credentials hardcoded as string literals.
This file is intentionally insecure — used as a detection fixture for mcpaudit.
"""

# Mode 1: variable name matching
password = "hunter2supersecret"

api_key = "AKIAIOSFODNN7EXAMPLE1234"  # also matches AWS regex

# Annotated assignment with secret name
client_secret: str = "abc123realsecret"

# Mode 2: key format regex — OpenAI key format
openai_key = "sk-" + "A" * 48  # not a Constant, won't fire

GITHUB_TOKEN = "ghs_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
