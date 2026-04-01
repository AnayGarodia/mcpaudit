"""
Safe credential handling: reads secrets from environment variables.
This file is intentionally secure — used as a negative fixture for mcpaudit.
"""
import os

# Read from environment — value is not an ast.Constant string
password = os.environ["PASSWORD"]
api_key = os.environ.get("API_KEY", "")

# Empty string and common placeholders are excluded
token = ""
secret = "changeme"
api_key_dev = "your_api_key"
placeholder_secret = "<your-secret-here>"

# Annotated declaration without assignment
client_secret: str

# Unrelated variable with a string value
greeting = "hello world"
app_name = "mcpaudit"
