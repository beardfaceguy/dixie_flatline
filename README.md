# Dixie Flatline

LLM-driven red team penetration testing tool.

## Quick Start

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install
pip install -e ".[dev]"

# List available tools
dixie tools

# Run an engagement
dixie engage example-engagement.yaml
```

## Docker Sandbox

Build the sandbox image with pentesting tools:

```bash
docker build -t dixie-sandbox:latest docker/
```

## Testing

```bash
pytest -v
```
