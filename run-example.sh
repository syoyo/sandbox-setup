# Basic shell (network isolated by default):
./claudebox.sh --shell --workdir work

# With GitHub MCP server (recommended):
# Reads token from ~/.config/claudebox/gh-token automatically.
# ./claudebox.sh --enable-github-mcp --workdir work

# Or pass token explicitly:
# GH_TOKEN=$(cat ~/.config/claudebox/gh-token) ./claudebox.sh --enable-github-mcp --workdir work

# With GitHub CONNECT proxy (unrecommended — exposes token in sandbox):
# ./claudebox.sh --enable-github --workdir work
