#./claudebox.sh --shell --workdir work

# Example: inject GitHub token from cred/gh_readonly
GH_TOKEN=$(cat "$(dirname "$0")/cred/gh_readonly") \
  ./claudebox.sh --enable-github --shell --workdir work
