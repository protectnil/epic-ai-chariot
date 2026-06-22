#!/usr/bin/env bash
# Installs tracked git hooks into .git/hooks/
set -euo pipefail
REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOKS_SRC="$REPO_ROOT/scripts/hooks"
HOOKS_DST="$REPO_ROOT/.git/hooks"
for hook in "$HOOKS_SRC"/*; do
  name=$(basename "$hook")
  [ "$name" = "install.sh" ] && continue
  cp "$hook" "$HOOKS_DST/$name"
  chmod +x "$HOOKS_DST/$name"
  echo "Installed $name"
done
echo "Done."
