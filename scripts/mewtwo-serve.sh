#!/usr/bin/env bash
# Mewtwo launcher (Linux/macOS). Run: ./scripts/mewtwo-serve.sh
cd "$(dirname "$0")/.." || exit 1
if [ -x ".venv/bin/mewtwo" ]; then
    exec .venv/bin/mewtwo serve "$@"
else
    echo ".venv not found - falling back to system Python."
    exec python3 -m mewtwo serve "$@"
fi
