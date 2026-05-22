#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

kubectl apply -f "$SCRIPT_DIR/users.yml"
kubectl apply -f "$SCRIPT_DIR/roles.yml"
kubectl apply -f "$SCRIPT_DIR/bindings.yml"
