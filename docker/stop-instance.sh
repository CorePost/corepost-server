#!/bin/bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 <preboot|agent|mobile-android|mobile-ios>" >&2
  exit 1
fi

instance="$1"
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
env_file="$repo_root/docker/instances/${instance}.env"

if [ ! -f "$env_file" ]; then
  echo "unknown instance: $instance" >&2
  exit 1
fi

cd "$repo_root"
project_name="$(grep '^COREPOST_PROJECT_NAME=' "$env_file" | cut -d= -f2)"
docker compose -p "$project_name" --env-file "$env_file" down
