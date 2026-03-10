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
data_dir="$(grep '^COREPOST_DATA_DIR=' "$env_file" | cut -d= -f2)"
data_path="$repo_root/${data_dir#./}"

docker compose -p "$project_name" --env-file "$env_file" down --remove-orphans >/dev/null 2>&1 || true
rm -rf "$data_path"
mkdir -p "$data_path"
docker compose -p "$project_name" --env-file "$env_file" up --build --wait -d

port="$(grep '^COREPOST_SERVER_PORT=' "$env_file" | cut -d= -f2)"
token="$(grep '^COREPOST_ADMIN_TOKEN=' "$env_file" | cut -d= -f2)"
openapi_path="$(awk -F= '/^COREPOST_OPENAPI_PATH=/{print $2; found=1} END{if (!found) print "/openapi.json"}' "$env_file")"

echo "instance=$instance"
echo "project=$project_name"
echo "port=$port"
echo "admin_token=$token"
echo "openapi_path=$openapi_path"
