#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
for tag in v0.2.7.1 v0.2.7.2 v0.2.7.10 v1.12.3.100; do
  output="$(bash "$script_dir/release-version.sh" "$tag")"
  [[ "$output" == *"version=${tag#v}"* ]]
done
for tag in v0.2.7 v0.2.7.0 v0.2.7.01 v0.2.7.1.2 v0.2.7.1-rc1 'v0.2.7.1$(false)'; do
  if bash "$script_dir/release-version.sh" "$tag" >/dev/null 2>&1; then
    echo "不应接受 tag：$tag" >&2
    exit 1
  fi
done
echo '发布版本规则测试通过'
