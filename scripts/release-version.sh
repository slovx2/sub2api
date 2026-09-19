#!/usr/bin/env bash
# 发布号使用 上游主版本.次版本.补丁版本.分支修订号，例如 v0.2.7.1。
set -euo pipefail

tag="${1:?需要传入发布 tag，例如 v0.2.7.1}"
if [[ ! "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.([1-9][0-9]*)$ ]]; then
  echo "无效发布 tag：$tag；应为 vX.Y.Z.N，N 从 1 开始递增" >&2
  exit 1
fi

printf 'tag=%s\nversion=%s\nupstream=%s.%s.%s\nmajor=%s\nminor=%s\n' \
  "$tag" "${tag#v}" "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" \
  "${BASH_REMATCH[3]}" "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
