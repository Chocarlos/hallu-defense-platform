#!/bin/bash
set -euo pipefail

readonly template_dir="/opt/hallu-defense/opensearch-config"
readonly runtime_dir="/usr/share/opensearch/config"

if [[ "$(id -u)" == "0" ]]; then
  echo "OpenSearch config materializer refuses to run as root" >&2
  exit 1
fi
if [[ ! -d "${template_dir}" || -L "${template_dir}" ]]; then
  echo "OpenSearch immutable config template is missing or unsafe" >&2
  exit 1
fi
if [[ ! -d "${runtime_dir}" || -L "${runtime_dir}" || ! -w "${runtime_dir}" ]]; then
  echo "OpenSearch runtime config must be a writable, non-symlink mount" >&2
  exit 1
fi

umask 077
shopt -s dotglob globstar nullglob
template_entries=("${template_dir}"/*)
if (( ${#template_entries[@]} == 0 )); then
  echo "OpenSearch immutable config template is empty" >&2
  exit 1
fi
for template_entry in "${template_dir}"/**; do
  if [[ -L "${template_entry}" ]]; then
    echo "OpenSearch immutable config template contains a symlink" >&2
    exit 1
  fi
done

runtime_entries=("${runtime_dir}"/*)
if (( ${#runtime_entries[@]} )); then
  rm -rf -- "${runtime_entries[@]}"
fi
cp -R --no-preserve=ownership,mode,timestamps -- \
  "${template_entries[@]}" "${runtime_dir}"/
copied_entries=("${runtime_dir}"/*)
if (( ${#copied_entries[@]} == 0 )); then
  echo "OpenSearch runtime config materialization produced no files" >&2
  exit 1
fi
chmod -R u+rwX,go-rwx -- "${copied_entries[@]}"

for required in opensearch.yml jvm.options; do
  if [[ ! -f "${runtime_dir}/${required}" || -L "${runtime_dir}/${required}" ]]; then
    echo "OpenSearch runtime config is missing required file: ${required}" >&2
    exit 1
  fi
done

exec /usr/share/opensearch/opensearch-docker-entrypoint.sh "$@"
