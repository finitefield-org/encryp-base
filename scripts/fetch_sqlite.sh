#!/usr/bin/env bash

set -euo pipefail

readonly SQLITE_VERSION_TOKEN="3510300"
readonly SQLITE_RELEASE="3.51.3"
readonly SQLITE_YEAR="2026"
readonly SQLITE_SHA3="ced02ff9738970f338c9c8e269897b554bcda73f6cf1029d49459e1324dbeaea"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
dest_dir="${repo_root}/third_party/sqlite/${SQLITE_VERSION_TOKEN}"
tmp_zip="${dest_dir}/sqlite-amalgamation-${SQLITE_VERSION_TOKEN}.zip"
download_url="https://www.sqlite.org/${SQLITE_YEAR}/sqlite-amalgamation-${SQLITE_VERSION_TOKEN}.zip"

mkdir -p "${dest_dir}"

curl -fsSL "${download_url}" -o "${tmp_zip}"

download_hash="$(openssl dgst -sha3-256 "${tmp_zip}" | awk '{print $2}')"
if [[ "${download_hash}" != "${SQLITE_SHA3}" ]]; then
  echo "SQLite archive hash mismatch" >&2
  echo "expected: ${SQLITE_SHA3}" >&2
  echo "actual:   ${download_hash}" >&2
  exit 1
fi

unzip -oq -j "${tmp_zip}" \
  "sqlite-amalgamation-${SQLITE_VERSION_TOKEN}/sqlite3.c" \
  "sqlite-amalgamation-${SQLITE_VERSION_TOKEN}/sqlite3.h" \
  "sqlite-amalgamation-${SQLITE_VERSION_TOKEN}/sqlite3ext.h" \
  -d "${dest_dir}"

rm -f "${tmp_zip}"

cat <<EOF
Fetched SQLite ${SQLITE_RELEASE} into ${dest_dir}
EOF
