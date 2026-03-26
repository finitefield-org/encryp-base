# Vendored SQLite

This directory vendors the SQLite amalgamation used by `encryp-base`.

## Pinned Version

- SQLite version: `3.51.3`
- Amalgamation token: `3510300`
- Source archive: `https://www.sqlite.org/2026/sqlite-amalgamation-3510300.zip`
- SHA3-256: `ced02ff9738970f338c9c8e269897b554bcda73f6cf1029d49459e1324dbeaea`

## Layout

- `3510300/sqlite3.c`
- `3510300/sqlite3.h`
- `3510300/sqlite3ext.h`

## Refresh

Run `scripts/fetch_sqlite.sh` to re-download the pinned amalgamation from the official SQLite site.
