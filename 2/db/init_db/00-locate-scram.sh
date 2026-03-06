#!/usr/bin/env bash
set -e

echo "password_encryption = 'scram-sha-256'" >> "$PGDATA/postgresql.conf"

echo "include '/etc/postgresql/postgresql.conf'" >> "$PGDATA/postgresql.conf"