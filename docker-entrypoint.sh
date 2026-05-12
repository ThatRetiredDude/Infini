#!/bin/sh
set -eu
node server/scripts/seed-admin.js
exec "$@"
