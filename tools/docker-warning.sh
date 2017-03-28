#!/bin/sh -e
echo "Warning: This Docker image will soon be switching to Alpine Linux." >&2
echo "You can switch now using the certbot/certbot repo on Docker Hub." >&2
exec /opt/certbot/venv/bin/certbot $@
