#!/bin/sh
# Mint a Thessley Passkey login QR for a WordPress site, serve the PNG from the
# loopback HTTPS surface, and wait for the approval while persisting cookies.
#
#   scripts/qr-login.sh [site-base-url] [username]
#
# Defaults: https://wp-opsec.eagleeye-intelligence.com admin
#
# Prerequisites: the loopback server is running (scripts/qr-https-serve.py) and
# qrencode + curl + python3 are installed. Nothing is written to the site.

set -eu

BASE=${1:-https://wp-opsec.eagleeye-intelligence.com}
USER=${2:-admin}
DIR=${QR_DIR:-/tmp/opencode/qr-site}
JAR=/tmp/opencode/qrlogin-cookies.txt
START=/tmp/opencode/qrlogin-start.json

mkdir -p "$DIR"
rm -f "$JAR" "$START"

curl -s -c "$JAR" -X POST "$BASE/?rest_route=/thessley/v1/passkey/login/start" \
     --data-urlencode "username=$USER" -o "$START"

ID=$(python3 -c "import json;print(json.load(open('$START'))['request_id'])")
python3 -c "import json;print(json.load(open('$START'))['app_link'])" > "$DIR/link.txt"

qrencode -l M -s 8 -m 2 -o "$DIR/qr.png" < "$DIR/link.txt"

echo "request:   $ID"
echo "QR:        https://127.0.0.1:8443/qr.png"
echo "link:      https://127.0.0.1:8443/link.txt"
echo "expires:   $(python3 -c "import json;print(json.load(open('$START')).get('expires_in'))") s"
echo

# Poll, saving the session cookie the approval issues (-b and -c together;
# reading with -b alone silently drops wordpress_logged_in).
for _ in $(seq 1 40); do
    OUT=$(curl -s -b "$JAR" -c "$JAR" "$BASE/?rest_route=/thessley/v1/passkey/login/$ID/status")
    ST=$(python3 -c "import json,sys;print(json.loads(sys.argv[1]).get('status','?'))" "$OUT" 2>/dev/null || echo '?')
    case "$ST" in
        approved)
            echo "status: approved"
            echo "$OUT" | head -c 200; echo
            curl -s -b "$JAR" -o /tmp/opencode/qrlogin-admin.html \
                 -w 'wp-admin: %{http_code}\n' --max-time 15 "$BASE/wp-admin/"
            grep -o '<title>[^<]*</title>' /tmp/opencode/qrlogin-admin.html | head -1
            exit 0
            ;;
        denied|expired)
            echo "status: $ST"
            exit 1
            ;;
    esac
    sleep 3
done

echo "status: still pending (mint a new request, approvals are single-use)"
exit 1
