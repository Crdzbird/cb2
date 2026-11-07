#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
PORT="${PORT:-8787}"
BASE="http://localhost:$PORT"
PORT="$PORT" TOKEN_TTL_SECONDS=2 node server.mjs &
SERVER=$!
trap 'kill "$SERVER" 2>/dev/null || true' EXIT
for _ in $(seq 50); do
    curl -s -o /dev/null "$BASE/" && break
    sleep 0.1
done

expect() {
    local want="$1" got="$2"
    echo "$got"
    [[ "$got" == *"$want"* ]] || { echo "expected: $want" >&2; exit 1; }
}

echo "\$ curl -s -X POST $BASE/login -d '{\"user\":\"ada\",\"password\":\"wrong\"}'"
expect '{"error":"invalid_credentials"}' "$(curl -s -X POST "$BASE/login" -d '{"user":"ada","password":"wrong"}')"

echo "\$ curl -s -X POST $BASE/login -d '{\"user\":\"ada\",\"password\":\"lovelace\"}'"
LOGIN="$(curl -s -X POST "$BASE/login" -d '{"user":"ada","password":"lovelace"}')"
expect '"token_type":"Bearer"' "$LOGIN"
TOKEN="$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).access_token)' "$LOGIN")"
TAMPERED="$(node -e 'const t = process.argv[1]; process.stdout.write(t.slice(0, 30) + (t[30] === "A" ? "B" : "A") + t.slice(31))' "$TOKEN")"

echo "\$ curl -s $BASE/me -H \"authorization: Bearer \$TOKEN\""
expect '{"sub":"ada","role":"admin"' "$(curl -s "$BASE/me" -H "authorization: Bearer $TOKEN")"

echo "\$ curl -si $BASE/me -H \"authorization: Bearer \$TAMPERED\""
expect 'error_description="invalid"' "$(curl -si "$BASE/me" -H "authorization: Bearer $TAMPERED" | grep -iE '^(HTTP|www-authenticate|\{)')"

echo "\$ curl -si $BASE/me"
expect '{"error":"missing_token"}' "$(curl -si "$BASE/me" | grep -iE '^(HTTP|\{)')"

sleep 3
echo "\$ curl -si $BASE/me -H \"authorization: Bearer \$TOKEN\"    (three seconds later)"
expect 'error_description="expired"' "$(curl -si "$BASE/me" -H "authorization: Bearer $TOKEN" | grep -iE '^(HTTP|www-authenticate|\{)')"
echo "smoke: every answer as expected"
