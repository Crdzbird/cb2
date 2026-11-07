#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
work="$(mktemp -d)"
port="${CB2_SMOKE_PORT:-18080}"
base="http://127.0.0.1:$port"

go build -o "$work/server" ./examples/server
go build -o "$work/cb2cli" ./examples/cb2cli
"$work/server" -addr "127.0.0.1:$port" 2> "$work/server.log" &
server=$!
trap 'kill "$server" 2>/dev/null || true; rm -rf "$work"' EXIT
for _ in $(seq 100); do
  curl -fs -o /dev/null "$base/healthz" && break
  sleep 0.1
done

expect() {
  local name="$1" want="$2" got="$3"
  if [[ "$got" != *"$want"* ]]; then
    echo "FAIL $name: want $want, got $got"
    cat "$work/server.log"
    exit 1
  fi
  echo "ok   $name: $got"
}

curl -fs -X POST "$base/login" -d '{"username":"alice","password":"wonderland"}' > "$work/login.json"
"$work/cb2cli" prove -session "$work/login.json" -method GET -url "$base/me" > "$work/h.txt"
expect "bound request" '"sub":"alice"' "$(curl -s -H @"$work/h.txt" "$base/me")"
expect "replayed proof" 'proof_replayed' "$(curl -s -H @"$work/h.txt" "$base/me")"
"$work/cb2cli" prove -session "$work/login.json" -method GET -url "$base/other" > "$work/h.txt"
expect "other target" 'proof_mismatch' "$(curl -s -H @"$work/h.txt" "$base/me")"
"$work/cb2cli" prove -session "$work/login.json" -method GET -url "$base/me" > "$work/h.txt"
sed -i.bak -e '1s/\(Authorization: CB2 .\{60\}\)A/\1B/' -e 't' -e '1s/\(Authorization: CB2 .\{60\}\)./\1A/' "$work/h.txt"
if cmp -s "$work/h.txt" "$work/h.txt.bak"; then
  echo "FAIL the token was not altered"
  exit 1
fi
expect "tampered token" 'invalid' "$(curl -s -H @"$work/h.txt" "$base/me")"
head -1 "$work/h.txt.bak" > "$work/token.txt"
expect "no proof" 'missing_proof' "$(curl -s -H @"$work/token.txt" "$base/me")"
expect "bad password" 'bad_credentials' "$(curl -s -X POST "$base/login" -d '{"username":"alice","password":"x"}')"
kill -TERM "$server"
wait "$server"
echo "ok   graceful shutdown"
