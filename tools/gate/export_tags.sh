#!/bin/sh
set -eu
out="${1:?usage: tools/gate/export_tags.sh OUT_DIR [--2fa sms]}"
shift
cd "$(dirname "$0")"
docker image inspect go-findmy-gate >/dev/null 2>&1 || docker build -t go-findmy-gate .
mkdir -p "$out"
chmod 700 "$out"
out=$(cd "$out" && pwd)

# A fresh machine "export", so the long-lived "gate" machine is never logged in again.
exec docker run --rm -it \
  -v findmy-gate-ext:/opt/os-findmy-e/ext \
  -v findmy-gate-state:/tmp/macadi \
  -v "$out":/out \
  go-findmy-gate sh -euc '
    umask 077
    [ -d ext/itunes/mac ] || .venv/bin/python tools/fetch_mac_coreadi.py
    tools/login.sh export "$@" --tags --tags-save /out/airtags.json
    .venv/bin/python - <<EOF
import json, os
for a in json.load(open("/out/airtags.json")):
    path = "/out/" + a["identifier"].replace("/", "_") + ".json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(a, f, indent=2)
    print("saved", a["name"], "->", os.path.basename(path))
os.remove("/out/airtags.json")
EOF
  ' sh "$@"
