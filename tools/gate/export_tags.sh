#!/bin/sh
set -eu
usage="usage: tools/gate/export_tags.sh login [--2fa sms] | keys OUT_DIR"
step="${1:?$usage}"
shift
cd "$(dirname "$0")"
docker image inspect go-findmy-gate >/dev/null 2>&1 || docker build -t go-findmy-gate .

run() {
  docker run --rm -it \
    -v findmy-gate-ext:/opt/os-findmy-e/ext \
    -v findmy-gate-state:/tmp/macadi \
    "$@"
}

case "$step" in
login)
  # Its own machine "export", so the long-lived "gate" machine is never logged in again.
  run go-findmy-gate sh -euc '
    .venv/bin/python -c "import sys; sys.path.insert(0, \"tools/machoadi\"); import cooldown; cooldown.guard()"
    [ -d ext/itunes/mac ] || .venv/bin/python tools/fetch_mac_coreadi.py
    if [ -f /tmp/macadi/export/identity.json ]; then
      tools/aged_login.sh /tmp/macadi/export "$@"
    else
      tools/login.sh export "$@" --save-login /tmp/macadi/export-login.json
    fi
  ' sh "$@"
  ;;
keys)
  out="${1:?$usage}"
  mkdir -p "$out"
  chmod 700 "$out"
  out=$(cd "$out" && pwd)
  run -v "$out":/out go-findmy-gate sh -euc '
    trap "rm -f /tmp/macadi/export-login.json /out/airtags.json" EXIT
    umask 077
    tools/restored_run.sh /tmp/macadi/export --tags --tags-save /out/airtags.json
    .venv/bin/python - <<EOF
import json, os
for a in json.load(open("/out/airtags.json")):
    path = "/out/" + a["identifier"].replace("/", "_") + ".json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(a, f, indent=2)
    print("saved", a["name"], "->", os.path.basename(path))
EOF
  '
  ;;
*)
  echo "$usage" >&2
  exit 2
  ;;
esac
