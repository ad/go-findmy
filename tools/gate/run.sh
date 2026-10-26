#!/bin/sh
set -eu
exec docker run --rm -it \
  -v findmy-gate-ext:/opt/os-findmy-e/ext \
  -v findmy-gate-state:/tmp/macadi \
  go-findmy-gate "$@"
