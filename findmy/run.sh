#!/usr/bin/with-contenv bashio
set -e

OSFE=/opt/os-findmy-e
COREADI_DIR=/data/coreadi
export COREADI_PATH=$COREADI_DIR/coreadi-pkg/rootfs/System/Library/PrivateFrameworks/CoreADI.framework/Versions/A/CoreADI.x86_64

if [ ! -f "$COREADI_PATH" ]; then
  bashio::log.info "Downloading CoreADI from iTunes 12.8.3"
  (cd "$OSFE" && .venv/bin/python tools/fetch_mac_coreadi.py --dest "$COREADI_DIR")
  # The installer images are ~270 MB and would land in every HA backup.
  rm -rf "$COREADI_DIR/iTunes12.8.3.dmg" "$COREADI_DIR/ipkg" "$COREADI_DIR/coreadi-pkg/CoreADI.pkg"
fi

if [ ! -f /data/anisette/identity.json ]; then
  bashio::log.info "Provisioning the anisette machine"
  # No exit on failure: the add-on must not retry provisioning against Apple in a restart loop.
  "$OSFE/.venv/bin/python" /opt/anisette_sidecar.py provision --state /data/anisette --osfe "$OSFE" \
    || bashio::log.error "Provisioning failed. If /data/anisette is not empty, it must be cleared first."
fi

mkdir -p /data/keys
chmod 700 /data/keys

"$OSFE/.venv/bin/python" /opt/anisette_sidecar.py serve --state /data/anisette --osfe "$OSFE" &
for _ in $(seq 30); do
  curl -sf http://127.0.0.1:6969/health >/dev/null && break
  sleep 1
done

MQTT_HOST=$(bashio::services mqtt "host")
MQTT_PORT=$(bashio::services mqtt "port")
MQTT_USER=$(bashio::services mqtt "username")
MQTT_PASSWORD=$(bashio::services mqtt "password")
export MQTT_HOST MQTT_PORT MQTT_USER MQTT_PASSWORD

exec go-findmy serve
