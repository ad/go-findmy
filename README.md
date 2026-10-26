# go-findmy

Locations of AirTags and OpenHaystack tags from Apple's Find My network, without a Mac. macOS anisette is emulated with [os-findmy-e](https://github.com/sacca97/os-findmy-e).

## Home Assistant add-on

Add this repository to the add-on store, then install "Find My". Tags show up as `device_tracker` entities over MQTT. Setup, polling and backups: [findmy/README.md](findmy/README.md).

## CLI

```sh
go run ./cmd/go-findmy keygen       # new OpenHaystack key into keys/<MAC>.keys
go run ./cmd/go-findmy login        # Apple ID sign-in and 2FA, add "sms" for an SMS code
go run ./cmd/go-findmy fetch        # reports for every tag in keys/
go run ./cmd/go-findmy serve        # the add-on's service, expects /data and MQTT_* env
```

- `login` and `fetch` need the anisette sidecar on `127.0.0.1:6969`. Start it as `findmy/run.sh` does: `$OSFE/.venv/bin/python sidecar/anisette_sidecar.py serve --state DIR --osfe $OSFE`, with `COREADI_PATH` set and `$OSFE` an os-findmy-e checkout.
- `keys/` holds `.keys` files from `keygen` and AirTag JSON files. `fetch` fails until the folder exists.

## AirTag keys

AirTag keys are exported once with `tools/gate/export_tags.sh`. Steps and caveats: [findmy/README.md#airtag-keys](findmy/README.md#airtag-keys).

## Secrets

These hold the Apple session or the tags' private keys. Keep them out of git and out of shared places:
- `account/`: tokens and the password hash from `login`;
- `keys/`: private keys of all tags;
- the `export_tags.sh` output folder;
- the sidecar `--state` folder: the emulated Mac;
- Home Assistant backups of the add-on.

## Apple risks

State as of 2026-10:
- The first sign-in on an empty sidecar state provisions an emulated Mac. Apple lists it on the account as a new device.
- Apple issues `searchPartyToken` only to a macOS or iOS machine, and the token works only with that machine's anisette.
- A client-info that does not match the anisette machine is refused: GSA answers `-80045`, `loginDelegates` answers `status:1`.
- Frequent polling or repeated sign-ins raise the risk of an Apple ID lock. Keep `poll_interval` at 15 minutes or more.
- Apple changes these rules without notice. Any of the above can break at any time.
