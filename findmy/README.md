# Find My add-on

Shows AirTags and OpenHaystack tags in Home Assistant as `device_tracker` entities. No Mac needed: the add-on emulates macOS anisette with [os-findmy-e](https://github.com/sacca97/os-findmy-e).

## Requirements

- The Mosquitto broker add-on, or another MQTT broker known to Home Assistant. The add-on does not start without it.
- The MQTT integration with discovery enabled.

## First start

1. The add-on downloads iTunes 12.8.3 from Apple once, extracts CoreADI into `/data/coreadi` and deletes the installer.
2. It provisions an emulated Mac in `/data/anisette`. Apple sees a new Mac on your account.
3. Sign in with your Apple ID and enter the 2FA code in the add-on panel. Until sign-in is wired in, put `dsid` and `searchPartyToken` into `/data/keys/auth.json` by hand.
4. Import each AirTag as JSON in FindMy.py / export-findmy format. OpenHaystack `.keys` files go into `/data/keys`.

## Polling

- `poll_interval` is in minutes, 15 at least. Polling more often raises the risk of an Apple ban.
- Each AirTag costs at most 3 requests per poll. A tag without a recent alignment is searched across several polls.
- After Apple rejects the token, the add-on stops polling and turns on `binary_sensor.find_my_login_required`. Sign in again in the panel.

## Backups

The add-on data, and so every Home Assistant backup, holds:
- the Apple session and tokens;
- the emulated Mac;
- the private keys of all tags.

Anyone with a backup can track your tags and use your Apple session. Store backups accordingly.
