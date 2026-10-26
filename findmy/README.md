# Find My add-on

Shows AirTags and OpenHaystack tags in Home Assistant as `device_tracker` entities. No Mac needed: the add-on emulates macOS anisette with [os-findmy-e](https://github.com/sacca97/os-findmy-e).

## Requirements

- The Mosquitto broker add-on, or another MQTT broker known to Home Assistant. The add-on does not start without it.
- The MQTT integration with discovery enabled.

## First start

1. The add-on downloads iTunes 12.8.3 from Apple once, extracts CoreADI into `/data/coreadi` and deletes the installer.
2. Open the add-on panel and sign in with your Apple ID. Right before the sign-in the add-on provisions an emulated Mac in `/data/anisette`; Apple sees a new Mac on your account.
3. Enter the 2FA code. A trusted Apple device gets it; without one, the first trusted phone number gets an SMS.
4. Import each AirTag as JSON in FindMy.py / export-findmy format, see "AirTag keys". OpenHaystack `.keys` files go into `/data/keys`.

## AirTag keys

The add-on does not read AirTag keys from iCloud itself. Export them once on any computer with Docker, from a clone of this repository, in two steps:

```sh
tools/gate/export_tags.sh login
tools/gate/export_tags.sh keys ~/airtags
```

- `login` asks for the Apple ID, the password and the 2FA code. Add `--2fa sms` to get the code by SMS instead of on a trusted device. A second `login` reuses the same emulated Mac; Apple may then skip the 2FA code.
- Run `keys` later, not right after `login`. Reading the keychain costs one more sign-in, and two sign-ins seconds apart got HTTP 429. An hour apart worked.
- After HTTP 429 both steps refuse to run for 45 minutes.
- `keys` lists your devices with an escrow record: pick the one whose screen-lock passcode you know and type that passcode. It then deletes the saved login, which holds the password, whatever the outcome.
- **A wrong passcode is not retried.** Apple limits wrong guesses, so check which device you picked.
- You get one `<identifier>.json` per AirTag in `~/airtags`, mode 0600. Paste each into the panel's Import form, then delete the folder: the files are the tags' private keys.
- Nothing is added to the keychain circle. Apple does see one more Mac on the account: remove it from the device list afterwards.

The first run builds the image and downloads iTunes 12.8.3 from Apple for CoreADI.

## Polling

- `poll_interval` is in minutes, 15 at least. Polling more often raises the risk of an Apple ban.
- Each AirTag costs at most 3 requests per poll. A tag without a recent alignment is searched across several polls.
- After Apple rejects the token, the add-on tries one relogin with the saved password. If that fails, it stops polling and turns on `binary_sensor.find_my_login_required`. Sign in again in the panel.
- After Apple refuses a sign-in (wrong password, locked Apple ID, HTTP 429), nothing is sent to Apple for 45 minutes. The panel shows when that ends.

## Backups

The add-on data, and so every Home Assistant backup, holds:
- the Apple session, tokens and the password hash in `/data/account`;
- the emulated Mac;
- the private keys of all tags.

Anyone with a backup can track your tags and use your Apple session. Store backups accordingly.
