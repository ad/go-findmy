# Find My add-on

Shows AirTags and OpenHaystack tags in Home Assistant as `device_tracker` entities. No Mac needed: the add-on emulates macOS anisette with [os-findmy-e](https://github.com/sacca97/os-findmy-e).

## Requirements

- The Mosquitto broker add-on, or another MQTT broker known to Home Assistant. The add-on does not start without it.
- The MQTT integration with discovery enabled.

## First start

1. The add-on downloads iTunes 12.8.3 from Apple once, extracts CoreADI into `/data/coreadi` and deletes the installer.
2. Open the add-on panel. It shows only the step you are on: Apple ID, then the code, then the tags. Sign in with your Apple ID. Right before the sign-in the add-on provisions an emulated Mac in `/data/anisette`; Apple sees a new Mac on your account.
3. Enter the 2FA code. A trusted Apple device gets it. With "Code by SMS" ticked, or without a trusted device, the first trusted phone number gets an SMS.
4. Once signed in, the panel lists your tags. Import AirTags as JSON, one tag or a list of all of them like `airtags.json` (paste it or pick the file) in FindMy.py / export-findmy format, see "AirTag keys". OpenHaystack `.keys` files go into `/data/keys`.

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
- You get one `<identifier>.json` per AirTag in `~/airtags`, mode 0600. Paste one file, or the whole `airtags.json` if `keys` left it, into the panel's Import form, then delete the folder: the files are the tags' private keys.
- Nothing is added to the keychain circle. Apple does see one more Mac on the account: remove it from the device list afterwards.

The first run builds the image and downloads iTunes 12.8.3 from Apple for CoreADI.

## Tags and time zone

- To remove a tag, open "Delete" under it in the panel and confirm. The add-on deletes the tag's key file and its device from Home Assistant. Import the tag again to get it back.
- Under the name of each tag the panel links to its device page in Home Assistant, with the entity ID. The add-on finds them in the Home Assistant entity registry, which is why it asks for `homeassistant_api`; the links are missing while Home Assistant does not answer or has not created the entity yet.
- To change the name of a tag's device in Home Assistant, open "Rename" under it. The name is kept in `/data/names.json`, so it stays when you import the tag again. An empty name restores the one from the tag's keys. The entity ID does not change; rename that in Home Assistant if you want.
- The panel shows times in the time zone of Home Assistant. Set `timezone` (for example `Europe/Berlin`) to use another one.

## Polling

- `poll_interval` is in minutes, 15 at least. Polling more often raises the risk of an Apple ban.
- Each AirTag costs at most 3 requests per poll. A tag without a recent alignment is searched across several polls.
- After Apple rejects the token, the add-on tries one relogin with the saved password. If Apple refuses it, the add-on stops polling and turns on `binary_sensor.find_my_login_required`. Sign in again in the panel. Any other relogin failure pauses polling for 45 minutes, then the relogin is tried again.
- After Apple refuses a sign-in (wrong password, locked Apple ID, HTTP 429), nothing is sent to Apple for 45 minutes. The panel shows when that ends. A refused sign-in with another Apple ID does not stop the saved one: it polls again after the pause.
- One Apple ID fetches the locations of all tags, also tags of other Apple IDs: import their keys, no second account is needed. To switch the Apple ID, use "Sign out" under Account in the panel, then sign in. Signing out keeps the 45-minute pause.

## Backups

The add-on data, and so every Home Assistant backup, holds:
- the Apple session, tokens and the password hash in `/data/account`;
- the emulated Mac;
- the private keys of all tags.

Anyone with a backup can track your tags and use your Apple session. Store backups accordingly.
