# ABB Welcome — Home Assistant integration

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=rankjie&repository=ha-abb-welcome&category=integration)

Local door-unlock buttons for ABB Welcome / Busch-Jaeger building intercoms backed
by an **IP gateway** (system type `mrange`).

This integration is LAN-first: pairing goes through the ABB MyBuildings cloud portal
once, and from then on every door unlock is a direct SIP request to your gateway on
port 5060. Door unlocks typically complete in well under 100 ms.

## Features

- One Home Assistant **button entity per outdoor station** (Outdoor 1 / Inner / Parking, etc.).
- LAN-only runtime: no internet round-trip when you press a button.
- Fully automated pairing — fill in four fields, the integration does the rest.
- Switchable unlock strategy if the default doesn't work on your gateway.

## Requirements

- An ABB Welcome **IP gateway** that you can reach on your local network
  (e.g. ABB **83342** or another `mrange`-system IP gateway, typically reachable
  at `192.168.x.x`).
- An **ABB-Welcome / Busch-Jaeger MyBuildings** account that is already linked to
  that gateway (the same login you use in the official ABB Welcome mobile app).
- The gateway's **web admin password** (the one used at `https://<gateway-ip>/`).
  Required for automated pairing — used during setup and stored with the
  config entry so re-pairing/renewal can run without interaction.

## Installation

### Via HACS (recommended)

Click the badge to add this repository to HACS in one step:

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=rankjie&repository=ha-abb-welcome&category=integration)

Then install **ABB Welcome** from HACS and restart Home Assistant.

If the button doesn't work (e.g. you haven't configured My Home Assistant): in HACS, open **⋮** → **Custom repositories**, add `https://github.com/rankjie/ha-abb-welcome` as an *Integration*, and install from there.

### Manual

Copy `custom_components/abb_welcome/` into your Home Assistant
`config/custom_components/` directory and restart.

## Configuration

Settings → **Devices & Services** → **Add Integration** → **ABB Welcome**.

Fill in four fields:

- MyBuildings portal **username**
- MyBuildings portal **password**
- Gateway local **IP address**
- Gateway **web admin password**

The integration then runs end-to-end without any further interaction:

1. Generates a fresh RSA keypair and requests a client certificate from the portal
   (HTTP Digest auth, returns 201 with a raw PEM).
2. Pulls the gateway's UUID from its local admin API.
3. Computes an 8-character **integrity code** locally from the cert's SHA-1
   fingerprint (the algorithm matches what the gateway re-derives on its side).
4. Sends a `welcome.connect` event so the gateway shows a pending pairing entry
   under a friendly name like `ha-1776370701`.
5. Logs into the gateway, finds that pending entry by friendly name, sets the
   permission flags, and submits the integrity code.
6. Polls the portal for the gateway's `acl-update` push, decrypts the SIP
   password with the private key, parses the door list, and creates one button
   entity per outdoor station.

A successful pairing typically completes in under 15 seconds.

## Entities

For each outdoor station discovered, the integration creates a
`button.<gateway>_<door_name>` entity. Press it from the UI or in an automation:

```yaml
service: button.press
target:
  entity_id: button.abb_welcome_outdoor_1
```

All buttons share a single device entry.

## Options

After setup, open the integration's **Configure** menu to change behaviour
without removing the entry.

### Unlock strategy

How the integration sends the unlock command to each door. Default is **Hybrid**.

| Strategy | What it does | When to use |
|---|---|---|
| **Hybrid** *(default)* | Plain SIP `MESSAGE` for the first outdoor station, `INVITE`-then-`MESSAGE` for the rest. | Best of both worlds on most setups. |
| **Fast** | Plain SIP `MESSAGE` for every door. | Lowest latency. Some gateways won't accept a `MESSAGE` without an active call session — try this only if Hybrid works for the first door. |
| **Standard** | `INVITE` to bring the call up, then `MESSAGE`, then `BYE`. Same flow as the official mobile app. | Most compatible. Adds ~1-2 seconds per unlock. Switch to this if Hybrid fails for any door on your gateway. |

If a door doesn't open with Hybrid, switch to **Standard** first; if every door
works with **Fast**, you can leave it there for the lowest-latency setup.

## Troubleshooting

- **"Cannot reach the gateway on port 5060"** — Home Assistant must be on the same
  LAN/VLAN as the gateway, and the gateway IP must be correct.
- **"Invalid portal credentials"** — the MyBuildings portal rejected the
  username or password.
- **"Gateway admin password is wrong"** — the local web admin login at
  `https://<gateway-ip>/` failed. Try logging in manually in a browser to confirm.
- **"The gateway did not see our pairing request"** — the connect event didn't
  arrive at the gateway in time. Try again; the gateway may have been busy or
  the portal-to-gateway link briefly down.
- **"The gateway rejected the integrity code"** — the cert-fingerprint algorithm
  drifted between gateway firmware and this integration. Please open an issue
  with the firmware version from the gateway's About page.
- **ACL polling timeout** — pairing completed on the gateway side but the
  configuration push did not arrive within ~3 minutes. Try again.
- **A door doesn't open** — switch the unlock strategy (Options → Configure) to
  **Standard** and try again. Only outdoor stations of `type=1` are exported as
  buttons.

## Tested hardware

- **ABB 83342 IP Gateway**, firmware `ASM04_GW_V6.25_20250513_MP_TIDM365`,
  system type `mrange`, 3 outdoor stations.

Reports of other models or firmware versions welcome via issues.

## License

MIT — see [LICENSE](LICENSE).
