# ABB Welcome — Home Assistant integration

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=rankjie&repository=ha-abb-welcome&category=integration)

Local controls and live camera streams for ABB Welcome / Busch-Jaeger building
intercoms backed by an **IP gateway** (system type `mrange`).

This integration is LAN-first: pairing goes through the ABB MyBuildings cloud portal
once, and from then on unlocks, realtime ring detection, and live intercom streams
run directly against your gateway on the local network. Door unlocks typically
complete in well under 100 ms.

## Features

- One Home Assistant **button entity per outdoor station** (Outdoor 1 / Inner / Parking, etc.).
- **WebRTC camera entities** for discovered outdoor stations, backed by HA's bundled go2rtc.
- **LAN H.264 video + PCMA/G.711 audio** for live intercom streams. Audio is the door-station microphone downlink; two-way talkback is not implemented in this integration yet.
- **Streaming enabled switch** to explicitly arm live streaming. Intercom video/audio is building-wide exclusive, so streams do not start accidentally from frontend prefetches or HomeKit probes.
- **Auto-arm on ring** — when the SIP listener sees an incoming doorbell INVITE, streaming is enabled briefly so opening the camera from the notification can start immediately.
- **Image entity** with the latest doorbell screenshot. The gateway only captures a frame when someone rings, so `image_last_updated` reflects the actual ring time, not a polling timestamp.
- **Realtime ring binary_sensor** — passively listens on the gateway's local SIP port and fires within tens of milliseconds of someone pressing the doorbell. Also emits an `abb_welcome_ring` event on the HA bus with caller URI, call id, station id, and configured station name for automations. Does not interfere with the indoor stations or the official ABB app.
- **Refresh Events** button — forces a portal poll if you don't want to wait for the next 30 s tick.
- **Event entity** + **last-event sensor** for ring / call / door-open history, including event ids, timestamps, sender, call grouping id, payload text, and station details when the gateway/cloud event provides them.
- LAN-only runtime for unlocks, ring detection, and live streams after pairing.
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

All entities share a single device entry.

The integration also creates:

- `camera.<gateway>_<door_name>` — live intercom stream for each discovered station.
- `switch.<gateway>_streaming_enabled` — arms streaming for a short window; switching it off tears down any active stream.
- `binary_sensor.<gateway>_intercom_ringing` — turns on briefly when a SIP INVITE/ring is observed.
- `image.<gateway>_latest_screenshot` — latest gateway screenshot from the portal event history.
- `event.<gateway>_intercom` — event entity for ring / call / door-open history.
- `sensor.<gateway>_last_event` — latest non-screenshot portal event with detailed attributes.
- `sensor.<gateway>_sip_listener` — diagnostic state for the realtime SIP listener.

### Live camera streams

Live camera streams are intentionally gated because opening an ABB intercom media
session can lock the building intercom while the call is active.

To view a stream manually:

1. Turn on `switch.<gateway>_streaming_enabled`.
2. Open the desired `camera.<gateway>_<door_name>` within the armed window.
3. The integration dials the gateway locally and passes H.264 video plus PCMA audio to HA/go2rtc/WebRTC.

When someone rings, the integration auto-arms streaming for a short window so a
camera opened from the ring notification can start without a separate manual step.

Current media support is one-way: door station → Home Assistant/browser video and
audio. Browser/HomeKit talkback is not supported yet.

### Realtime ring event payload

Every incoming SIP ring fires `abb_welcome_ring` on the Home Assistant event bus.
The payload includes both raw SIP caller fields and configured door mapping:

```json
{
  "caller_uri": "sip:100000001@ipgw6cce7a2bb673;user=phone",
  "caller_user": "100000001",
  "station_id": "100000001",
  "station": "Outdoor 1",
  "station_name": "Outdoor 1",
  "call_id": "1293890397@192.168.178.112",
  "received_at": 1777723346.1623127
}
```

Example automation condition:

```yaml
condition:
  - condition: template
    value_template: "{{ trigger.event.data.station_id == '100000001' }}"
```

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

- **"Cannot reach the gateway"** — Home Assistant must be on the same LAN/VLAN as the gateway, and the gateway IP must be correct. Unlocks use local SIP, while realtime ring detection and live streaming use the gateway's local SIP/TLS listener.
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
- **WebRTC says `wrong response on DESCRIBE`** — make sure `Streaming enabled` is on, then open the camera within the armed window. Version 1.3.0+ also reconnects the SIP dialer automatically if the gateway has closed an idle TLS connection.
- **Camera has video but no audio** — use version 1.2.0-dev15 / 1.3.0 or newer. The stream exposes the gateway's PCMA/G.711 audio track through go2rtc/WebRTC.
- **The camera stops after a short time** — this is expected if the stream consumer closes or the armed switch is turned off. Streaming is deliberately short-lived to avoid holding the building intercom media session open.

## Tested hardware

- **ABB 83342 IP Gateway**, firmware `ASM04_GW_V6.25_20250513_MP_TIDM365`,
  system type `mrange`, 3 outdoor stations.

Reports of other models or firmware versions welcome via issues.

## License

MIT — see [LICENSE](LICENSE).
