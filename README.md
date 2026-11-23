# ABB Welcome for Home Assistant

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=rankjie&repository=ha-abb-welcome&category=integration)

Open the door, see who is ringing and talk to them, for ABB Welcome and
Busch-Jaeger door intercoms. Pairing uses your MyBuildings account once; after
that everything runs on your local network.

## What you get

- A **button** for each door, plus a second-lock button where the station has one.
- A **button** for each relay actuator on the gateway (web-admin setups).
- A **camera** for each door station, with live video and audio.
- A **talk button** in the live view.
- A **ringing sensor** and an event the moment someone presses the doorbell.
- The **latest visitor snapshot** and a history of rings, calls and door openings.
- **Apple Home** doorbells through the companion [Scrypted plugin][scrypted-bridge].

## What you need

- One of these devices on your network:
  - an ABB 83342 IP gateway, or another IP gateway with a web admin page
  - an M2240x Wi-Fi indoor station
  - a Busch-Jaeger IP touch panel
- A MyBuildings account that already works with this device in the ABB Welcome app.
- For an IP gateway, its web admin password.

The models and firmware versions tested so far are listed in
[Setup and pairing](docs/setup.md#tested-hardware).

## Install

1. Click the badge above, or open HACS → **Custom repositories** and add
   `https://github.com/rankjie/ha-abb-welcome` as an *Integration*.
2. Install **ABB Welcome** and restart Home Assistant.

Without HACS, copy `custom_components/abb_welcome/` into your
`config/custom_components/` folder and restart.

## Set up

Open Settings → **Devices & Services** → **Add Integration** → **ABB Welcome**.

1. Choose your device type: an IP gateway with web admin, or an app-managed
   indoor station (M2240x, IP touch).
2. Enter your MyBuildings username and password and the device's local IP
   address. An IP gateway also asks for its web admin password.
3. Wait for pairing. A gateway takes about 15 seconds, an indoor station up to
   90 seconds.

If setup fails, the error page ends with a **Debug report** box. Paste it into a
[GitHub issue](https://github.com/rankjie/ha-abb-welcome/issues). More detail,
including notes for the IP touch 7, is in [Setup and pairing](docs/setup.md).

## Use it

### Open a door

Press the door's button entity. If the door stays locked, see
[Unlocking doors](docs/unlocking.md).

### Watch the camera

The intercom carries one call at a time, and a live view is a call to the door
station. So the camera only starts when you allow it:

1. Turn on the **Streaming enabled** switch. It stays on for 3 minutes.
2. Open the camera.

Turning the switch off ends the call.

### When someone rings

The ringing sensor turns on, and the camera for that door is unlocked for 2
minutes without touching the switch.

- Opening the camera **answers the call**: the indoor stations stop ringing.
- To watch first and let the others keep ringing, turn on **Preview a ringing
  call without answering** in the integration options. The call is then
  answered when you start talking.
- To keep Home Assistant from ever taking a ringing call, turn off the **Allow
  pickup** switch.

### Talk

The live view has a talk button on Home Assistant 2026.11 or newer:

1. Turn on Settings → System → Labs → **Two-way audio**.
2. Open Home Assistant over HTTPS. Browsers only allow the microphone on a
   secure connection.

## Apple Home

Use the [ABB HA Doorbell Scrypted plugin][scrypted-bridge]. It adds each door
station to Apple Home as a doorbell with notifications, live video, two-way
audio and a lock. Home Assistant's own HomeKit bridge only gives you a one-way
camera. Setup steps are in [Apple Home](docs/apple-home.md).

## Options

Open the integration's **Configure** menu.

| Option | What it does |
|---|---|
| Unlock strategy | How the door is opened. Change it if a door stays locked. |
| Door opener code, Second lock opener code | For stations that open only on a code. |
| Physical default door | The door your indoor panel opens by default. Needed for the Hybrid strategy on app-managed devices. |
| Serve camera streams to the LAN over RTSP | Needed for Scrypted. Turn it off if you do not use it. |
| Advertised LAN host, Preferred RTSP port | Leave as they are unless Scrypted cannot reach the stream. |
| Allow pickup from streams | Whether opening the camera may take a ringing call. |
| Preview a ringing call without answering | Watch a ring without answering it. Off by default. |
| Show the last station screenshot as the camera still image | Turn it off if you do not want an old screenshot shown while the live view connects. The Apple Home doorbell snapshot uses this image too. |

## Something not working?

- **The camera shows an error instead of video**: turn on **Streaming enabled**
  first, then open the camera.
- **A door does not open**: switch the unlock strategy to **Standard**. If it
  still stays locked, your station may need a
  [door opener code](docs/unlocking.md#door-opener-code).
- **The live view stops a few seconds after opening the door**: the intercom
  ends the call after a door release. Reopen the camera after a moment.
- **Video works at home but not on mobile data**: your go2rtc needs a TURN
  server.
- **Apple Home has video but no microphone**: add the doorbell through the
  Scrypted plugin, not Home Assistant's HomeKit bridge.

The full list is in [Troubleshooting](docs/troubleshooting.md).

## More

- [Setup and pairing](docs/setup.md)
- [Calls and streaming](docs/calls.md)
- [Unlocking doors](docs/unlocking.md)
- [Apple Home](docs/apple-home.md)
- [Example dashboard and automations](docs/examples.md)
- [Entities, services and events](docs/reference.md)
- [Troubleshooting](docs/troubleshooting.md)

## License

MIT - see [LICENSE](LICENSE).

[scrypted-bridge]: https://github.com/rankjie/abb-ha-doorbell
