# Setup and pairing

The short version is in the [README](../README.md#set-up). This page has the details.

## Device profiles

- **Web-admin IP gateway (83342 / MRANGE)** keeps the existing HTTPS/CGI setup.
- **App-managed indoor station (M2240x / ASI22, IP touch)** uses SIP-TLS port
  5061 and MyBuildings app pairing; it never contacts port 443
  or asks for a gateway admin password.

## What to enter

- MyBuildings portal **username**
- MyBuildings portal **password**
- Gateway local **IP address**
- Gateway **web admin password** (web-admin profile only)
- Gateway **Portal UUID** (optional)

Optional: if neither the local `portalclient.cgi` endpoint nor the MyBuildings
discovery list gives the gateway UUID, fill in **Gateway Portal UUID** from the
gateway web admin Portal page or ABB Welcome mobile app, then retry.

## What pairing does

Both profiles:

1. Determine the gateway UUID before anything is registered on MyBuildings.
2. Generate a fresh RSA keypair and request a client certificate from the
   MyBuildings portal. Each certificate appears as an `ha-*` client, so a retry
   in the same setup dialog with the same portal account reuses it.
3. Compute the gateway integrity code from the certificate fingerprint.
4. Send a `welcome.connect` event so the device sees a pending pairing.
5. Poll for the gateway ACL update, decrypt the SIP password, read the door
   list, and create HA entities.

The setup dialog shows which stage is running and counts the ACL checks.

For a web-admin gateway, setup reads the gateway UUID from its CGI (unless an
override was supplied), then logs into the CGI to approve the pending client.
If the CGI returns no UUID, setup takes the IP gateway listed in the MyBuildings
discovery list, or asks you to choose when the account has several.

The gateway remembers the address of the most recent web admin login and
refuses CGI requests sent from any other address. Each integration login, at
setup and whenever it refreshes the door list, sets that address to
`https://<configured gateway address>/`. A web admin tab open under a different
address (`http://` or another hostname) then stops loading data until you log in
again in the browser.

For an app-managed device, setup reads the MyBuildings discovery list with the
new certificate and sends the pairing request to the gateway or Wi-Fi indoor
station listed there, the same way the official app picks its target. An entered
Portal UUID is used when it is in that list. If it is not, and the account has
exactly one device, that device is used instead. With several devices, setup
lists them and asks for one. Setup never calls the local CGI.

A successful web-admin pairing typically completes in under 15 seconds.

For an app-managed device, the integration creates one `ha-*` client, persists
the identity, and waits about 90 seconds for the ACL update. It alternates the
plain ACL query with the query the official app uses for Wi-Fi indoor stations.
M2240x/ASI22 additional apps normally pair automatically when they use the same
MyBuildings account; the M22403-W has no approval screen on the panel. If no
ACL arrives, the dialog shows the client name and integrity code, and **Submit**
sends the pairing request again with the same identity before checking for
another round. An `ha-*` client shown as active in MyBuildings only has a
certificate; it is paired once the device has sent its ACL.

The pending private identity is stored in Home Assistant's private storage. A
later config flow can resume the same certificate, client identity, and
`welcome.connect` request after a browser reload or Home Assistant restart; it
does not consume another client slot. MyBuildings credentials are used only for
the initial certificate request and the password is not stored. The recovery
screen also provides an explicitly confirmed discard path for clients that have
already been removed/unpaired.

## Busch-Jaeger IP touch 7

For a **Busch-Jaeger IP touch 7** (firmware 3.08) with a Smart Access Point
(V6.66), enter the **touch panel's IP address** in the app-managed profile.
The owner verified pairing, ring detection and live video with
`v1.8.0-dev4`. The panel identifies itself as `GlobalIP` and explicitly
grants HA permission to open the door. [Pairing diagnostics](https://github.com/rankjie/ha-abb-welcome/issues/45#issuecomment-6985603402)

This panel acknowledges the unlock `MESSAGE` of every unlock strategy but
leaves the door locked. It needs the **Door opener code** instead (see
[Door opener code](unlocking.md#door-opener-code)); setup asks for it on the last step
when the panel reports `GlobalIP`. With `v1.8.0-dev6` the owner opened
the primary lock (the outdoor station's Lock-GND output) both during an HA
live view and with no live view open. The subsidiary relay has not been
tested on the device. [Field results](https://github.com/rankjie/ha-abb-welcome/issues/45#issuecomment-7007694606)

On this installation, enabling the Smart AP's SIP server interrupted calls
from the H81381P1-S-03 outdoor station to the indoor panel. Keep it off for
this pairing. [Hardware test results](https://github.com/rankjie/ha-abb-welcome/issues/45#issuecomment-6985197643)

## Checking the door-opening permission

For an app-managed entry, **Download diagnostics** checks the latest retained
pairing record for the panel's system type and this HA client's door-opening
permission. Only share the `pairing_acl` section. A missing record or an
unknown permission leaves the grant unconfirmed.

## Tested hardware

- **ABB 83342 IP Gateway**, firmware `ASM04_GW_V6.25_20250513_MP_TIDM365`,
  system type `mrange`, 3 outdoor stations.
- **ABB M22403-W Wi-Fi indoor station**, firmware
  `ASI22_V1.23_20251225_PP_IMX6SOLO`, system type `ASI22`, 2 outdoor stations.
  Validated with automatic MyBuildings app pairing and recovery, SIP-TLS
  registration after restart, per-station ring detection and unlock, H.264
  video, PCMA/G.711 audio, portal history and screenshots, call pickup, and
  two-way talkback. App-managed door topology refresh remains the documented
  exception and requires re-pairing.
- **Busch-Jaeger IP touch 7**, firmware 3.08, system type `GlobalIP`, behind a
  Smart Access Point V6.66 with one **H81381P1-S-03** outdoor station. Validated
  by its owner with app pairing, ring detection, live video and unlocking the
  primary lock with the door opener code.

Reports for other models and firmware versions are welcome.
