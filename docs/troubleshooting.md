# Troubleshooting

- **Cannot reach the gateway web admin on HTTPS port 443**: check the gateway IP
  and that Home Assistant can route to it.
- **Cannot reach SIP-TLS port 5061**: for an app-managed device, check its local
  IP, Wi-Fi connection, and routing from Home Assistant.
- **No ACL update after app pairing**: submit again to resend the pairing
  request. If the indoor station lists a pending app under System Settings ->
  APP Settings, approve it there. If the config-flow page disappears, start
  ABB Welcome setup again and choose the app-managed profile; Home Assistant
  offers to resume the saved identity, which resends the pairing request
  without creating another MyBuildings client.
- **Any setup failure**: the error page ends with a **Debug report** box holding
  the setup's DEBUG log with passwords, IPs, UUIDs and certificates redacted.
  Copy the whole box into a GitHub issue.
- **Invalid portal credentials**: the MyBuildings portal rejected the username or
  password.
- **Gateway admin password is wrong**: log into `https://<gateway-ip>/` manually
  as `admin` to confirm the password.
- **Could not read the gateway's portal UUID**: fill in **Gateway Portal UUID**
  manually and retry.
- **The gateway did not see our pairing request**: retry pairing; the
  portal-to-gateway link may have been briefly delayed.
- **A door does not open**: try **Standard** unlock strategy. If the panel
  accepts the request but the door stays locked, as on the IP touch 7 setup
  described in [Setup](setup.md#busch-jaeger-ip-touch-7), set the [door opener code](unlocking.md#door-opener-code).
- **The live view stops a few seconds after opening the door**: the gateway
  ends the call about five seconds after a door release and refuses new calls
  for a short while. This also happens on the physical indoor station. The
  integration waits 3 to 15 seconds before calling the gateway again, so a
  reopened stream may need a moment.
- **WebRTC says `wrong response on DESCRIBE`**: turn on `Streaming enabled` and
  open the camera within the armed window.
- **Camera has video but no audio**: confirm you are on a current version and
  that the stream includes the PCMA/G.711 audio track.
- **HomeKit has video but no microphone**: add the doorbells through the
  [Scrypted plugin][scrypted-bridge], not only through HA's native HomeKit
  bridge.
- **Apple TV opens a preview by itself**: configure Scrypted **HomeKit Pickup
  Safety**, enter the Apple TV/Home Hub fixed LAN IP, and keep
  Rebroadcast/Prebuffer disabled for ABB doorbells.
- **Scrypted cannot load stream after HA reload**: click **Refresh Discovery** in
  the Scrypted plugin, or check the camera `lan_rtsp_url` attribute.
- **WebRTC live stream works on local Wi-Fi but hangs or fails on mobile data (5G/4G)**:
  Mobile network carriers implement Carrier-Grade NAT (CGNAT) with symmetric NAT,
  which prevents direct STUN peer-to-peer negotiation. Configure an ICE TURN relay
  server (such as `coturn`) in `go2rtc.yaml` under `webrtc: ice_servers:` to allow
  media packets to relay smoothly.

[scrypted-bridge]: https://github.com/rankjie/abb-ha-doorbell
