# Reference

## Entities

The integration creates one HA device for the gateway.

For each unlock-capable outdoor station:

- `button.<gateway>_<door_name>` - unlocks that station.
- `camera.<gateway>_<door_name>` - live intercom stream for that station.

Gateway-level entities:

- `switch.<gateway>_streaming_enabled` - arms stream startup for a short window.
  Turning it off tears down active streams/calls.
- `switch.<gateway>_allow_pickup` - allows or refuses incoming-call pickup.
- `binary_sensor.<gateway>_intercom_ringing` - turns on briefly when a SIP ring
  is observed.
- `image.<gateway>_latest_screenshot` - latest gateway screenshot from event
  history.
- `event.<gateway>_intercom` - ring / call / door-open event entity.
- `sensor.<gateway>_last_event` - latest non-screenshot portal event.
- `sensor.<gateway>_sip_listener` - diagnostic state for the realtime SIP
  listener.
- `button.<gateway>_refresh_events` - manually poll portal event history.

## Services

- `abb_welcome.refresh_doors` - re-read outdoor stations from a web-admin
  gateway and reload the entry if the list changed. App-managed devices return
  an unsupported error; re-pair after topology changes.
- `abb_welcome.arm_streaming` - arm streaming for all stations or one
  `station_id`. A client that provides an `entry_id`, `station_id` and
  a unique `owner_token` gets its own bounded lease. With the same fields,
  `renew: true` extends only an active lease and `release: true` removes
  only that lease. Clients can borrow an existing compatible ring or switch
  window without extending or releasing it. Calls without a token retain
  their original behavior.
- `abb_welcome.talk_start` - start sending queued microphone audio on the active
  stream.
- `abb_welcome.talk_stop` - stop voice audio and return the talkback leg to
  silence.
- `abb_welcome.talk_pcm16le` - queue base64 PCM16LE microphone audio.
- `abb_welcome.talk_tone` - send a short generated tone for testing.
- `abb_welcome.export_credentials` - export stored SIP/gateway credentials to a
  JSON file for local debugging. This output contains secrets. Admin users
  only; the file must be inside the config directory but not in `www/`, and
  is written with owner-only (0600) permissions.
- `abb_welcome.diagnose_messages` - temporarily publish sanitized inbound SIP
  MESSAGE bodies for protocol investigation. Disabled by default; accepts an
  optional `entry_id` and a `duration` of 0–600 seconds (default 300). Zero stops
  diagnostics, and an integration reload clears the window.
- `abb_welcome.talk_audio_file` - play an 8 kHz mono 16-bit PCM WAV file
  through the door station. See [Examples](examples.md).

## Ring event

Every incoming SIP ring fires `abb_welcome_ring` on the Home Assistant event bus.

Example payload:

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

Automation example:

```yaml
condition:
  - condition: template
    value_template: "{{ trigger.event.data.station_id == '100000001' }}"
```

## SIP MESSAGE diagnostics

To investigate physical programmable buttons, open **Developer Tools → Events**
and start listening to `abb_welcome_sip_message`. Then run this action in
**Developer Tools → Actions**:

```yaml
action: abb_welcome.diagnose_messages
data:
  duration: 300
```

Press the configured physical button several times, with a few seconds between
presses. Record the press times and the resulting events. Compare different
unused actuator addresses and both buttons. Supplying `entry_id` restricts the
diagnostic window to that integration entry.

Each event contains `entry_id`, `received_at`, `body_bytes`, `body_format`,
`body_redacted`, and a sanitized `body` string. Known SIP commands and supported
button parameters, such as button ID, function and actuator address, remain
readable. Private fields, unknown values and unknown JSON field names are
masked; an unrecognized text body may therefore show only `<redacted>`.
Binary bodies and bodies larger than 4096 bytes are omitted. SIP headers,
authentication data and media keys are not published.

For example, an inbound camera-count MESSAGE produces:

```json
{
  "entry_id": "your-entry-id",
  "received_at": 1791028800.0,
  "body_bytes": 3,
  "body_format": "text",
  "body_redacted": false,
  "body": "c:2"
}
```

This observes messages delivered to the integration's SIP client. It does not
guarantee that the panel sends physical button actions to that client. Confirm
normal doorbell reception before interpreting an empty diagnostic window. The
event is for temporary diagnosis; physical programmable-button automations are
not yet supported.
