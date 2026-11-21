# Calls and streaming

## Streaming

ABB intercom media is exclusive, so live streams are gated.

Manual stream:

1. Turn on `switch.<gateway>_streaming_enabled`.
2. Open the desired `camera.<gateway>_<door_name>` within the armed window.
3. HA dials the selected station and passes H.264 video plus PCMA/G.711 audio to
   go2rtc/WebRTC and to Scrypted/HomeKit.

Turning off `switch.<gateway>_streaming_enabled` immediately disarms streaming
and closes active stream sessions.

The switch exposes useful attributes:

- `reason`: why streaming is armed (`manual`, `ring`, etc.).
- `target_station_id`: station id allowed during a ring-scoped arm.
- `remaining_seconds`: time left in the arm window.

You can also arm streaming from an automation:

```yaml
service: abb_welcome.arm_streaming
data:
  station_id: "100000001"
  duration: 60
```

## Allow pickup

`switch.<gateway>_allow_pickup` controls whether HA/Scrypted/HomeKit may answer
an incoming ringing call.

- **On**: an incoming ring arms streaming for that station. Opening the matching
  camera from HomeKit can pick up the ringing call.
- **Off**: an incoming ring force-disarms streaming. HA still reports the ring,
  but it refuses HomeKit/Scrypted pickup so phones and indoor stations can
  answer safely.

This is independent from manual proactive streaming. You can still turn on
`Streaming enabled` and open a camera outside a ring.

## Preview before answering

By default, opening the camera during a ring answers the call: the indoor
stations stop ringing and nobody else can pick up. With the option **Preview a
ringing call without answering** turned on, opening the camera only previews
the ring, the way the ABB Welcome app does:

- Video (and the visitor's audio, if the station sends it) arrives while every
  other station keeps ringing and can still answer.
- Talking answers the call: the live-stream microphone, `talk_start`,
  `talk_pcm16le`, `talk_tone` or `talk_audio_file`.
- While previewing, the camera reports `previewing: true`, and
  `talkback_ready: true` because talking can start at any time.
- The camera's `preview_before_answer` attribute tells whether the option is
  on.
- The preview lasts as long as the ring, also when no viewer is left, so the
  stream can be reopened. If another station answers or the ring times out, the
  stream closes and the ring's streaming window ends.

This only applies to a ringing call. Opening the camera outside a ring still
places a call to the door station.

## Talkback

### Microphone in the live stream

On Home Assistant 2026.11 or newer the camera declares two-way audio, so the
live stream shows a talk button:

1. Turn on **Settings → System → Labs → Two-way audio**.
2. Open Home Assistant over HTTPS. Browsers only grant microphone access on a
   secure connection.

The microphone travels over the same WebRTC session as the video. go2rtc hands
it to the integration's RTSP server as an ONVIF audio backchannel (PCMA, no
transcoding), so go2rtc-based cards with their own microphone button work the
same way.

### Services

HA also exposes talkback as services for the currently active stream. These
services are mainly intended for the Scrypted plugin. A service call that names
a `talkback_session_id` takes the talk over from the live-stream microphone
until it calls `talk_stop`.

- `abb_welcome.talk_start`
- `abb_welcome.talk_stop`
- `abb_welcome.talk_pcm16le`
- `abb_welcome.talk_tone`

The audio format for `talk_pcm16le` is base64-encoded 8 kHz mono signed 16-bit
little-endian PCM. HA converts it to continuous PCMA/G.711 A-law RTP on the
active call's audio leg. Idle talkback sends silence continuously, and voice
frames are queued into the same RTP sequence.

Scrypted assigns a per-client `talkback_session_id` so stale clients cannot stop
or overwrite a newer microphone session.
