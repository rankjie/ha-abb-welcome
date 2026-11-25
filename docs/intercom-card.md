# ABB Welcome Intercom card

The ABB Welcome Intercom card is a Lovelace custom card for an ABB Welcome
camera. It provides user-initiated live video, optional street audio,
press-and-hold talkback, ringing indication, and a separately confirmed door
unlock action. The expandable call history is independent of Live.

## Configure the card

The integration registers the card when an ABB config entry loads. Refresh the
dashboard, add **ABB Welcome Intercom**, and choose an ABB camera. The editor
offers an optional title, unlock button, ring sensor and station identifier.
The browser console logs the loaded card version.

Home Assistant loads the card's module (about 2,500 lines of JavaScript) on
every dashboard page for every user while an ABB Welcome entry is loaded,
whether or not a dashboard uses the card.

The card's text is in English and Italian. Every other Home Assistant
language shows the English text.

The automatic suggestions use the integration's entity metadata to avoid
guessing across stations. An explicit `unlock_button` override is intentional:
use it only when the selected button is the door action that belongs to this
card. The confirmation dialog shows the chosen target before it sends the
button press.

If the integration exposes both primary and second-lock buttons for the same station,
automatic discovery intentionally makes no ambiguous choice. Set
`unlock_button` explicitly to the intended lock; this card controls one chosen
lock button at a time.

Example YAML:

```yaml
type: custom:abb-welcome-intercom-card
camera: camera.entry_intercom
name: Entry intercom
unlock_button: button.entry_unlock
ring_sensor: binary_sensor.entry_ringing
```

Entity ids in the example are placeholders. Select entities from the local
installation rather than copying them unchanged.

## Live video and audio

Select the black video area or **Live** to start. The video area is also a
keyboard-accessible button. Opening the dashboard does not request a camera
stream or microphone. **Stop** is always available while a live request,
connection, or playback is active.

The video area reports these states in plain language:

- `connecting`: the live request is being prepared;
- `waiting for video`: negotiation may still be in progress and no first frame
  is available yet;
- `playing`: video is rendering;
- `buffering`: playback has stalled after it began;
- `paused`: local playback was paused;
- `playback blocked`: the browser prevented playback and needs a user gesture;
- `error`: live video could not be established or has timed out.

The initial connection waits up to 15 seconds for a first frame. Once playback
has started, a 10-second stall is treated as an error. These are UI safety
boundaries, not evidence that a physical station or its network is healthy.

Live holds its station open through a Home Assistant websocket subscription
(`abb_welcome/live`) for as long as it runs, with no time limit. **Stop**,
closing the dashboard, or losing the connection to Home Assistant releases the
station. Live ends with a message when the door station hangs up the call,
which ABB stations do on their own call timeout, or when a ring or
**Streaming enabled** window that Live was using closes. Press **Live** to
call the station again.

Street audio is controlled by the speaker button and is independent from the
microphone. The speaker may be turned on or off without changing talkback.

During a ring, the integration's **Preview a ringing call without answering**
option also applies to this card. With it enabled, opening Live previews the
visitor and starting talkback answers the call. With it disabled, opening Live
can answer, subject to the integration's pickup settings.

Live video can still be useful on HTTP, but browser microphone capture normally
requires HTTPS. On HTTP the card keeps live video available and explains the
microphone restriction. To talk, open Home Assistant at a trusted HTTPS address
such as Nabu Casa, then allow microphone access when prompted.

## Push to talk

Start Live before holding **Talk**. Hold the button with a pointer, Space, or
Enter to speak; releasing stops the microphone and detaches its track while
the same live video and listening session continue. Releasing
outside the button, moving keyboard focus away, leaving the page, hiding the
document, disconnecting Home Assistant, or stopping Live also terminates the
hold. This is deliberately fail-safe: the microphone is not kept warm in the
background.

The card uses Home Assistant's native two-way WebRTC audio. For a camera with
the ABB RTSP backchannel enabled, HA can route the microphone through go2rtc
to the intercom. No audio is captured before the first hold. **Microphone on**
means the browser attached a track; it does not prove that the visitor heard
it. A permission denial or microphone error stays shown after you release
Talk and can be retried on a later hold. If the camera or HA
cannot negotiate a microphone channel, Live and listening still work, but Talk
is unavailable. The card does not fall back to the ABB PCM services.
Set `native_talkback: false` in the card YAML to disable the microphone control.

## Unlock confirmation

Unlock is a two-step operation. Select **Unlock**, review the explicit target
in the confirmation prompt, then select **Open**. The initial focus moves to
**Cancel**, so a keyboard user has a safe default action. **Cancel**, Escape,
and the 30-second confirmation timeout return focus to the original Unlock
control only when the user has not already moved focus elsewhere. A successful
busy operation does not take focus away from the user's current control.

Do not retry after an uncertain result: an interrupted service response may
still have operated the door. Verify the physical result before taking another
action.

## Call history

Expand **Call history** to see up to 20 recent rings from the ABB portal for
the selected camera's gateway. The card does not load history while collapsed
or open a live stream. Linked photos appear inline as the rows come into view;
turn off **Screenshots** at the top to hide them all and stop pending image reads.
A ring can have an unknown outcome, no photo, or several photos. The integration
uses only explicit ABB event links. If the portal times out while looking up
photos, the card shows the partial result with **Refresh history** available
to try again. This is the portal's recent history, not a Home Assistant archive.

Browsing history requires read access to the selected camera and its ABB
event entity. Loading the photo linked to a call additionally requires read
access to the gateway's image entity. Home Assistant keeps recent row metadata
in memory for up to five minutes so a dashboard refresh can show it, with an
indicator while fetching an update. These cached rows contain no photo bytes.
Photo requests are authenticated separately; closing history or hiding photos
clears the displayed images from the card.

## Accessibility and narrow layouts

All controls retain keyboard focus indicators and reachable names. On narrow
screens the title wraps before the header controls overlap. The confirmation controls wrap for
narrow mobile widths rather than overflowing the card.

## Tests

Run the Home Assistant service and backend fixtures with `python -m pytest -q`
and the card tests with `node --test tests/frontend/*.test.mjs`. The card
fixtures exercise WebRTC signaling, microphone lifecycle, entity discovery,
keyboard controls and unlock confirmation with simulated browser and HA APIs.
