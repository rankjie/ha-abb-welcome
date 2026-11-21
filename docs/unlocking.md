# Unlocking doors

Each door has a button entity. Press it from a dashboard or an automation:

```yaml
service: button.press
target:
  entity_id: button.abb_welcome_outdoor_1
```

## Unlock strategy

| Strategy | What it does | When to use |
|---|---|---|
| **Hybrid** *(web-admin default)* | Plain SIP `MESSAGE` for the physical default station, `INVITE`-then-`MESSAGE` for every other station. | App-managed devices require an explicit physical-default selection. Web-admin legacy entries retain their first-stored-door behavior. |
| **Fast** | Plain SIP `MESSAGE` without first establishing a targeted call. | Allowed for app-managed devices only when one unlockable door exists. It is blocked with multiple doors because the panel may ignore the requested target. |
| **Standard** *(app-managed default)* | TLS `INVITE` to bring the call up, then `MESSAGE`, then `BYE`. | Uses the required SIP-TLS port 5061 and avoids assuming port 5060 is available. Adds roughly 1-2 seconds per unlock. |

Second-lock buttons always establish a targeted call, send the MRANGE second-lock
command `a`, and hang up, including when Fast or Hybrid is selected. The first
lock keeps the selected strategy. Second-lock availability comes from the
gateway device list or the pairing ACL's `secondunlock` flag. Reload the
integration or run `abb_welcome.refresh_doors` after changing this setting on a
web-admin gateway; app-managed topology changes require re-pairing.

If a door does not open with Hybrid, switch to **Standard**. Do not use Fast to
test targeting on a multi-door app-managed device: the physical panel may
ignore the requested station and open its own default door.
The app-managed profile defaults to **Standard**. Its physical indoor-panel
default is not exposed by the protocol, so Home Assistant does not guess from
door-list order. To use Hybrid, first confirm which door the physical panel
opens by default and select that exact door in Configure. If the selected
station disappears after re-pairing or topology changes, every Hybrid unlock
falls back to Standard; another door is never selected silently.

## Door opener code

Some outdoor stations ignore the unlock `MESSAGE` and open only on a DTMF code
sent as SIP `INFO` (RFC 2976) inside a call with that station. The Smart
Access Point lists the codes on the outdoor station's **3rd party door opener
settings** page, one for the default lock and one for the subsidiary lock.

Enter them as **Door opener code** and **Second lock opener code**, either on
the last setup step (shown for `GlobalIP` panels such as the IP touch 7) or
later under **Configure**. A lock
with a code no longer uses the unlock strategy: its button sends the code in
the running live-view call with that station, or places a short call of its
own, sends the code and hangs up.

One code applies to every door of the entry. Outdoor stations configured with
different opener codes are not supported: only the stations whose code matches
the entered one will open.

These stations switch the relay without answering the `INFO`, so Home
Assistant reports the press as successful once the request is sent and not
rejected. It cannot tell whether the door opened. The codes are stored in the
config entry and redacted from diagnostics and logs.
