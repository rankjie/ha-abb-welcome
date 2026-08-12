"""ABB per-media SDP negotiation and RTP AES framing tests."""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
import socket
import struct
import sys
import time
import types
from pathlib import Path

import pytest

_PKG_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "abb_welcome"


def _load(name: str) -> types.ModuleType:
    pkg = sys.modules.setdefault("abb_welcome", types.ModuleType("abb_welcome"))
    pkg.__path__ = [str(_PKG_DIR)]
    full = f"abb_welcome.{name}"
    if full not in sys.modules:
        spec = importlib.util.spec_from_file_location(full, _PKG_DIR / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[full] = module
        spec.loader.exec_module(module)
    return sys.modules[full]


intercom = _load("intercom_dialer")
media = _load("media_pipeline")
sip_listener = _load("sip_listener")
redaction = _load("redaction")

_AUDIO_KEY = b"audio-key-16byte"
_VIDEO_KEY = b"video-key-16byte"
_LOCAL_AUDIO_KEY = b"localAudioKey123"
_LOCAL_VIDEO_KEY = b"localVideoKey123"


def _rtp(payload: bytes, *, pt: int = 102) -> bytes:
    return struct.pack("!BBHII", 0x80, pt, 1, 9000, 1234) + payload


def _rtp_with_all_header_options(payload: bytes) -> bytes:
    header = struct.pack("!BBHII", 0xB1, 102, 1, 9000, 1234)
    csrc = struct.pack("!I", 5678)
    extension = struct.pack("!HHI", 0xBEDE, 1, 0x11223344)
    padding = b"\x00\x00\x00\x04"
    return header + csrc + extension + payload + padding


def test_parse_sdp_preserves_separate_hidden_media_keys() -> None:
    audio_encoded = base64.b64encode(_AUDIO_KEY).decode()
    video_encoded = base64.b64encode(_VIDEO_KEY).decode()
    parsed = intercom.parse_sdp(
        "v=0\r\n"
        "c=IN IP4 192.0.2.10\r\n"
        "m=audio 5004 RTP/AVP 8\r\n"
        f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{audio_encoded}|2^20\r\n"
        "m=video 5006 RTP/AVPF 102\r\n"
        f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{video_encoded}\r\n",
        custom_media_crypto=True,
    )

    audio, video = parsed.medias
    assert (audio.abb_encrypt, audio.abb_encrypt_key) == (True, _AUDIO_KEY)
    assert (video.abb_encrypt, video.abb_encrypt_key) == (True, _VIDEO_KEY)
    assert parsed.crypto_attribute_count == 2
    assert audio.crypto_tag == video.crypto_tag == 1
    assert audio.crypto_suite == "AES_CM_128_HMAC_SHA1_80"
    assert _AUDIO_KEY.decode() not in repr(audio)
    assert _VIDEO_KEY.decode() not in repr(video)


def test_app_managed_offer_advertises_fresh_hidden_local_keys() -> None:
    generated = intercom.generate_media_encryption_keys()
    assert len(generated.audio) == len(generated.video) == 16
    assert generated.audio != generated.video
    assert all(0x20 <= byte < 0x7F for byte in generated.audio + generated.video)
    assert generated.audio.decode() not in repr(generated)
    assert generated.video.decode() not in repr(generated)

    local = intercom.MediaEncryptionKeys(
        audio=_LOCAL_AUDIO_KEY,
        video=_LOCAL_VIDEO_KEY,
    )
    offer = intercom._build_offer_sdp("192.0.2.20", 6000, 6002, "client", local)
    parsed = intercom.parse_sdp(offer, custom_media_crypto=True)

    assert offer.count("a=crypto:1 AES_CM_128_HMAC_SHA1_32 inline:") == 2
    assert parsed.medias[0].crypto_inline_key == _LOCAL_AUDIO_KEY
    assert parsed.medias[1].crypto_inline_key == _LOCAL_VIDEO_KEY

    call = intercom.CallState(
        door=intercom.Door("door", "sip:door@example.invalid"),
        call_id="test-call",
        local_tag="local",
        remote_tag="remote",
        invite_cseq=1,
        request_uri="sip:door@example.invalid",
        remote_contact="sip:door@example.invalid",
        audio_local_port=6000,
        video_local_port=6002,
        answer=parsed,
        local_send_keys=local,
    )
    assert _LOCAL_AUDIO_KEY.decode() not in repr(call)
    assert _LOCAL_VIDEO_KEY.decode() not in repr(call)


def test_crypto_is_inert_for_web_admin_and_secure_rtp_profiles() -> None:
    encoded = base64.b64encode(_VIDEO_KEY).decode()
    body = (
        "c=IN IP4 192.0.2.10\r\n"
        "m=video 5006 RTP/AVPF 102\r\n"
        f"a=crypto:1 SUITE inline:{encoded}\r\n"
    )
    web = intercom.parse_sdp(body)
    assert web.crypto_attribute_count == 1
    assert web.medias[0].crypto_tag is None
    assert web.medias[0].abb_encrypt is False

    secure = intercom.parse_sdp(
        body.replace("RTP/AVPF", "RTP/SAVPF"), custom_media_crypto=True
    )
    assert secure.medias[0].crypto_tag == 1
    assert secure.medias[0].abb_encrypt is False
    assert secure.medias[0].abb_encrypt_key == b""


@pytest.mark.parametrize(
    "inline_value",
    (
        "not!base64",
        base64.b64encode(b"short").decode(),
        base64.b64encode(b"key-with-null-\x00xx").decode(),
    ),
)
def test_app_managed_crypto_rejects_invalid_inline_keys(inline_value: str) -> None:
    body = (
        "c=IN IP4 192.0.2.10\r\n"
        "m=video 5006 RTP/AVPF 102\r\n"
        f"a=crypto:1 SUITE inline:{inline_value}\r\n"
    )

    with pytest.raises(ValueError, match="invalid SDP crypto"):
        intercom.parse_sdp(body, custom_media_crypto=True)
    # The compatibility path does not reinterpret standard SDP crypto.
    assert intercom.parse_sdp(body).medias[0].abb_encrypt is False


def test_app_managed_crypto_rejects_ambiguous_duplicate_attributes() -> None:
    encoded = base64.b64encode(_VIDEO_KEY).decode()
    body = (
        "c=IN IP4 192.0.2.10\r\n"
        "m=video 5006 RTP/AVPF 102\r\n"
        f"a=crypto:1 SUITE inline:{encoded}\r\n"
        f"a=crypto:1 SUITE inline:{encoded}\r\n"
    )

    with pytest.raises(ValueError, match="multiple SDP crypto attributes"):
        intercom.parse_sdp(body, custom_media_crypto=True)


def test_aes_ecb_known_vector_and_framing_roundtrip() -> None:
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    packet = _rtp(plaintext)

    encrypted = media._encrypt_rtp_payload(packet, key)

    assert encrypted[:12] == packet[:12]
    assert encrypted[12:14] == b"\x00\x10"
    assert encrypted[14:] == bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert media._decrypt_rtp_payload(encrypted, key) == packet


def test_encryption_honors_csrc_extensions_and_rtp_padding() -> None:
    packet = _rtp_with_all_header_options(b"plain-media-payload")
    encrypted = media._encrypt_rtp_payload(packet, _VIDEO_KEY)

    assert encrypted[:24] == packet[:24]
    assert encrypted[-4:] == packet[-4:]
    assert media._decrypt_rtp_payload(encrypted, _VIDEO_KEY) == packet


def test_invalid_keys_and_malformed_encrypted_payloads_are_rejected() -> None:
    description = intercom.MediaDescription(
        "video",
        5004,
        "RTP/AVP",
        abb_encrypt=True,
        abb_encrypt_key=b"too-short",
    )
    with pytest.raises(ValueError, match="invalid ABB media encryption key length"):
        media._media_encryption_key(description)
    with pytest.raises(ValueError, match="malformed RTP"):
        media._encrypt_rtp_payload(b"short", _VIDEO_KEY)
    with pytest.raises(ValueError, match="malformed ABB encrypted"):
        media._decrypt_rtp_payload(_rtp(b"\x00\x01bad"), _VIDEO_KEY)

    # A valid AES block whose advertised plaintext length leaves non-zero
    # bytes in the zero-padding region must not be accepted.
    framed = bytearray(media._encrypt_rtp_payload(_rtp(b"A" * 16), _VIDEO_KEY))
    framed[12:14] = b"\x00\x0f"
    with pytest.raises(ValueError, match="padding"):
        media._decrypt_rtp_payload(bytes(framed), _VIDEO_KEY)


def test_incoming_decrypts_before_h264_inspection_and_pt_rewrite() -> None:
    forwarded: list[bytes] = []
    protocol = media._RTPProtocol(
        forwarded.append,
        96,
        None,
        track_h264_nals=True,
        encryption_key=_VIDEO_KEY,
    )
    plaintext = _rtp(b"\x67\x01")

    protocol.datagram_received(
        media._encrypt_rtp_payload(plaintext, _VIDEO_KEY),
        ("192.0.2.10", 5004),
    )

    assert len(forwarded) == 1
    assert forwarded[0][1] & 0x7F == 96
    assert forwarded[0][12:] == b"\x67\x01"
    assert protocol.h264_nals.sps == 1
    assert protocol.decrypt_errors == 0

    protocol.datagram_received(
        media._encrypt_rtp_payload(plaintext, _AUDIO_KEY),
        ("192.0.2.10", 5004),
    )
    assert protocol.decrypt_errors == 1
    assert len(forwarded) == 1


class _FakeTransport:
    def __init__(self) -> None:
        self.sent: list[tuple[bytes, tuple[str, int]]] = []
        self.close_calls = 0

    def sendto(self, packet: bytes, destination: tuple[str, int]) -> None:
        self.sent.append((packet, destination))

    def close(self) -> None:
        self.close_calls += 1


def test_talkback_send_timing_stats_observe_successful_transport_sends() -> None:
    send_times = iter(
        (100_000_000_000, 100_020_000_000, 100_055_000_000, 100_080_000_000)
    )
    transport = _FakeTransport()
    sender = media._PCMATalkSender(
        transport,
        ("192.0.2.10", 5004),
        monotonic_ns=lambda: next(send_times),
    )

    sender._send_pcma(b"\xd5" * 160)
    assert sender.stats()["send_intervals"] == 0

    sender.start_talk()
    sender._send_pcma(b"\xd5" * 160)
    sender.stop_talk()
    sender._send_pcma(b"\xd5" * 160)
    sender._send_pcma(b"\xd5" * 160)

    stats = sender.stats()
    assert len(transport.sent) == 4
    assert stats["send_intervals"] == 3
    assert stats["send_gaps_over_30ms"] == 1
    assert stats["max_send_gap_ms"] == pytest.approx(35.0)


def test_talkback_deadline_skips_burst_catch_up_after_late_wake() -> None:
    interval_ns = 20_000_000

    assert (
        media._next_talk_send_deadline_ns(
            100_000_000,
            105_000_000,
            interval_ns,
        )
        == 120_000_000
    )
    assert (
        media._next_talk_send_deadline_ns(
            100_000_000,
            155_000_000,
            interval_ns,
        )
        == 175_000_000
    )


def test_talkback_queue_drops_oldest_frames_and_preserves_order() -> None:
    sender = media._PCMATalkSender(
        _FakeTransport(),
        ("192.0.2.10", 5004),
        max_queue_frames=2,
    )
    pcm_frames = [struct.pack("<160h", *([sample] * 160)) for sample in (1, 2, 3)]

    sender.start_talk()
    assert sender.feed_pcm16le(b"".join(pcm_frames)) == 3

    with sender._condition:
        queued = list(sender._queued_pcma)
    assert queued == [
        media._encode_pcm16le_to_pcma(pcm_frames[1]),
        media._encode_pcm16le_to_pcma(pcm_frames[2]),
    ]
    assert sender.stats()["dropped_frames"] == 1


def test_talkback_sender_start_failure_closes_owned_socket(monkeypatch) -> None:
    transport = _FakeTransport()
    sender = media._PCMATalkSender(transport, ("192.0.2.10", 5004))

    def _fail_start(_thread) -> None:
        raise RuntimeError("thread unavailable")

    monkeypatch.setattr(media.threading.Thread, "start", _fail_start)
    with pytest.raises(RuntimeError, match="thread unavailable"):
        asyncio.run(sender.start())

    assert transport.close_calls == 1
    assert sender.active is False


def test_talkback_sender_thread_closes_socket_once_on_stop() -> None:
    async def _run() -> tuple[dict, int]:
        transport = _FakeTransport()
        sender = media._PCMATalkSender(transport, ("192.0.2.10", 5004))
        await sender.start()
        assert sender.active is True
        await sender.stop()
        await sender.stop()
        return sender.stats(), transport.close_calls

    stats, close_calls = asyncio.run(_run())

    assert stats["active"] is False
    assert close_calls == 1


def test_talkback_thread_cadence_survives_event_loop_block() -> None:
    async def _run() -> dict:
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receiver.bind(("127.0.0.1", 0))
        sender_socket.bind(("127.0.0.1", 0))
        sender = media._PCMATalkSender(
            sender_socket,
            receiver.getsockname(),
        )
        try:
            await sender.start()
            await asyncio.sleep(0.08)
            time.sleep(0.25)  # noqa: ASYNC251 - deliberately block this thread
            await asyncio.sleep(0.08)
            return sender.stats()
        finally:
            await sender.stop()
            receiver.close()

    stats = asyncio.run(_run())

    assert stats["send_intervals"] >= 12
    assert stats["max_send_gap_ms"] < 150


def test_outgoing_talkback_and_punch_use_media_encryption() -> None:
    transport = _FakeTransport()
    destination = ("192.0.2.10", 5004)
    sender = media._PCMATalkSender(transport, destination, encryption_key=_AUDIO_KEY)
    sender.ssrc = 0x01020304
    sender.seq = 0xFFFF
    sender.timestamp = 0xFFFFFFF0
    sender._send_pcma(b"\xd5" * 160, marker=True)
    sender._send_pcma(b"\xd5" * 160)

    talkback_wire = transport.sent[0][0]
    assert talkback_wire[12:14] == b"\x00\xa0"
    talkback_plain = media._decrypt_rtp_payload(talkback_wire, _AUDIO_KEY)
    next_plain = media._decrypt_rtp_payload(transport.sent[1][0], _AUDIO_KEY)
    assert talkback_plain[12:] == b"\xd5" * 160
    assert talkback_plain[1] == 0x88
    assert next_plain[1] == 0x08
    assert struct.unpack_from("!HII", talkback_plain, 2) == (
        0xFFFF,
        0xFFFFFFF0,
        0x01020304,
    )
    assert struct.unpack_from("!HI", next_plain, 2) == (0, 0x00000090)

    session = media.StreamSession(
        dialer=object(),
        door=intercom.Door("door", "address"),
        gateway_host="192.0.2.10",
    )
    asyncio.run(
        session._punch(transport, destination, pt=102, encryption_key=_VIDEO_KEY)
    )
    assert len(transport.sent) == 8
    for packet, _destination in transport.sent[2:]:
        decrypted = media._decrypt_rtp_payload(packet, _VIDEO_KEY)
        assert len(decrypted) == 12
        assert decrypted[1] & 0x7F == 102


def test_app_managed_media_uses_remote_wire_key_after_local_negotiation() -> None:
    remote = intercom.MediaDescription(
        "audio",
        5004,
        "RTP/AVP",
        abb_encrypt=True,
        abb_encrypt_key=_AUDIO_KEY,
    )
    local = intercom.MediaEncryptionKeys(
        audio=_LOCAL_AUDIO_KEY,
        video=_LOCAL_VIDEO_KEY,
    )

    assert media._directional_media_encryption_keys(remote, local) == (
        _AUDIO_KEY,
        _AUDIO_KEY,
    )
    assert media._directional_media_encryption_keys(remote, None) == (
        _AUDIO_KEY,
        _AUDIO_KEY,
    )

    remote.abb_encrypt = False
    with pytest.raises(ValueError, match="missing negotiated remote audio"):
        media._directional_media_encryption_keys(remote, local)


def test_synthetic_tone_is_prebuffered_without_rtp_underruns() -> None:
    async def _run() -> tuple[dict, dict]:
        transport = _FakeTransport()
        sender = media._PCMATalkSender(
            transport,
            ("192.0.2.10", 5004),
            encryption_key=_AUDIO_KEY,
        )
        await sender.start()
        session = media.StreamSession(
            dialer=object(),
            door=intercom.Door("door", "address"),
            gateway_host="192.0.2.10",
        )
        session._talk_sender = sender
        before = sender.stats()
        try:
            after = await session.send_talkback_tone(
                duration_ms=400,
                frequency_hz=880,
                amplitude=0.25,
            )
        finally:
            await sender.stop()
        return before, after

    before, after = asyncio.run(_run())

    assert after["frames"] - before["frames"] == 20
    assert after["voice_packets"] - before["voice_packets"] == 20
    assert after["underrun_packets"] - before["underrun_packets"] <= 1
    assert after["dropped_frames"] == 0


def test_rtcp_is_never_encrypted_or_rewritten() -> None:
    rtcp = media._build_rtcp_rr(1, 2, 3)
    assert media._encrypt_rtp_payload(rtcp, _VIDEO_KEY) is rtcp
    assert media._decrypt_rtp_payload(rtcp, _VIDEO_KEY) is rtcp

    forwarded: list[bytes] = []
    protocol = media._RTPProtocol(forwarded.append, 96, None, encryption_key=_VIDEO_KEY)
    protocol.datagram_received(rtcp, ("192.0.2.10", 5005))
    assert forwarded == [rtcp]


def test_incoming_answer_advertises_directional_local_keys() -> None:
    audio_encoded = base64.b64encode(_AUDIO_KEY).decode()
    video_encoded = base64.b64encode(_VIDEO_KEY).decode()
    offer = intercom.parse_sdp(
        "v=0\r\n"
        "c=IN IP4 192.0.2.10\r\n"
        "m=audio 5004 RTP/AVP 8\r\n"
        "a=rtpmap:8 PCMA/8000\r\n"
        f"a=crypto:1 SUITE_A inline:{audio_encoded}\r\n"
        "m=video 5006 RTP/AVPF 102\r\n"
        "a=rtpmap:102 H264/90000\r\n"
        f"a=crypto:1 SUITE_V inline:{video_encoded} UNENCRYPTED_SRTCP\r\n",
        custom_media_crypto=True,
    )
    answer = sip_listener._build_answer_sdp(
        offer,
        username="client",
        media_ip="192.0.2.20",
        audio_port=6000,
        video_port=6002,
        local_send_keys=intercom.MediaEncryptionKeys(
            audio=_LOCAL_AUDIO_KEY,
            video=_LOCAL_VIDEO_KEY,
        ),
    )

    assert answer.count("a=crypto:1") == 2
    local_audio_encoded = base64.b64encode(_LOCAL_AUDIO_KEY).decode()
    local_video_encoded = base64.b64encode(_LOCAL_VIDEO_KEY).decode()
    assert f"a=crypto:1 SUITE_A inline:{local_audio_encoded}" in answer
    assert (
        f"a=crypto:1 SUITE_V inline:{local_video_encoded} UNENCRYPTED_SRTCP" in answer
    )
    assert audio_encoded not in answer
    assert video_encoded not in answer
    assert "abb_encrypt" not in answer


def test_incoming_answer_rejects_bad_remote_key() -> None:
    video_encoded = base64.b64encode(_VIDEO_KEY).decode()
    offer = intercom.parse_sdp(
        "v=0\r\n"
        "c=IN IP4 192.0.2.10\r\n"
        "m=video 5006 RTP/AVPF 102\r\n"
        "a=rtpmap:102 H264/90000\r\n"
        f"a=crypto:1 SUITE_V inline:{video_encoded}\r\n",
        custom_media_crypto=True,
    )

    offer.medias[0].crypto_inline_key = b"short"
    offer.medias[0].abb_encrypt_key = b"short"
    with pytest.raises(ValueError, match="invalid SDP crypto key"):
        sip_listener._build_answer_sdp(
            offer,
            username="client",
            media_ip="192.0.2.20",
            audio_port=6000,
            video_port=6002,
        )


def test_incoming_answer_retains_proprietary_encryption_mirroring() -> None:
    offer = intercom.parse_sdp(
        "c=IN IP4 192.0.2.10\r\n"
        "m=audio 5004 RTP/AVP 8\r\n"
        "a=rtpmap:8 PCMA/8000\r\n"
        "a=abb_encrypt:1\r\n"
        f"a=abb_encrypt_key:{_AUDIO_KEY.decode()}\r\n"
    )
    answer = sip_listener._build_answer_sdp(
        offer,
        username="client",
        media_ip="192.0.2.20",
        audio_port=6000,
        video_port=6002,
    )
    assert "a=abb_encrypt:1" in answer
    assert f"a=abb_encrypt_key:{_AUDIO_KEY.decode()}" in answer


def test_sip_frame_summary_contains_only_safe_protocol_metadata() -> None:
    secret = "very-private-auth-token"
    station = "private-station-123"
    address = "192.0.2.10"
    call_id = "private-call-id@example.invalid"
    body = (
        f"v=0\r\nc=IN IP4 {address}\r\n"
        f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{secret}\r\n"
    ).encode()
    start_line = f"INVITE sip:{station}@{address} SIP/2.0"
    headers = [
        ("Via", f"SIP/2.0/TLS {address};branch={secret}"),
        ("Via", "SIP/2.0/TLS second.private.invalid"),
        ("From", f"<sip:{station}@{address}>;tag={secret}"),
        ("To", f"<sip:ha@{address}>"),
        ("Call-ID", call_id),
        ("CSeq", "9483 INVITE"),
        ("Contact", f"<sip:{station}@{address}>"),
        ("Authorization", f'Digest response="{secret}"'),
        ("Proxy-Authorization", secret),
        ("Cookie", f"session={secret}"),
        ("Certificate", "-----BEGIN CERTIFICATE-----private-----END CERTIFICATE-----"),
        ("Content-Type", f"application/sdp; boundary={secret}"),
    ]
    raw = (
        start_line.encode()
        + b"\r\n"
        + b"\r\n".join(f"{key}: {value}".encode() for key, value in headers)
        + b"\r\n\r\n"
        + body
    )
    frame = sip_listener._SipFrame(
        start_line=start_line,
        headers=headers,
        body=body,
        raw=raw,
    )

    summary = sip_listener._summarise_frame(frame)

    encoded = json.dumps(summary)
    for private_value in (secret, station, address, call_id, "sip:", "CERTIFICATE"):
        assert private_value not in encoded
    for forbidden_key in (
        "request_uri",
        "headers",
        "body",
        "raw",
        "authorization",
        "cookie",
    ):
        assert forbidden_key not in summary

    assert summary["start_line"] == "INVITE <redacted> SIP/2.0"
    assert summary["method"] == "INVITE"
    assert summary["protocol"] == "SIP/2.0"
    assert summary["header_count"] == len(headers)
    assert summary["via_count"] == 2
    assert summary["content_type"] == "application/sdp"
    assert summary["cseq_method"] == "INVITE"
    assert summary["body_bytes"] == len(body)
    assert summary["raw_bytes"] == len(raw)


def test_sip_response_summary_omits_reason_and_header_values() -> None:
    secret = "private-realm-and-nonce"
    raw = (
        f"SIP/2.0 401 {secret}\r\n"
        f'WWW-Authenticate: Digest realm="{secret}", nonce="{secret}"\r\n'
        "CSeq: 92 REGISTER\r\n\r\n"
    ).encode()
    frame = sip_listener._SipFrame(
        start_line=f"SIP/2.0 401 {secret}",
        headers=[
            ("WWW-Authenticate", f'Digest realm="{secret}", nonce="{secret}"'),
            ("CSeq", "92 REGISTER"),
        ],
        body=b"",
        raw=raw,
    )

    summary = sip_listener._summarise_frame(frame)

    assert secret not in json.dumps(summary)
    assert summary == {
        "is_response": True,
        "protocol": "SIP/2.0",
        "header_count": 2,
        "via_count": 0,
        "body_bytes": 0,
        "raw_bytes": len(raw),
        "status_code": 401,
        "start_line": "SIP/2.0 401",
        "cseq_method": "REGISTER",
    }


def test_message_body_is_private_to_internal_callback() -> None:
    secret = b"c:2 private-station sip:door@192.0.2.10"
    internal_frames: list = []
    event_payloads: list[dict] = []
    listener = sip_listener.SipListener(
        "gateway.invalid",
        "ha",
        "password",
        "example.invalid",
        on_frame=event_payloads.append,
        on_message=internal_frames.append,
    )
    headers = [
        ("Via", "SIP/2.0/TLS gateway.invalid;branch=private"),
        ("From", "<sip:private-station@192.0.2.10>"),
        ("To", "<sip:ha@example.invalid>"),
        ("Call-ID", "private-call-id"),
        ("CSeq", "1 MESSAGE"),
        ("Content-Type", "text/plain"),
    ]
    frame = sip_listener._SipFrame(
        start_line="MESSAGE sip:ha@192.0.2.10 SIP/2.0",
        headers=headers,
        body=secret,
        raw=b"private wire frame " + secret,
    )

    writer = _FakeTransport()

    async def _drain() -> None:
        return None

    writer.write = lambda data: None
    writer.drain = _drain
    asyncio.run(listener._dispatch(frame, writer, "192.0.2.20", 5061))

    assert internal_frames == [frame]
    assert len(event_payloads) == 2  # inbound MESSAGE and outbound 200 response
    assert secret.decode() not in json.dumps(event_payloads)
    assert event_payloads[0]["method"] == "MESSAGE"
    assert event_payloads[0]["body_bytes"] == len(secret)


def test_existing_recursive_secret_redaction_still_covers_media_keys() -> None:
    secret = base64.b64encode(_VIDEO_KEY).decode()
    assert redaction.redact_log_value({"crypto_inline_key": secret}) == {
        "crypto_inline_key": "<redacted>"
    }
    local = intercom.MediaEncryptionKeys(
        audio=_LOCAL_AUDIO_KEY,
        video=_LOCAL_VIDEO_KEY,
    )
    assert redaction.redact_log_value({"local_send_keys": local}) == {
        "local_send_keys": "<redacted>"
    }
