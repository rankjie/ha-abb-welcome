"""Opt-in headless Chromium + go2rtc + ABB RTSP smoke test, loopback only."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import socket
import struct
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from test_talk_audio_file import _load_submodule

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "tests/frontend"


def _port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _rtp(payload, pt, seq, timestamp, ssrc, marker=False):
    return struct.pack(
        "!BBHII", 0x80, pt | (0x80 if marker else 0), seq & 0xFFFF, timestamp, ssrc
    ) + payload


def test_native_hold_and_release_against_go2rtc(tmp_path) -> None:
    rtc = os.environ.get("GO2RTC_BIN")
    browser = os.environ.get("ABB_CHROMIUM_BIN")
    if not rtc or not browser:
        pytest.skip("set GO2RTC_BIN and ABB_CHROMIUM_BIN to test the native browser path")
    encoded = subprocess.check_output(
        ["ffmpeg", "-v", "error", "-f", "lavfi", "-i", "color=c=blue:s=160x90:r=10",
         "-frames:v", "1", "-c:v", "libx264", "-profile:v", "baseline",
         "-x264-params", "keyint=1:repeat-headers=1", "-f", "h264", "pipe:1"],
        timeout=10,
    )
    nals = [
        nal for nal in re.split(rb"\x00\x00(?:\x00)?\x01", encoded)
        if nal and (nal[0] & 31) in (5, 7, 8)
    ]
    assert [nal[0] & 31 for nal in nals] == [7, 8, 5]
    assert all(len(nal) < 1200 for nal in nals)
    sps, pps = (base64.b64encode(nal).decode() for nal in nals[:2])
    counters = {"audio": 0, "describe_backchannel": 0, "plays": 0}
    rtsp = _load_submodule("rtsp_server")

    async def exercise():
        senders = set()

        async def describe(backchannel):
            counters["describe_backchannel"] += int(backchannel)
            lines = [
                "v=0", "o=- 0 0 IN IP4 127.0.0.1", "s=ABB synthetic",
                "c=IN IP4 127.0.0.1", "t=0 0", "a=control:*",
                "m=video 0 RTP/AVP 96", "a=rtpmap:96 H264/90000",
                f"a=fmtp:96 packetization-mode=1;profile-level-id={nals[0][1:4].hex()};sprop-parameter-sets={sps},{pps}",
                "a=control:trackID=0", "m=audio 0 RTP/AVP 8", "a=rtpmap:8 PCMA/8000",
                "a=control:trackID=1",
            ]
            if backchannel:
                lines += [
                    "m=audio 0 RTP/AVP 8", "a=rtpmap:8 PCMA/8000",
                    "a=control:trackID=2", "a=sendonly",
                ]
            return "\r\n".join(lines) + "\r\n"

        async def play(session):
            counters["plays"] += 1

            async def frames():
                seq = 0
                for tick in range(2000):
                    if tick % 5 == 0 and session.has_video:
                        for index, nal in enumerate(nals):
                            session.push_rtp(0, _rtp(nal, 96, seq, tick * 1800, 31, index == 2))
                            seq += 1
                    if session.has_audio:
                        session.push_rtp(2, _rtp(b"\xd5" * 160, 8, tick, tick * 160, 32))
                    await asyncio.sleep(0.02)

            task = asyncio.create_task(frames())
            senders.add(task)
            task.add_done_callback(senders.discard)

        async def teardown(_session):
            pass

        def on_audio(_session, packet):
            if len(packet) > 12 and packet[1] & 0x7F == 8:
                counters["audio"] += 1

        source = rtsp.RtspServer(
            host="127.0.0.1", on_describe=describe, on_play=play,
            on_teardown=teardown, on_backchannel_rtp=on_audio,
        )
        await source.start()
        api_port, media_port = _port(), _port()
        config = tmp_path / "go2rtc.yaml"
        config.write_text(
            f'api:\n  listen: "127.0.0.1:{api_port}"\n  origin: "*"\n'
            f'rtsp:\n  listen: ""\nwebrtc:\n  listen: "127.0.0.1:{media_port}"\n'
            f'  candidates: ["127.0.0.1:{media_port}"]\n'
            f'streams:\n  abb_fixture: "{source.url}"\n',
            encoding="utf-8",
        )
        process = await asyncio.create_subprocess_exec(
            rtc, "-config", str(config), stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                route = self.path.split("?", 1)[0]
                if route == "/":
                    mime, data = "text/html", (FRONTEND / "native-go2rtc-fixture.html").read_bytes()
                elif route == "/card.js":
                    mime = "text/javascript"
                    data = (ROOT / "custom_components/abb_welcome/frontend/abb-welcome-intercom-card.js").read_bytes()
                elif route == "/stats":
                    mime, data = "application/json", json.dumps(counters).encode()
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=http.serve_forever, daemon=True)
        worker.start()
        try:
            for _ in range(60):
                try:
                    _, writer = await asyncio.open_connection("127.0.0.1", api_port)
                    writer.close()
                    await writer.wait_closed()
                    break
                except OSError:
                    await asyncio.sleep(0.05)
            else:
                pytest.fail("go2rtc fixture API did not start")
            proc = await asyncio.create_subprocess_exec(
                "node", str(FRONTEND / "native-go2rtc-browser.mjs"), browser,
                str(tmp_path / "browser"),
                f"http://127.0.0.1:{http.server_port}/?rtc={api_port}",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            try:
                out, err = await asyncio.wait_for(proc.communicate(), timeout=33)
            except TimeoutError:
                proc.terminate()
                await proc.wait()
                raise
            assert proc.returncode == 0, (out.decode(), err.decode())
            print(out.decode().strip())
            assert counters["describe_backchannel"] >= 1 and counters["audio"] >= 5
        finally:
            http.shutdown()
            http.server_close()
            for task in list(senders):
                task.cancel()
            await asyncio.gather(*senders, return_exceptions=True)
            if process.returncode is None:
                process.terminate()
                await process.wait()
            await source.stop()

    asyncio.run(exercise())
