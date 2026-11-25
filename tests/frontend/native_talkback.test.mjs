import { test } from "node:test";
import assert from "node:assert/strict";
import {
  NativeTalkbackMachine,
  WebRtcSession,
} from "../../custom_components/abb_welcome/frontend/abb-welcome-intercom-card.js";
import { deferred, settle } from "./_harness.mjs";

function track(kind = "audio") {
  return {
    kind, readyState: "live", enabled: true, stops: 0, events: new Map(),
    addEventListener(name, listener) { this.events.set(name, listener); },
    removeEventListener(name) { this.events.delete(name); },
    stop() { this.readyState = "ended"; this.stops++; },
  };
}

function setup({ supported = true, direction = "sendrecv" } = {}) {
  const calls = { ws: [], capture: 0, replace: [], offer: 0, subscribe: 0, close: 0, unsub: 0, streams: [] };
  const micTracks = [];
  const recvTracks = [];
  const streams = [];
  const rtcSender = {
    track: null,
    async replaceTrack(mic) { calls.replace.push(mic); this.track = mic; },
  };
  const audio = { sender: rtcSender, currentDirection: null };
  let offerEvent;
  const peer = {
    signalingState: "have-local-offer",
    addTransceiver(kind, options) { streams.push([kind, options.direction]); if (kind === "audio") return audio; },
    async createOffer() { calls.offer++; return { sdp: "offer" }; },
    async setLocalDescription() {},
    async setRemoteDescription() { audio.currentDirection = direction; },
    close() { calls.close++; },
  };
  const rtc = new WebRtcSession({
    entityId: "camera.front",
    nativeTalkback: true,
    async callWS(params) {
      calls.ws.push(params.type);
      if (params.type === "camera/capabilities") {
        if (supported === "reject") throw Error("unknown command");
        return { two_way_audio: supported };
      }
      return { configuration: {} };
    },
    subscribeMessage(callback) { calls.subscribe++; offerEvent = callback; return () => calls.unsub++; },
    createPeerConnection: () => peer,
    createMediaStream: () => ({
      addTrack(value) { recvTracks.push(value); },
      getTracks() { return recvTracks; },
    }),
    onStream: (stream) => calls.streams.push(stream),
  });
  const fixture = {
    async capture() {
      const mic = track();
      micTracks.push(mic);
      return { getTracks: () => [mic], getAudioTracks: () => [mic] };
    },
  };
  const machine = new NativeTalkbackMachine({
    session: () => rtc,
    acquire: () => { calls.capture++; return fixture.capture(); },
  });
  return {
    rtc, machine, calls, audio, micTracks, rtcSender, peer, streams,
    capture(callback) { fixture.capture = callback; },
    async answer() {
      offerEvent({ type: "answer", answer: "answer" });
      await settle();
      machine.setReady(rtc.nativeMicReady);
    },
  };
}

test("hold attaches the only microphone; release stops it and retains the same receiving video and peer", async () => {
  const h = setup();
  assert.equal(await h.rtc.start(), true);
  assert.deepEqual(h.streams, [["audio", "sendrecv"], ["video", "recvonly"]]);
  assert.deepEqual(h.calls.ws, ["camera/webrtc/get_client_config", "camera/capabilities"]);
  assert.equal(h.calls.capture, 0);
  assert.equal(h.rtcSender.track, null);
  await h.answer();
  const remoteVideo = track("video");
  const remoteAudio = track("audio");
  h.peer.ontrack({ track: remoteVideo });
  h.peer.ontrack({ track: remoteAudio });
  const media = h.calls.streams.at(-1);
  const hold = h.machine.press();
  await h.machine.press(); // a second press does not open another microphone
  await hold;
  const [mic] = h.micTracks;
  assert.equal(h.machine.state, "talking");
  assert.equal(h.calls.capture, 1);
  assert.equal(h.rtcSender.track, mic);
  h.machine.release();
  assert.equal(mic.enabled, false);
  assert.equal(mic.readyState, "ended");
  await settle();
  assert.equal(h.rtcSender.track, null);
  assert.deepEqual(media.getTracks(), [remoteVideo, remoteAudio]);
  assert.equal(remoteVideo.readyState, "live");
  assert.equal(h.calls.streams.every(stream => stream === media), true);
  assert.equal(h.calls.offer, 1);
  assert.equal(h.calls.subscribe, 1);
  assert.equal(h.calls.unsub, 0);
  assert.equal(h.calls.close, 0);
  assert.deepEqual(h.calls.replace, [mic, null]);
  assert.equal(h.machine.state, "idle");
});

test("release while permission is pending stops the late stream without touching the peer", async () => {
  const h = setup();
  await h.rtc.start();
  await h.answer();
  const delayed = deferred();
  h.capture(() => delayed.promise);
  const hold = h.machine.press();
  h.machine.release();
  const mic = track();
  delayed.resolve({ getTracks: () => [mic], getAudioTracks: () => [mic] });
  await hold;
  assert.equal(mic.readyState, "ended");
  assert.deepEqual(h.calls.replace, []);
  assert.equal(h.calls.close, 0);
});

test("late replaceTrack cannot leak audio or detach a newer hold", async () => {
  const h = setup();
  await h.rtc.start();
  await h.answer();
  const first = deferred();
  const replace = h.rtcSender.replaceTrack.bind(h.rtcSender);
  h.rtcSender.replaceTrack = async (mic) => {
    if (mic && h.calls.replace.length === 0) await first.promise;
    return replace(mic);
  };
  const abandoned = h.machine.press();
  await settle();
  const [old] = h.micTracks;
  h.machine.release();
  assert.equal(old.readyState, "ended");
  const newHold = h.machine.press();
  await settle();
  const [, current] = h.micTracks;
  first.resolve();
  await Promise.all([abandoned, newHold]);
  assert.deepEqual(h.calls.replace, [old, null, current]);
  assert.equal(h.rtcSender.track, current);
  assert.equal(h.machine.state, "talking");
  h.machine.dispose("disconnected");
  await settle();
  assert.equal(current.readyState, "ended");
  assert.equal(h.rtcSender.track, null);
  assert.equal(h.calls.close, 0);
});

test("an unavailable native channel leaves Live receive-only and never requests the device", async () => {
  for (const options of [{ supported: false }, { supported: "reject" }, { direction: "recvonly" }]) {
    const h = setup(options);
    assert.equal(await h.rtc.start(), true);
    await h.answer();
    await h.machine.press();
    assert.equal(h.rtc.nativeMicReady, false);
    assert.equal(h.calls.capture, 0);
    assert.equal(h.calls.offer, 1);
    assert.equal(h.calls.close, 0);
  }
});

test("permission denial and failure to attach never interrupt Live and allow a new hold", async () => {
  const h = setup();
  await h.rtc.start();
  await h.answer();
  h.capture(async () => { throw Object.assign(Error("denied"), { name: "NotAllowedError" }); });
  await h.machine.press();
  assert.equal(h.machine.state, "mic_denied");
  h.capture(async () => {
    const mic = track();
    h.micTracks.push(mic);
    return { getTracks: () => [mic], getAudioTracks: () => [mic] };
  });
  h.rtcSender.replaceTrack = async (mic) => {
    if (mic) throw Error("codec mismatch");
  };
  await h.machine.press();
  assert.equal(h.machine.state, "error");
  assert.equal(h.micTracks[0].readyState, "ended");
  assert.equal(h.calls.close, 0);
  assert.equal(h.calls.offer, 1);
});

test("a microphone error stays visible after the hold is released", async () => {
  const h = setup();
  await h.rtc.start();
  await h.answer();
  h.capture(async () => { throw Object.assign(Error("denied"), { name: "NotAllowedError" }); });
  await h.machine.press();
  h.machine.release();
  assert.equal(h.machine.state, "mic_denied");
});

test("a denial after the permission prompt ended the hold is still reported", async () => {
  const h = setup();
  await h.rtc.start();
  await h.answer();
  const prompt = deferred();
  h.capture(() => prompt.promise);
  const hold = h.machine.press();
  h.machine.release();
  assert.equal(h.machine.state, "idle");
  prompt.reject(Object.assign(Error("denied"), { name: "NotAllowedError" }));
  await hold;
  assert.equal(h.machine.state, "mic_denied");
});

test("a denial after Live ended leaves Talk blocked", async () => {
  const h = setup();
  await h.rtc.start();
  await h.answer();
  const prompt = deferred();
  h.capture(() => prompt.promise);
  const hold = h.machine.press();
  h.machine.setReady(false);
  prompt.reject(Object.assign(Error("denied"), { name: "NotAllowedError" }));
  await hold;
  assert.equal(h.machine.state, "blocked");
});

test("a newer hold owns the state when an older permission prompt fails", async () => {
  const h = setup();
  await h.rtc.start();
  await h.answer();
  const prompt = deferred();
  h.capture(() => prompt.promise);
  const abandoned = h.machine.press();
  h.machine.release();
  h.capture(async () => {
    const mic = track();
    h.micTracks.push(mic);
    return { getTracks: () => [mic], getAudioTracks: () => [mic] };
  });
  await h.machine.press();
  prompt.reject(Object.assign(Error("denied"), { name: "NotAllowedError" }));
  await abandoned;
  assert.equal(h.machine.state, "talking");
});

test("a lost session or an ended device silences the microphone", async () => {
  const h = setup();
  await h.rtc.start();
  await h.answer();
  await h.machine.press();
  const [mic] = h.micTracks;
  mic.readyState = "ended";
  mic.events.get("ended")();
  await settle();
  assert.equal(h.machine.state, "idle");
  assert.equal(h.rtcSender.track, null);
  await h.machine.press();
  const [, second] = h.micTracks;
  h.rtc.stop();
  assert.equal(second.enabled, false);
  assert.equal(second.readyState, "ended");
});
