/*
 * The card owns its WebRTC signaling instead of depending on Home Assistant's
 * private ha-camera-stream element. These tests pin the public camera WS
 * contract and, crucially, prove that muted autoplay never drops the audio
 * track from the remote MediaStream.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { WebRtcSession } from "../../custom_components/abb_welcome/frontend/abb-welcome-intercom-card.js";
import { settle } from "./_harness.mjs";

function makeWebRtcHarness() {
  const h = {
    ws: [],
    transceivers: [],
    remoteDescriptions: [],
    remoteCandidates: [],
    tracks: [],
    stoppedTracks: [],
    streams: [],
    errors: [],
    closed: 0,
    unsubscribed: 0,
    callback: null,
    subscription: null,
  };
  h.peer = {
    signalingState: "have-local-offer",
    iceConnectionState: "new",
    addTransceiver: (kind, options) => h.transceivers.push({ kind, options }),
    createDataChannel: (name) => {
      h.dataChannel = name;
    },
    createOffer: async () => ({ type: "offer", sdp: "offer-sdp" }),
    setLocalDescription: async (offer) => {
      h.localDescription = offer;
    },
    setRemoteDescription: async (answer) => h.remoteDescriptions.push(answer),
    addIceCandidate: async (candidate) => h.remoteCandidates.push(candidate),
    close: () => h.closed++,
  };
  h.stream = {
    addTrack: (track) => h.tracks.push(track),
    getTracks: () => h.tracks,
  };
  h.ports = {
    entityId: "camera.abb_door",
    callWS: async (message) => {
      h.ws.push(message);
      if (message.type === "camera/webrtc/get_client_config") {
        return { configuration: { iceServers: [] }, dataChannel: "keepalive" };
      }
      return {};
    },
    subscribeMessage: (callback, message) => {
      h.callback = callback;
      h.subscription = message;
      return Promise.resolve(() => h.unsubscribed++);
    },
    createPeerConnection: (configuration) => {
      h.configuration = configuration;
      return h.peer;
    },
    createMediaStream: () => h.stream,
    onStream: (stream, track) => h.streams.push({ stream, track }),
    onError: (message) => h.errors.push(message),
  };
  return h;
}

test("uses the Home Assistant camera WebRTC WS contract", async () => {
  const h = makeWebRtcHarness();
  const session = new WebRtcSession(h.ports);
  assert.equal(await session.start(), true);

  assert.deepEqual(h.ws[0], {
    type: "camera/webrtc/get_client_config",
    entity_id: "camera.abb_door",
  });
  assert.deepEqual(h.configuration, { iceServers: [] });
  assert.equal(h.dataChannel, "keepalive");
  assert.deepEqual(h.transceivers, [
    { kind: "audio", options: { direction: "recvonly" } },
    { kind: "video", options: { direction: "recvonly" } },
  ]);
  assert.deepEqual(h.subscription, {
    type: "camera/webrtc/offer",
    entity_id: "camera.abb_door",
    offer: "offer-sdp",
  });
});

test("retains both remote audio and video tracks for later unmute", async () => {
  const h = makeWebRtcHarness();
  const session = new WebRtcSession(h.ports);
  await session.start();
  const audio = { kind: "audio", stop: () => h.stoppedTracks.push("audio") };
  const video = { kind: "video", stop: () => h.stoppedTracks.push("video") };

  h.peer.ontrack({ track: audio });
  h.peer.ontrack({ track: video });
  assert.deepEqual(h.tracks, [audio, video]);
  assert.deepEqual(h.streams.map(({ track }) => track.kind), ["audio", "video"]);

  session.stop();
  assert.deepEqual(h.stoppedTracks, ["audio", "video"]);
  assert.equal(h.closed, 1);
  await settle();
  assert.equal(h.unsubscribed, 1);
});

test("queues local ICE until the session id and normalizes remote ICE", async () => {
  const h = makeWebRtcHarness();
  const session = new WebRtcSession(h.ports);
  await session.start();
  h.peer.onicecandidate({
    candidate: {
      candidate: "local-candidate",
      toJSON: () => ({ candidate: "local-candidate", sdpMid: "1" }),
    },
  });
  assert.equal(h.ws.length, 1);

  h.callback({ type: "session", session_id: "session-7" });
  await settle();
  assert.deepEqual(h.ws[1], {
    type: "camera/webrtc/candidate",
    entity_id: "camera.abb_door",
    session_id: "session-7",
    candidate: { candidate: "local-candidate", sdpMid: "1" },
  });

  h.callback({ type: "answer", answer: "answer-sdp" });
  h.callback({ type: "candidate", candidate: { candidate: "remote" } });
  await settle();
  assert.deepEqual(h.remoteDescriptions, [
    { type: "answer", sdp: "answer-sdp" },
  ]);
  assert.deepEqual(h.remoteCandidates, [
    { candidate: "remote", sdpMid: "0" },
  ]);
});

test("signaling errors clean up once and surface to the card", async () => {
  const h = makeWebRtcHarness();
  const session = new WebRtcSession(h.ports);
  await session.start();
  h.callback({ type: "error", code: "failed", message: "camera refused" });
  await settle();

  assert.deepEqual(h.errors, ["camera refused"]);
  assert.equal(h.closed, 1);
  assert.equal(h.unsubscribed, 1);
});
