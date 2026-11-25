/* Card-level wiring for the live-media monitor.  No browser or HA runtime. */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  AbbWelcomeIntercomCard,
  LIVE_START_TIMEOUT_MS,
} from "../../custom_components/abb_welcome/frontend/abb-welcome-intercom-card.js";
import { deferred, settle } from "./_harness.mjs";

class FakeClock {
  constructor() {
    this.time = 0;
    this.nextId = 0;
    this.timers = new Map();
  }
  setTimeout = (fn, ms) => {
    const id = ++this.nextId;
    this.timers.set(id, { fn, at: this.time + ms, ms });
    return id;
  };
  clearTimeout = (id) => this.timers.delete(id);
  advance(ms) {
    const until = this.time + ms;
    while (true) {
      const due = [...this.timers.entries()]
        .filter(([, timer]) => timer.at <= until)
        .sort(([aId, a], [bId, b]) => a.at - b.at || aId - bId)[0];
      if (!due) break;
      const [id, timer] = due;
      this.timers.delete(id);
      this.time = timer.at;
      timer.fn();
    }
    this.time = until;
  }
}

class FakeVideo {
  constructor() {
    this.readyState = 0;
    this.videoWidth = 0;
    this.videoHeight = 0;
    this.currentTime = 0;
    this.paused = false;
    this.muted = true;
    this.volume = 1;
    this.playPlan = [];
    this.playCalls = 0;
    this.removeCalls = 0;
    this.srcAssignments = 0;
    this._srcObject = null;
    this._listeners = new Map();
    this._nextFrame = 0;
    this._frameCallbacks = new Map();
    this._allFrameCallbacks = new Map();
  }
  get srcObject() { return this._srcObject; }
  set srcObject(value) {
    this.srcAssignments++;
    this._srcObject = value;
  }
  addEventListener(name, callback) {
    const set = this._listeners.get(name) || new Set();
    set.add(callback);
    this._listeners.set(name, set);
  }
  removeEventListener(name, callback) { this._listeners.get(name)?.delete(callback); }
  emit(name) { for (const callback of this._listeners.get(name) || []) callback({ type: name }); }
  requestVideoFrameCallback(callback) {
    const id = ++this._nextFrame;
    this._frameCallbacks.set(id, callback);
    this._allFrameCallbacks.set(id, callback);
    return id;
  }
  cancelVideoFrameCallback(id) { this._frameCallbacks.delete(id); }
  frame(id = [...this._frameCallbacks.keys()][0], mediaTime = 1) {
    const callback = this._frameCallbacks.get(id);
    assert.ok(callback, "a video-frame callback is pending");
    this._frameCallbacks.delete(id);
    this.currentTime = mediaTime;
    callback(0, { width: this.videoWidth, height: this.videoHeight, mediaTime });
  }
  lateFrame(id, mediaTime = 1) {
    const callback = this._allFrameCallbacks.get(id);
    assert.ok(callback, "the previous callback was registered");
    callback(0, { width: this.videoWidth, height: this.videoHeight, mediaTime });
  }
  play() {
    this.playCalls++;
    const next = this.playPlan.shift();
    if (next && typeof next.then === "function") return next;
    return next ? Promise.reject(next) : Promise.resolve();
  }
  remove() { this.removeCalls++; }
}

class FakeStream {
  constructor() { this.tracks = []; }
  addTrack(track) { this.tracks.push(track); }
  getTracks() { return this.tracks; }
}

class FakeTrack {
  constructor(kind) {
    this.kind = kind;
    this.readyState = "live";
    this.muted = false;
    this._listeners = new Map();
  }
  addEventListener(name, callback) {
    const set = this._listeners.get(name) || new Set();
    set.add(callback);
    this._listeners.set(name, set);
  }
  removeEventListener(name, callback) { this._listeners.get(name)?.delete(callback); }
  emit(name) { for (const callback of this._listeners.get(name) || []) callback({ type: name }); }
  stop() { this.readyState = "ended"; }
}

function installBrowser(clock, peer) {
  globalThis.window = {
    isSecureContext: true,
    setTimeout: clock.setTimeout,
    clearTimeout: clock.clearTimeout,
  };
  globalThis.RTCPeerConnection = class { constructor() { return peer; } };
  globalThis.MediaStream = FakeStream;
  globalThis.document = { createElement: () => new FakeVideo() };
}

function makePeer() {
  return {
    signalingState: "have-local-offer",
    iceConnectionState: "new",
    connectionState: "new",
    closes: 0,
    addTransceiver: () => {},
    createOffer: async () => ({ type: "offer", sdp: "offer" }),
    setLocalDescription: async () => {},
    addIceCandidate: async () => {},
    close() { this.closes++; },
  };
}

function makeHass({ live = async () => {}, subscribe } = {}) {
  const calls = [];
  const hass = {
    connected: true,
    connection: {
      connected: true,
      subscribeMessage: (callback, message) => {
        if (message.type === "abb_welcome/live") {
          const call = { type: "live", callback, message, releases: 0 };
          calls.push(call);
          return live().then(() => () => { call.releases++; });
        }
        calls.push({ type: "subscribe", callback, message });
        return subscribe ? subscribe(callback, message) : () => {};
      },
    },
    states: {
      "camera.front": {
        state: "idle",
        attributes: { config_entry_id: "entry", station_id: "station", talkback_ready: false },
      },
    },
    callService: (domain, service, data) => {
      calls.push({ type: "service", domain, service, data });
    },
    callWS: async () => ({ configuration: {} }),
  };
  return { hass, calls };
}

function makeCard({ live, subscribe } = {}) {
  const clock = new FakeClock();
  const peer = makePeer();
  installBrowser(clock, peer);
  const { hass, calls } = makeHass({ live, subscribe });
  const card = new AbbWelcomeIntercomCard();
  card.setConfig({ camera: "camera.front", unlock_button: "button.front" });
  card._hass = hass;
  card._refs = { media: { appendChild: (video) => { card.appendedVideo = video; } } };
  return { card, clock, peer, hass, calls };
}

async function startToSubscribed(fixture) {
  const pending = fixture.card._startLive();
  await pending;
  return fixture.card.appendedVideo;
}

function liveWindows(calls) {
  return calls.filter((call) => call.type === "live");
}

test("signaling completion sets live true while media is still waiting", async () => {
  const fixture = makeCard();
  const video = await startToSubscribed(fixture);
  assert.equal(fixture.card._live, true);
  assert.equal(fixture.card._mediaState, "waiting");
  assert.notEqual(fixture.card._liveStartTimer, null, "playback, not subscribe, clears the global deadline");
  assert.equal(video.srcObject, null);
});

test("global startup deadline gives up on a hung live window and releases a late grant", async () => {
  const windowGate = deferred();
  const fixture = makeCard({ live: () => windowGate.promise });
  const pending = fixture.card._startLive();
  await settle();
  const [window] = liveWindows(fixture.calls);

  fixture.clock.advance(LIVE_START_TIMEOUT_MS);
  assert.equal(fixture.card._live, false);
  assert.equal(fixture.card._mediaState, "idle");
  assert.equal(fixture.card._playerEl, null);
  windowGate.resolve();
  await pending;
  assert.equal(window.releases, 1);
});

test("global startup deadline closes and releases a hung signaling subscription", async () => {
  const subscription = deferred();
  const fixture = makeCard({ subscribe: () => subscription.promise });
  void fixture.card._startLive();
  await settle();
  assert.equal(fixture.card._live, "starting");
  assert.ok(fixture.card._playerEl);
  assert.equal(fixture.calls.filter((call) => call.type === "subscribe").length, 1);

  fixture.clock.advance(LIVE_START_TIMEOUT_MS);
  assert.equal(fixture.card._live, false);
  assert.equal(fixture.card._playerEl, null);
  assert.equal(fixture.peer.closes, 1);
  assert.equal(liveWindows(fixture.calls)[0].releases, 1);
});

test("the first decoded frame clears the card-level startup deadline", async () => {
  const fixture = makeCard();
  const video = await startToSubscribed(fixture);
  video.videoWidth = 1280;
  video.videoHeight = 720;
  video.frame();
  assert.equal(fixture.card._mediaState, "playing");
  assert.equal(fixture.card._liveStartTimer, null);
});

test("Stop before a frame ignores late media events and frame callbacks", async () => {
  const fixture = makeCard();
  const video = await startToSubscribed(fixture);
  const stale = [...video._frameCallbacks.keys()][0];
  fixture.card._stopLive();
  video.videoWidth = 1280;
  video.videoHeight = 720;
  video.emit("playing");
  video.lateFrame(stale);
  assert.equal(fixture.card._live, false);
  assert.equal(fixture.card._mediaState, "idle");
  assert.equal(fixture.card._playerEl, null);
});

for (const state of ["closed", "failed"]) {
  test(`WebRTC connection state ${state} tears down live media`, async () => {
    const fixture = makeCard();
    await startToSubscribed(fixture);
    fixture.peer.connectionState = state;
    fixture.peer.onconnectionstatechange();
    assert.equal(fixture.card._live, false);
    assert.equal(fixture.card._playerEl, null);
    assert.equal(fixture.peer.closes, 1);
    assert.equal(liveWindows(fixture.calls)[0].releases, 1);
  });
}

test("an audio NotAllowed retry re-mutes video without falsely ending playback", async () => {
  const fixture = makeCard();
  const video = await startToSubscribed(fixture);
  video.muted = false;
  fixture.card._audioUnmuted = true;
  video.playPlan.push({ name: "NotAllowedError" });
  fixture.card._playVideo(true);
  await settle();
  assert.equal(video.muted, true);
  assert.equal(fixture.card._audioUnmuted, false);
  assert.equal(fixture.card._audioBlocked, true);
  assert.equal(video.playCalls, 2, "the muted retry is offered after the rejected audio attempt");
  assert.equal(fixture.card._live, true);
  assert.equal(fixture.card._mediaState, "waiting");
});

test("a decoded muted frame does not clear an audio-listen block", async () => {
  const fixture = makeCard();
  const video = await startToSubscribed(fixture);
  video.muted = false;
  fixture.card._audioUnmuted = true;
  video.playPlan.push({ name: "NotAllowedError" });
  fixture.card._playVideo(true);
  await settle();
  assert.equal(fixture.card._audioBlocked, true);
  assert.equal(video.muted, true, "the fallback keeps video muted");

  video.videoWidth = 1280;
  video.videoHeight = 720;
  video.frame();
  assert.equal(fixture.card._mediaState, "playing");
  assert.equal(fixture.card._audioBlocked, true, "video evidence is not proof that listening was allowed");
});

test("a late play rejection cannot override a later muted request", async () => {
  const fixture = makeCard();
  const video = await startToSubscribed(fixture);
  const lateAudioPlay = deferred();
  video.playPlan.push(lateAudioPlay.promise);
  video.muted = false;
  fixture.card._audioUnmuted = true;
  fixture.card._playVideo(true);

  // The user disables listening, then asks for muted video again.  The first
  // promise may reject afterwards, but its stale policy must not win.
  fixture.card._audioUnmuted = false;
  fixture.card._applyAudio();
  fixture.card._playVideo();
  lateAudioPlay.reject({ name: "NotAllowedError" });
  await settle();

  assert.equal(video.playCalls, 2);
  assert.equal(video.muted, true);
  assert.equal(fixture.card._audioUnmuted, false);
  assert.equal(fixture.card._audioBlocked, false);
  assert.equal(fixture.card._mediaState, "waiting");
});

test("a normal video play rejection is surfaced as blocked media", async () => {
  const fixture = makeCard();
  const video = await startToSubscribed(fixture);
  video.playPlan.push({ name: "NotAllowedError" });
  fixture.card._playVideo();
  await settle();
  assert.equal(fixture.card._live, true);
  assert.equal(fixture.card._mediaState, "blocked");
  assert.notEqual(fixture.card._liveStartTimer, null, "blocked playback remains startup-bounded");
});

test("the second audio ontrack keeps the established stream attached", async () => {
  const fixture = makeCard();
  const video = await startToSubscribed(fixture);
  fixture.peer.ontrack({ track: { kind: "video", readyState: "live" } });
  await settle();
  const stream = video.srcObject;
  const assignments = video.srcAssignments;
  fixture.peer.ontrack({ track: { kind: "audio", readyState: "live" } });
  await settle();
  assert.equal(video.srcObject, stream);
  assert.equal(video.srcAssignments, assignments, "second track must not reset srcObject/playback");
  assert.equal(stream.getTracks().length, 2);
  assert.equal(fixture.card._hasIncomingAudio, true);
});

test("audio track state changes update listen availability without resetting the stream", async () => {
  const fixture = makeCard();
  const video = await startToSubscribed(fixture);
  const audio = new FakeTrack("audio");
  fixture.peer.ontrack({ track: audio });
  await settle();
  const stream = video.srcObject;
  const assignments = video.srcAssignments;
  assert.equal(fixture.card._hasIncomingAudio, true);

  audio.muted = true;
  audio.emit("mute");
  assert.equal(fixture.card._hasIncomingAudio, false, "muted audio disables Listen");
  assert.equal(video.srcObject, stream);
  assert.equal(video.srcAssignments, assignments);

  audio.muted = false;
  audio.emit("unmute");
  assert.equal(fixture.card._hasIncomingAudio, true, "unmuting restores Listen");
  assert.equal(video.srcAssignments, assignments);

  audio.readyState = "ended";
  audio.emit("ended");
  assert.equal(fixture.card._hasIncomingAudio, false, "ended audio disables Listen");
  assert.equal(fixture.card._live, true, "an audio end alone does not end video");
  assert.equal(video.srcAssignments, assignments);
});

test("track events delivered after Stop are inert", async () => {
  const fixture = makeCard();
  const video = await startToSubscribed(fixture);
  const audio = new FakeTrack("audio");
  fixture.peer.ontrack({ track: audio });
  await settle();
  fixture.card._stopLive();
  const assignments = video.srcAssignments;
  audio.muted = true;
  audio.emit("mute");
  audio.muted = false;
  audio.emit("unmute");
  audio.readyState = "ended";
  audio.emit("ended");
  assert.equal(fixture.card._live, false);
  assert.equal(fixture.card._mediaState, "idle");
  assert.equal(fixture.card._hasIncomingAudio, false);
  assert.equal(video.srcAssignments, assignments, "removed track listeners cannot remount/reset media");
});

test("native Hold leaves the card's player, incoming audio, and owned Live window running", async (t) => {
  const fixture = makeCard();
  const original = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  const mic = new FakeTrack("audio");
  mic.enabled = true;
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: {
    mediaDevices: { getUserMedia: async () => ({ getTracks: () => [mic], getAudioTracks: () => [mic] }) },
  } });
  t.after(() => {
    if (original) Object.defineProperty(globalThis, "navigator", original);
    else delete globalThis.navigator;
  });
  fixture.card.setConfig({ camera: "camera.front" });
  fixture.hass.callWS = async ({ type }) => type === "camera/capabilities"
    ? { two_way_audio: true } : { configuration: {} };
  const sender = { track: null, async replaceTrack(track) { this.track = track; } };
  const audio = { sender, currentDirection: null };
  fixture.peer.addTransceiver = (kind) => kind === "audio" ? audio : {};
  fixture.peer.setRemoteDescription = async () => { audio.currentDirection = "sendrecv"; };
  const video = await startToSubscribed(fixture);
  fixture.hass.states["camera.front"].attributes.talkback_ready = true;
  const ws = fixture.calls.find(item => item.type === "subscribe");
  ws.callback({ type: "answer", answer: "answer" });
  await settle();
  fixture.peer.ontrack({ track: new FakeTrack("video") });
  fixture.peer.ontrack({ track: new FakeTrack("audio") });
  const incoming = video.srcObject;
  const lease = fixture.card._armLease;
  assert.equal(sender.track, null, "Live starts with no microphone attached");
  await fixture.card._machine.press();
  assert.equal(sender.track, mic);
  fixture.card._machine.release();
  assert.equal(mic.readyState, "ended");
  await settle();
  assert.equal(sender.track, null);
  assert.equal(video.srcObject, incoming);
  assert.equal(fixture.card._playerEl, video);
  assert.equal(fixture.card._armLease, lease);
  assert.equal(fixture.card._live, true);
  assert.equal(fixture.peer.closes, 0);
  assert.equal(liveWindows(fixture.calls)[0].releases, 0);
  assert.deepEqual(fixture.calls.filter(item => item.type === "service"), []);
  fixture.card._stopLive();
  assert.equal(fixture.peer.closes, 1);
});

test("native_talkback false keeps Live receive-only even when HA supports Talk", async () => {
  const fixture = makeCard();
  const directions = [];
  fixture.card.setConfig({ camera: "camera.front", native_talkback: false });
  fixture.hass.callWS = async ({ type }) => {
    assert.notEqual(type, "camera/capabilities");
    return { configuration: {} };
  };
  fixture.peer.addTransceiver = (kind, { direction }) => { directions.push([kind, direction]); };
  await startToSubscribed(fixture);
  assert.equal(fixture.card._live, true);
  assert.deepEqual(directions, [["audio", "recvonly"], ["video", "recvonly"]]);
  assert.equal(fixture.card._machine.state === "idle", false);
  fixture.card._stopLive();
});

test("Live holds the station through one live window and Stop releases it once", async () => {
  const fixture = makeCard();
  await startToSubscribed(fixture);
  const windows = liveWindows(fixture.calls);
  assert.equal(windows.length, 1);
  assert.deepEqual(windows[0].message, {
    type: "abb_welcome/live",
    entry_id: "entry",
    station_id: "station",
  });
  fixture.card._stopLive();
  fixture.card._stopLive();
  assert.equal(windows[0].releases, 1);
});

test("an ended live window stops Live and says so", async () => {
  const fixture = makeCard();
  const video = await startToSubscribed(fixture);
  video.videoWidth = 1280;
  video.videoHeight = 720;
  video.frame();
  const [window] = liveWindows(fixture.calls);
  window.callback({ ended: true });
  assert.equal(fixture.card._live, false);
  assert.equal(fixture.card._playerEl, null);
  assert.equal(fixture.peer.closes, 1);
  assert.equal(fixture.card._statusOverride, fixture.card._strings.live_ended);

  window.callback({ ended: true });
  assert.equal(fixture.peer.closes, 1, "a late repeat is ignored");
});
