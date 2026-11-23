/*
 * Playback evidence must be derived from decoded video, not just from the
 * media-element event sequence.  These tests deliberately use a tiny
 * EventTarget substitute so they also run under node --test without a DOM.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

// Keep this as a namespace import while the implementation is introduced: a
// named import would make the whole test file unload before the new export is
// present, obscuring the useful contract failures below.
import * as frontend from "../../custom_components/abb_welcome/frontend/abb-welcome-intercom-card.js";

class FakeClock {
  constructor() {
    this.time = 0;
    this.nextId = 0;
    this.timers = new Map();
  }

  setTimeout = (fn, delay) => {
    const id = ++this.nextId;
    this.timers.set(id, { fn, at: this.time + delay });
    return id;
  };

  clearTimeout = (id) => this.timers.delete(id);

  advance(ms) {
    const until = this.time + ms;
    while (true) {
      const due = [...this.timers.entries()]
        .filter(([, timer]) => timer.at <= until)
        .sort(([leftId, left], [rightId, right]) =>
          left.at - right.at || leftId - rightId
        )[0];
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
  constructor({ frameCallbacks = true } = {}) {
    this.readyState = 0;
    this.videoWidth = 0;
    this.videoHeight = 0;
    this.currentTime = 0;
    this.paused = false;
    this._listeners = new Map();
    this._nextFrameId = 0;
    this._frameCallbacks = new Map();
    this._allFrameCallbacks = new Map();
    this._nextMediaTime = 0;
    if (frameCallbacks) {
      this.requestVideoFrameCallback = (callback) => {
        const id = ++this._nextFrameId;
        this._frameCallbacks.set(id, callback);
        this._allFrameCallbacks.set(id, callback);
        return id;
      };
      this.cancelVideoFrameCallback = (id) => this._frameCallbacks.delete(id);
    }
  }

  addEventListener(type, listener) {
    const listeners = this._listeners.get(type) || new Set();
    listeners.add(listener);
    this._listeners.set(type, listeners);
  }

  removeEventListener(type, listener) {
    this._listeners.get(type)?.delete(listener);
  }

  emit(type) {
    for (const listener of this._listeners.get(type) || []) listener({ type });
  }

  frame(id, metadata = {}) {
    const callback = this._frameCallbacks.get(id);
    assert.ok(callback, `frame callback ${id} is pending`);
    this._frameCallbacks.delete(id);
    const mediaTime = metadata.mediaTime ?? (this._nextMediaTime += 1 / 30);
    this.currentTime = mediaTime;
    callback(0, { width: this.videoWidth, height: this.videoHeight, mediaTime, ...metadata });
  }

  lateFrame(id, metadata = {}) {
    const callback = this._allFrameCallbacks.get(id);
    assert.ok(callback, `frame callback ${id} was registered`);
    const mediaTime = metadata.mediaTime ?? (this._nextMediaTime += 1 / 30);
    this.currentTime = mediaTime;
    callback(0, { width: this.videoWidth, height: this.videoHeight, mediaTime, ...metadata });
  }

  get frameIds() {
    return [...this._frameCallbacks.keys()];
  }

  get listenerCount() {
    return [...this._listeners.values()].reduce((sum, listeners) => sum + listeners.size, 0);
  }
}

function monitorFor(video, clock = new FakeClock()) {
  const states = [];
  const errors = [];
  const monitor = new frontend.VideoPlaybackMonitor(video, {
    onState: (state) => states.push(state),
    onError: (reason) => errors.push(reason),
    setTimeout: clock.setTimeout,
    clearTimeout: clock.clearTimeout,
    now: () => clock.time,
  });
  return { monitor, states, errors, clock };
}

function onlyFrame(video) {
  assert.equal(video.frameIds.length, 1, "one frame callback is armed");
  return video.frameIds[0];
}

test("exports the bounded live startup and stall contract", () => {
  assert.equal(frontend.LIVE_START_TIMEOUT_MS, 15_000);
  assert.equal(frontend.LIVE_STALL_TIMEOUT_MS, 10_000);
  assert.equal(typeof frontend.VideoPlaybackMonitor, "function");
});

test("rVFC requires a valid decoded frame before playing", () => {
  const video = new FakeVideo();
  const { monitor, states } = monitorFor(video);
  monitor.start();
  assert.deepEqual(states, ["waiting"]);

  video.readyState = 4;
  video.videoWidth = 1280;
  video.videoHeight = 720;
  video.emit("loadeddata");
  video.emit("playing");
  video.emit("timeupdate");
  assert.deepEqual(states, ["waiting"], "events alone are not decoded-video evidence");

  const first = onlyFrame(video);
  video.frame(first, { width: 0, height: 720 });
  assert.deepEqual(states, ["waiting"]);
  assert.equal(video.frameIds.length, 1, "invalid frames continue observation");

  video.frame(onlyFrame(video), { width: 1280, height: 720 });
  assert.deepEqual(states, ["waiting", "playing"]);
});

test("startup stays bounded, including when playback is blocked or paused", () => {
  for (const action of [
    (monitor) => monitor.playRejected({ name: "NotAllowedError" }),
    (monitor, video) => {
      video.paused = true;
      video.emit("pause");
    },
  ]) {
    const video = new FakeVideo();
    const { monitor, states, errors, clock } = monitorFor(video);
    monitor.start();
    action(monitor, video);
    clock.advance(frontend.LIVE_START_TIMEOUT_MS);
    assert.equal(errors.at(-1), "timeout");
    assert.equal(states[0], "waiting");
  }
});

test("buffering resumes only with a next progressing frame before the stall deadline", () => {
  const video = new FakeVideo();
  const { monitor, states, errors, clock } = monitorFor(video);
  monitor.start();
  video.videoWidth = 640;
  video.videoHeight = 480;
  video.frame(onlyFrame(video));
  assert.deepEqual(states, ["waiting", "playing"]);

  clock.advance(frontend.LIVE_STALL_TIMEOUT_MS - 1);
  video.emit("waiting");
  video.emit("stalled");
  assert.deepEqual(states, ["waiting", "playing", "buffering"]);

  // A resumed frame is the only event that may restore the live indication;
  // it must happen before the outstanding stall deadline expires.
  video.frame(onlyFrame(video));
  assert.equal(states.at(-1), "playing");
  assert.deepEqual(errors, []);
});

test("continuous media-time progress renews the stall deadline", () => {
  const video = new FakeVideo();
  const { monitor, errors, clock } = monitorFor(video);
  monitor.start();
  video.videoWidth = 640;
  video.videoHeight = 480;
  video.frame(onlyFrame(video), { mediaTime: 1 });

  clock.advance(frontend.LIVE_STALL_TIMEOUT_MS - 1_000);
  video.frame(onlyFrame(video), { mediaTime: 2 });
  clock.advance(frontend.LIVE_STALL_TIMEOUT_MS - 1);
  assert.deepEqual(errors, [], "the later real frame moved the deadline");
  clock.advance(1);
  assert.deepEqual(errors, ["stalled"]);
});

test("repeated callbacks for the same media time do not conceal a freeze", () => {
  const video = new FakeVideo();
  const { monitor, errors, clock } = monitorFor(video);
  monitor.start();
  video.videoWidth = 640;
  video.videoHeight = 480;
  video.frame(onlyFrame(video), { mediaTime: 7 });

  clock.advance(frontend.LIVE_STALL_TIMEOUT_MS - 1);
  video.frame(onlyFrame(video), { mediaTime: 7 });
  clock.advance(1);
  assert.deepEqual(errors, ["stalled"]);
  assert.equal(video.listenerCount, 0, "a terminal stall tears down listeners");
  assert.equal(video.frameIds.length, 0, "a terminal stall cancels rVFC");
});

test("advancing presentation counts keep video live even when mediaTime repeats", () => {
  const video = new FakeVideo();
  const { monitor, errors, clock } = monitorFor(video);
  monitor.start();
  video.videoWidth = 640;
  video.videoHeight = 480;
  video.frame(onlyFrame(video), { mediaTime: 0, presentedFrames: 1 });
  clock.advance(frontend.LIVE_STALL_TIMEOUT_MS - 1_000);
  video.frame(onlyFrame(video), { mediaTime: 0, presentedFrames: 60 });
  clock.advance(frontend.LIVE_STALL_TIMEOUT_MS - 1);
  assert.equal(monitor.state, "playing");
  assert.deepEqual(errors, []);
  clock.advance(1);
  assert.deepEqual(errors, ["stalled"]);
});

test("changing mediaTime cannot hide a non-advancing presentation counter", () => {
  const video = new FakeVideo();
  const { monitor, errors, clock } = monitorFor(video);
  monitor.start();
  video.videoWidth = 640;
  video.videoHeight = 480;
  video.frame(onlyFrame(video), { mediaTime: 0, presentedFrames: 8 });
  clock.advance(frontend.LIVE_STALL_TIMEOUT_MS - 1);
  video.frame(onlyFrame(video), { mediaTime: 1, presentedFrames: 8 });
  video.frame(onlyFrame(video), { mediaTime: 2, presentedFrames: 7 });
  video.frame(onlyFrame(video), { mediaTime: 3 });
  clock.advance(1);
  assert.deepEqual(errors, ["stalled"]);
});

test("without rVFC, fallback evidence needs dimensions, readiness, and an active video", () => {
  const video = new FakeVideo({ frameCallbacks: false });
  const { monitor, states } = monitorFor(video);
  monitor.start();

  video.emit("loadeddata");
  assert.deepEqual(states, ["waiting"]);
  video.readyState = 2;
  video.videoWidth = 1280;
  video.videoHeight = 720;
  video.paused = true;
  video.emit("timeupdate");
  assert.deepEqual(states, ["waiting"]);

  video.paused = false;
  video.emit("loadeddata");
  assert.deepEqual(states, ["waiting", "playing"]);
});

test("fallback quality counters require a rendered frame and detect a frozen counter", () => {
  const video = new FakeVideo({ frameCallbacks: false });
  const quality = { totalVideoFrames: 0, droppedVideoFrames: 0 };
  video.getVideoPlaybackQuality = () => quality;
  video.readyState = 2;
  video.videoWidth = 1280;
  video.videoHeight = 720;
  video.currentTime = 10;
  const { monitor, states, errors, clock } = monitorFor(video);
  monitor.start();
  video.emit("loadeddata");
  assert.deepEqual(states, ["waiting"], "zero rendered frames is not playback evidence");

  quality.totalVideoFrames = 1;
  video.emit("timeupdate");
  assert.deepEqual(states, ["waiting", "playing"]);

  // Clock movement in a media element can continue even while the decoded
  // picture is frozen; the quality frame key, not currentTime, is decisive.
  clock.advance(frontend.LIVE_STALL_TIMEOUT_MS - 1);
  video.currentTime = 20;
  video.emit("timeupdate");
  clock.advance(1);
  assert.deepEqual(errors, ["stalled"]);
});

test("terminal media and play failures have stable reason codes and ignore late callbacks", () => {
  for (const { reason, trigger } of [
    { reason: "playback-error", trigger: (monitor) => monitor.playRejected(new Error("network")) },
    { reason: "ended", trigger: (_monitor, video) => video.emit("ended") },
    { reason: "video-error", trigger: (_monitor, video) => video.emit("error") },
  ]) {
    const video = new FakeVideo();
    const { monitor, errors, clock } = monitorFor(video);
    monitor.start();
    const stale = onlyFrame(video);
    trigger(monitor, video);
    assert.deepEqual(errors, [reason]);
    assert.equal(video.listenerCount, 0);
    assert.equal(video.frameIds.length, 0);
    assert.equal(clock.timers.size, 0);

    video.lateFrame(stale, { width: 1280, height: 720, mediaTime: 1 });
    video.emit("error");
    assert.deepEqual(errors, [reason], "terminal cleanup rejects late activity");
  }
});

test("stop removes resources and an old rVFC callback cannot affect a new generation", () => {
  const video = new FakeVideo();
  const { monitor, states, errors, clock } = monitorFor(video);
  monitor.start();
  const stale = onlyFrame(video);
  monitor.stop();
  assert.equal(video.listenerCount, 0);
  assert.equal(video.frameIds.length, 0);
  assert.equal(clock.timers.size, 0);

  video.emit("error");
  video.lateFrame(stale, { width: 1280, height: 720 });
  assert.deepEqual(errors, []);
  assert.deepEqual(states, ["waiting"]);

  monitor.start();
  const current = onlyFrame(video);
  video.lateFrame(stale, { width: 1280, height: 720 });
  assert.deepEqual(states, ["waiting", "waiting"]);
  video.videoWidth = 1280;
  video.videoHeight = 720;
  video.frame(current);
  assert.equal(states.at(-1), "playing");
});
