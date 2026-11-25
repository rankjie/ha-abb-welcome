/*
 * Card-level live lifecycle: every invalidating event advances a generation,
 * so late live-window/signaling completions cannot reopen media or overwrite current UI.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AbbWelcomeIntercomCard } from "../../custom_components/abb_welcome/frontend/abb-welcome-intercom-card.js";
import { deferred, settle } from "./_harness.mjs";

function installBrowser(peerFactory) {
  let nextTimer = 0;
  const timers = new Map();
  globalThis.window = {
    isSecureContext: true,
    setTimeout: (fn, ms) => {
      const id = ++nextTimer;
      timers.set(id, { fn, ms });
      return id;
    },
    clearTimeout: (id) => timers.delete(id),
  };
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: { mediaDevices: { getUserMedia: async () => null } },
  });
  globalThis.RTCPeerConnection = class {
    constructor(configuration) {
      return peerFactory(configuration);
    }
  };
  globalThis.MediaStream = class {
    constructor() {
      this.tracks = [];
    }
    addTrack(track) {
      this.tracks.push(track);
    }
    getTracks() {
      return this.tracks;
    }
  };
}

function makeHass(liveWindow, counters) {
  const hass = {
    connected: true,
    connection: {
      connected: true,
      subscribeMessage: (...args) => {
        if (args[1]?.type === "abb_welcome/live") {
          counters.live.push(args);
          return liveWindow().then(() => () => counters.liveReleases++);
        }
        counters.subscriptions.push(args);
        return Promise.resolve(() => counters.unsubscribes++);
      },
    },
    states: {
      "camera.front": {
        state: "idle",
        attributes: {
          config_entry_id: "entry-front",
          station_id: "station-front",
          talkback_ready: false,
        },
      },
    },
    entities: {
      "camera.front": {
        device_id: "gateway",
        platform: "abb_welcome",
      },
    },
    devices: { gateway: { primary_config_entry: "entry-front" } },
    callWS: async (message) => {
      counters.ws.push(message);
      return { configuration: {} };
    },
  };
  return hass;
}

function makeCard(hass, counters) {
  const card = new AbbWelcomeIntercomCard();
  card.setConfig({
    camera: "camera.front",
    unlock_button: "button.front",
  });
  card.hass = hass;
  card._mountPlayer = () => {
    counters.mounts++;
    card._playerEl = {
      srcObject: null,
      play: async () => {},
      remove: () => counters.removals++,
    };
  };
  return card;
}

function invalidate(kind, card, hass) {
  if (kind === "stop") {
    card._stopLive();
    return;
  }
  if (kind === "config-change") {
    card.setConfig({
      camera: "camera.other",
      unlock_button: "button.other",
      station_id: "station-other",
    });
    return;
  }
  if (kind === "hass-disconnect") {
    card.hass = {
      ...hass,
      connected: false,
      connection: { ...hass.connection, connected: false },
    };
    return;
  }
  if (kind === "dom-disconnect") {
    card.disconnectedCallback();
    return;
  }
  if (kind === "visibility-hidden") {
    globalThis.document = { visibilityState: "hidden" };
    card._handleVisibilityChange();
    return;
  }
  throw new Error(`unknown invalidator: ${kind}`);
}

function counters() {
  return {
    live: [],
    liveReleases: 0,
    ws: [],
    subscriptions: [],
    unsubscribes: 0,
    peers: 0,
    closes: 0,
    offers: 0,
    mounts: 0,
    removals: 0,
  };
}

for (const kind of [
  "stop",
  "config-change",
  "hass-disconnect",
  "dom-disconnect",
  "visibility-hidden",
]) {
  test(`${kind} while the live window is pending prevents every late WebRTC continuation`, async () => {
    const windowGate = deferred();
    const count = counters();
    installBrowser(() => {
      count.peers++;
      throw new Error("a stale live window must not create a peer");
    });
    const hass = makeHass(() => windowGate.promise, count);
    const card = makeCard(hass, count);

    const pending = card._startLive();
    assert.equal(count.live.length, 1);
    assert.deepEqual(count.live[0][1], {
      type: "abb_welcome/live",
      entry_id: "entry-front",
      station_id: "station-front",
    });
    assert.deepEqual(count.live[0][2], { resubscribe: false });
    invalidate(kind, card, hass);
    const statusAfterInvalidation = card._statusOverride;

    windowGate.resolve();
    await pending;
    assert.equal(count.liveReleases, 1, "the late grant is released at once");
    assert.equal(card._live, false);
    assert.equal(card._webRtc, null);
    assert.equal(card._playerEl, null);
    assert.equal(count.ws.length, 0);
    assert.equal(count.peers, 0);
    assert.equal(count.mounts, 0);
    assert.equal(card._statusOverride, statusAfterInvalidation);
  });
}

test("a late live window refusal after Stop is silent and does not retry", async () => {
  const windowGate = deferred();
  const count = counters();
  installBrowser(() => {
    count.peers++;
    throw new Error("a stale live window must not create a peer");
  });
  const hass = makeHass(() => windowGate.promise, count);
  const card = makeCard(hass, count);

  const pending = card._startLive();
  card._stopLive();
  card._stopLive();
  const statusAfterStop = card._statusOverride;
  windowGate.reject({ code: "station_busy", message: "Another station is already armed" });
  await pending;

  assert.equal(count.live.length, 1);
  assert.equal(count.liveReleases, 0);
  assert.equal(count.ws.length, 0);
  assert.equal(count.peers, 0);
  assert.equal(card._statusOverride, statusAfterStop);
});

test("a refused live window stops Live and shows why", async () => {
  const count = counters();
  installBrowser(() => {
    count.peers++;
    throw new Error("a refused live window must not create a peer");
  });
  const hass = makeHass(
    () => Promise.reject({ code: "station_busy", message: "Another station is already armed" }),
    count
  );
  const card = makeCard(hass, count);

  await card._startLive();
  assert.equal(card._live, false);
  assert.equal(count.peers, 0);
  assert.match(card._statusOverride, /Another station is already armed/);
});

function pendingOfferFixture() {
  const offerGate = deferred();
  const count = counters();
  const peer = {
    signalingState: "have-local-offer",
    iceConnectionState: "new",
    addTransceiver: () => {},
    createOffer: () => {
      count.offers++;
      return offerGate.promise;
    },
    setLocalDescription: async () => {},
    addIceCandidate: async () => {},
    close: () => count.closes++,
  };
  installBrowser(() => {
    count.peers++;
    return peer;
  });
  const hass = makeHass(async () => {}, count);
  const card = makeCard(hass, count);
  return { offerGate, count, peer, hass, card };
}

for (const kind of [
  "stop",
  "config-change",
  "hass-disconnect",
  "dom-disconnect",
  "visibility-hidden",
]) {
  test(`${kind} during WebRTC start closes the pending session exactly once`, async () => {
    const { offerGate, count, hass, card } = pendingOfferFixture();
    const pending = card._startLive();
    await settle();
    assert.equal(count.offers, 1);
    assert.equal(count.peers, 1);
    assert.ok(card._webRtc);
    assert.ok(card._playerEl);

    invalidate(kind, card, hass);
    const statusAfterInvalidation = card._statusOverride;
    assert.equal(count.closes, 1);
    assert.equal(count.removals, 1);
    assert.equal(card._webRtc, null);
    assert.equal(card._playerEl, null);
    assert.equal(count.liveReleases, 1);

    offerGate.resolve({ type: "offer", sdp: "late-offer" });
    await pending;
    assert.equal(count.closes, 1);
    assert.equal(count.removals, 1);
    assert.equal(count.subscriptions.length, 0);
    assert.equal(card._live, false);
    assert.equal(card._webRtc, null);
    assert.equal(card._statusOverride, statusAfterInvalidation);
  });
}

test("late WebRTC start rejection after config change is silent", async () => {
  const { offerGate, count, hass, card } = pendingOfferFixture();
  const pending = card._startLive();
  await settle();
  invalidate("config-change", card, hass);
  const statusAfterChange = card._statusOverride;

  offerGate.reject(new Error("late createOffer failure"));
  await pending;
  assert.equal(count.closes, 1);
  assert.equal(count.removals, 1);
  assert.equal(count.subscriptions.length, 0);
  assert.equal(card._webRtc, null);
  assert.equal(card._statusOverride, statusAfterChange);
  assert.equal(count.liveReleases, 1);
});

test("talkback readiness that arrives during signaling is applied when Live opens", async () => {
  const { offerGate, count, peer, hass, card } = pendingOfferFixture();
  const callWS = hass.callWS;
  hass.callWS = (msg) => msg.type === "camera/capabilities"
    ? Promise.resolve({ two_way_audio: true }) : callWS(msg);
  const audio = { sender: { async replaceTrack() {} }, currentDirection: null };
  peer.addTransceiver = (kind) => kind === "audio" ? audio : {};
  peer.setRemoteDescription = async () => { audio.currentDirection = "sendrecv"; };
  const pending = card._startLive();
  await settle();
  hass.states["camera.front"].attributes.talkback_ready = true;
  card.hass = hass;
  assert.equal(card._machine.state, "blocked");

  offerGate.resolve({ type: "offer", sdp: "offer" });
  await pending;
  assert.equal(card._live, true);
  assert.equal(card._machine.state, "blocked", "camera readiness alone cannot open the mic");
  count.subscriptions[0][0]({ type: "answer", answer: "answer" });
  await settle();
  assert.equal(card._machine.state, "idle");
  card._stopLive();
});

test("unsupported WebRTC fails before the station is armed", async () => {
  const count = counters();
  installBrowser(() => {
    throw new Error("not used");
  });
  delete globalThis.RTCPeerConnection;
  const hass = makeHass(async () => {}, count);
  const card = makeCard(hass, count);

  await card._startLive();
  assert.equal(count.live.length, 0);
  assert.equal(card._live, false);
  assert.equal(card._webRtc, null);
});

test("visibility hidden closes an active live session once and is idempotent", () => {
  const count = counters();
  installBrowser(() => {
    throw new Error("not used");
  });
  globalThis.document = { visibilityState: "hidden" };
  const hass = makeHass(async () => {}, count);
  const card = makeCard(hass, count);
  card._live = true;
  card._webRtc = { stop: () => count.closes++ };
  card._playerEl = {
    srcObject: {},
    remove: () => count.removals++,
  };

  card._handleVisibilityChange();
  card._handleVisibilityChange();
  assert.equal(card._live, false);
  assert.equal(card._webRtc, null);
  assert.equal(card._playerEl, null);
  assert.equal(count.closes, 1);
  assert.equal(count.removals, 1);
});
