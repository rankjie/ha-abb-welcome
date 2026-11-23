/*
 * Card-level live lifecycle: every invalidating event advances a generation,
 * so late arm/signaling completions cannot reopen media or overwrite current UI.
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

function makeHass(armStreaming, counters) {
  const hass = {
    connected: true,
    connection: {
      connected: true,
      subscribeMessage: (...args) => {
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
    callService: (domain, service, data) => {
      counters.services.push({ domain, service, data });
      return armStreaming();
    },
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
    services: [],
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
  test(`${kind} during arm prevents every late WebRTC continuation`, async () => {
    const armGate = deferred();
    const count = counters();
    installBrowser(() => {
      count.peers++;
      throw new Error("a stale arm must not create a peer");
    });
    const hass = makeHass(() => armGate.promise, count);
    const card = makeCard(hass, count);

    const pending = card._startLive();
    assert.equal(count.services.length, 1);
    const ownerToken = count.services[0].data.owner_token;
    assert.match(ownerToken, /^abbcard-/);
    invalidate(kind, card, hass);
    const statusAfterInvalidation = card._statusOverride;
    assert.equal(count.services.length, 2);
    assert.deepEqual(count.services[1].data, {
      entry_id: "entry-front",
      station_id: "station-front",
      owner_token: ownerToken,
      release: true,
    });

    armGate.resolve();
    await pending;
    assert.equal(card._live, false);
    assert.equal(card._webRtc, null);
    assert.equal(card._playerEl, null);
    assert.equal(count.ws.length, 0);
    assert.equal(count.peers, 0);
    assert.equal(count.mounts, 0);
    assert.equal(card._statusOverride, statusAfterInvalidation);
    assert.equal(count.services.length, 3);
    assert.deepEqual(count.services[2].data, count.services[1].data);
  });
}

test("late arm rejection after Stop is silent and does not retry", async () => {
  const armGate = deferred();
  const count = counters();
  installBrowser(() => {
    count.peers++;
    throw new Error("a stale arm must not create a peer");
  });
  const hass = makeHass(() => armGate.promise, count);
  const card = makeCard(hass, count);

  const pending = card._startLive();
  card._stopLive();
  const statusAfterStop = card._statusOverride;
  armGate.reject(new Error("late arm failure"));
  await pending;

  assert.equal(count.services.length, 3);
  assert.equal(count.ws.length, 0);
  assert.equal(count.peers, 0);
  assert.equal(card._statusOverride, statusAfterStop);
});

test("Stop releases a never-settling arm lease immediately and only once per phase", async () => {
  const never = deferred();
  const count = counters();
  installBrowser(() => {
    throw new Error("a pending arm must not create a peer");
  });
  const hass = makeHass(() => never.promise, count);
  const card = makeCard(hass, count);

  void card._startLive();
  await settle();
  assert.equal(count.services.length, 1);
  const ownerToken = count.services[0].data.owner_token;
  card._stopLive();
  card._stopLive();
  assert.equal(count.services.length, 2);
  assert.deepEqual(count.services[1].data, {
    entry_id: "entry-front",
    station_id: "station-front",
    owner_token: ownerToken,
    release: true,
  });
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
    assert.equal(count.services.length, 2);

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
  assert.equal(count.services.length, 2);
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

test("unsupported WebRTC fails before any arm service side effect", async () => {
  const count = counters();
  installBrowser(() => {
    throw new Error("not used");
  });
  delete globalThis.RTCPeerConnection;
  const hass = makeHass(async () => {}, count);
  const card = makeCard(hass, count);

  await card._startLive();
  assert.equal(count.services.length, 0);
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
