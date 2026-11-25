/*
 * Cross-profile frontend contract. The card consumes only public entity
 * metadata and ABB services: profile selection stays entirely in the backend.
 */

import { readFile } from "node:fs/promises";
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  AbbWelcomeIntercomCard,
  STRINGS,
} from "../../custom_components/abb_welcome/frontend/abb-welcome-intercom-card.js";
import { deferred } from "./_harness.mjs";

function installWindowStub() {
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
  globalThis.RTCPeerConnection = class {
    constructor() {
      this.signalingState = "have-local-offer";
      this.iceConnectionState = "new";
    }
    addTransceiver() {}
    async createOffer() {
      return { type: "offer", sdp: "offer-sdp" };
    }
    async setLocalDescription() {}
    close() {}
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
  return timers;
}

function profileFixture(profile) {
  if (profile === "mrange_ip_gateway") {
    return {
      config: { camera: "camera.front" },
      hass: {
        connected: true,
        connection: {
          connected: true,
          subscribeMessage: async () => () => {},
        },
        states: {
          "camera.front": {
            state: "idle",
            attributes: {
              config_entry_id: "entry-mrange",
              station_id: "1001",
              talkback_ready: false,
            },
          },
        },
        entities: {
          "camera.front": {
            device_id: "gateway-mrange",
            platform: "abb_welcome",
          },
        },
        devices: {
          "gateway-mrange": { primary_config_entry: "entry-mrange" },
        },
        callWS: async () => ({ configuration: {} }),
      },
      scope: { entry_id: "entry-mrange", station_id: "1001" },
    };
  }
  return {
    config: { camera: "camera.lobby", station_id: "1000000042" },
    hass: {
      connected: true,
      connection: {
        connected: true,
        subscribeMessage: async () => () => {},
      },
      states: {
        "camera.lobby": {
          state: "idle",
          attributes: { talkback_ready: false },
        },
      },
      entities: {
        "camera.lobby": {
          device_id: "gateway-wifi",
          platform: "abb_welcome",
          config_entry_id: "entry-wifi",
        },
      },
      devices: {
        "gateway-wifi": { primary_config_entry: "entry-wifi" },
      },
      callWS: async () => ({ configuration: {} }),
    },
    scope: { entry_id: "entry-wifi", station_id: "1000000042" },
  };
}

for (const profile of ["mrange_ip_gateway", "m22401_wifi_station"]) {
  test(`${profile}: idle is neutral and Live arms exactly one scoped station`, async () => {
    installWindowStub();
    const fixture = profileFixture(profile);
    const calls = [];
    const windows = [];
    fixture.hass.callService = async (domain, service, data) => {
      calls.push({ domain, service, data });
    };
    const subscribe = fixture.hass.connection.subscribeMessage;
    fixture.hass.connection.subscribeMessage = async (callback, message, options) => {
      if (message.type !== "abb_welcome/live") return subscribe(callback, message, options);
      const window = { message, releases: 0 };
      windows.push(window);
      return () => { window.releases++; };
    };

    const card = new AbbWelcomeIntercomCard();
    card.setConfig(fixture.config);
    card.hass = fixture.hass;
    card._mountPlayer = () => {
      card._playerEl = {
        srcObject: null,
        play: async () => {},
        remove: () => {},
      };
    };

    assert.deepEqual(calls, []);
    assert.deepEqual(windows, []);
    assert.equal(card._live, false);
    assert.equal(card._playerEl, null);
    assert.equal(card._webRtc, null);

    await card._startLive();
    assert.deepEqual(calls, []);
    assert.deepEqual(windows.map(({ message }) => message), [
      { type: "abb_welcome/live", ...fixture.scope },
    ]);
    assert.equal(card._live, true);

    card._stopLive();
    assert.equal(windows[0].releases, 1);
    assert.equal(card._live, false);
    assert.equal(card._playerEl, null);
  });
}

test("Live is fail-closed and side-effect free when persistent scope is incomplete", async () => {
  installWindowStub();
  const calls = [];
  const card = new AbbWelcomeIntercomCard();
  card.setConfig({ camera: "camera.incomplete" });
  card.hass = {
    connected: true,
    connection: { connected: true },
    states: {
      "camera.incomplete": {
        state: "idle",
        attributes: { config_entry_id: "entry-without-station" },
      },
    },
    entities: {
      "camera.incomplete": {
        device_id: "gateway",
        platform: "abb_welcome",
      },
    },
    devices: { gateway: { primary_config_entry: "entry-without-station" } },
    callService: async (...args) => calls.push(args),
  };

  await card._startLive();
  assert.deepEqual(calls, []);
  assert.equal(card._live, false);
  assert.match(card._statusOverride, new RegExp(STRINGS.en.err_missing_scope));
});

test("config change disposes an uncertain unlock without stale UI or retry", async () => {
  installWindowStub();
  const pressGate = deferred();
  const calls = [];
  const card = new AbbWelcomeIntercomCard();
  card.setConfig({
    camera: "camera.front",
    unlock_button: "button.unlock_front",
  });
  card.hass = {
    connected: true,
    connection: { connected: true },
    states: {
      "camera.front": { state: "idle", attributes: {} },
      "camera.back": { state: "idle", attributes: {} },
      "button.unlock_front": { state: "unknown", attributes: {} },
      "button.unlock_back": { state: "2026-11-20T10:00:00+00:00", attributes: {} },
    },
    entities: {},
    devices: {},
    callService: (domain, service, data) => {
      calls.push({ domain, service, data });
      return pressGate.promise;
    },
  };

  const oldUnlock = card._unlock;
  oldUnlock.tap();
  const pending = oldUnlock.confirm();
  assert.deepEqual(calls, [
    {
      domain: "button",
      service: "press",
      data: { entity_id: "button.unlock_front" },
    },
  ]);

  card.setConfig({
    camera: "camera.back",
    unlock_button: "button.unlock_back",
  });
  pressGate.resolve();
  assert.equal(await pending, false);
  assert.equal(card._statusOverride, "");
  assert.equal(card._unlock.state, "idle");
  assert.equal(calls.length, 1);

  card._unlock.tap();
  card._unlock.cancel();
  assert.equal(card._statusOverride, "");
  assert.equal(calls.length, 1);
});

test("HA disconnect invalidates in-flight unlock and reconnect creates a fresh machine", async () => {
  installWindowStub();
  const pressGate = deferred();
  const calls = [];
  const connectedHass = {
    connected: true,
    connection: { connected: true },
    states: {
      "camera.front": { state: "idle", attributes: {} },
      "button.unlock_front": { state: "2026-11-20T10:00:00+00:00", attributes: {} },
    },
    entities: {},
    devices: {},
    callService: (domain, service, data) => {
      calls.push({ domain, service, data });
      return pressGate.promise;
    },
  };
  const card = new AbbWelcomeIntercomCard();
  card.setConfig({
    camera: "camera.front",
    unlock_button: "button.unlock_front",
  });
  card.hass = connectedHass;

  const oldUnlock = card._unlock;
  oldUnlock.tap();
  const pending = oldUnlock.confirm();
  assert.equal(calls.length, 1);

  card.hass = {
    ...connectedHass,
    connected: false,
    connection: { connected: false },
  };
  assert.equal(card._unlock, null);
  const disconnectedStatus = card._statusOverride;
  assert.equal(disconnectedStatus, STRINGS.en.disconnected);

  pressGate.resolve();
  assert.equal(await pending, false);
  assert.equal(card._statusOverride, disconnectedStatus);
  assert.equal(calls.length, 1);

  card.hass = { ...connectedHass, connection: { connected: true } };
  assert.ok(card._unlock);
  assert.notEqual(card._unlock, oldUnlock);
  assert.equal(card._unlock.state, "idle");
  assert.equal(card._statusOverride, "");
  assert.equal(calls.length, 1);
});

test("automatic unlock snapshots the exact door at the first tap", async () => {
  installWindowStub();
  const calls = [];
  const hass = {
    connected: true,
    connection: { connected: true },
    states: {
      "camera.door": {
        state: "idle",
        attributes: { station_id: "front" },
      },
      "button.front": { state: "2026-11-20T10:00:00+00:00", attributes: {} },
      "button.back": { state: "2026-11-20T10:00:00+00:00", attributes: {} },
    },
    entities: {
      "camera.door": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_camera_front",
      },
      "button.front": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_front",
      },
      "button.back": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_back",
      },
    },
    devices: {},
    callService: async (domain, service, data) => {
      calls.push({ domain, service, data });
    },
  };
  const card = new AbbWelcomeIntercomCard();
  card.setConfig({ camera: "camera.door" });
  card.hass = hass;

  assert.equal(card._unlock.tap(), true);
  hass.states["camera.door"].attributes.station_id = "back";
  hass.entities["camera.door"].unique_id = "gw_camera_back";
  assert.equal(await card._unlock.confirm(), true);
  assert.deepEqual(calls, [
    {
      domain: "button",
      service: "press",
      data: { entity_id: "button.front" },
    },
  ]);
});

test("a snapshotted unlock that disappears fails closed and never switches doors", async () => {
  installWindowStub();
  const calls = [];
  const hass = {
    connected: true,
    connection: { connected: true },
    states: {
      "camera.door": {
        state: "idle",
        attributes: { station_id: "front" },
      },
      "button.front": { state: "2026-11-20T10:00:00+00:00", attributes: {} },
      "button.back": { state: "2026-11-20T10:00:00+00:00", attributes: {} },
    },
    entities: {
      "camera.door": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_camera_front",
      },
      "button.front": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_front",
      },
      "button.back": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_back",
      },
    },
    devices: {},
    callService: async (...args) => calls.push(args),
  };
  const card = new AbbWelcomeIntercomCard();
  card.setConfig({ camera: "camera.door" });
  card.hass = hass;

  card._unlock.tap();
  delete hass.states["button.front"];
  hass.states["camera.door"].attributes.station_id = "back";
  hass.entities["camera.door"].unique_id = "gw_camera_back";
  assert.equal(await card._unlock.confirm(), false);
  assert.equal(card._unlock.state, "error");
  assert.deepEqual(calls, []);
});

test("visibility hidden invalidates open and in-flight unlock confirmation", async () => {
  installWindowStub();
  globalThis.document = { visibilityState: "visible" };
  const pressGate = deferred();
  const calls = [];
  const hass = {
    connected: true,
    connection: { connected: true },
    states: {
      "camera.front": { state: "idle", attributes: {} },
      "button.front": { state: "2026-11-20T10:00:00+00:00", attributes: {} },
    },
    entities: {},
    devices: {},
    callService: (domain, service, data) => {
      calls.push({ domain, service, data });
      return pressGate.promise;
    },
  };
  const card = new AbbWelcomeIntercomCard();
  card.setConfig({ camera: "camera.front", unlock_button: "button.front" });
  card.hass = hass;

  const openConfirm = card._unlock;
  openConfirm.tap();
  globalThis.document.visibilityState = "hidden";
  card._handleVisibilityChange();
  assert.equal(card._unlock, null);
  assert.equal(await openConfirm.confirm(), false);
  assert.deepEqual(calls, []);

  globalThis.document.visibilityState = "visible";
  card._handleVisibilityChange();
  const inFlight = card._unlock;
  assert.notEqual(inFlight, openConfirm);
  inFlight.tap();
  const pending = inFlight.confirm();
  assert.equal(calls.length, 1);
  globalThis.document.visibilityState = "hidden";
  card._handleVisibilityChange();
  const statusAfterHidden = card._statusOverride;
  pressGate.resolve();
  assert.equal(await pending, false);
  assert.equal(card._statusOverride, statusAfterHidden);
  assert.equal(calls.length, 1);

  globalThis.document.visibilityState = "visible";
  card._handleVisibilityChange();
  assert.ok(card._unlock);
  assert.notEqual(card._unlock, inFlight);
  assert.equal(card._unlock.state, "idle");
});

test("frontend production assets contain no gateway model branch tokens", async () => {
  const cardSource = await readFile(
    new URL(
      "../../custom_components/abb_welcome/frontend/abb-welcome-intercom-card.js",
      import.meta.url
    ),
    "utf8"
  );
  const modelToken = /m22401|mrange|wifi_panel|ip_gateway|gateway_kind|device_type/i;
  assert.doesNotMatch(cardSource, modelToken);
  assert.doesNotMatch(cardSource, /talk_(?:start|pcm16le|stop)|AudioWorklet/);
});

test("Unlock stays available until the button itself is unavailable", () => {
  const card = new AbbWelcomeIntercomCard();
  const withState = (state) => {
    card._hass = { states: state === undefined ? {} : { "button.front": { state, attributes: {} } } };
    return card._isUnlockEntityValid("button.front");
  };
  assert.equal(withState("unknown"), true, "a button never pressed from HA");
  assert.equal(withState("2026-11-20T10:00:00+00:00"), true);
  assert.equal(withState("unavailable"), false);
  assert.equal(withState(undefined), false);
});
