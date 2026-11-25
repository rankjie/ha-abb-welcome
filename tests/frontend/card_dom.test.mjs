/* Minimal DOM smoke test for the actual custom element (zero dependencies). */

import { test } from "node:test";
import assert from "node:assert/strict";

class FakeClassList {
  constructor() {
    this.values = new Set();
  }
  toggle(name, force) {
    const add = force === undefined ? !this.values.has(name) : force;
    if (add) this.values.add(name);
    else this.values.delete(name);
    return add;
  }
  contains(name) {
    return this.values.has(name);
  }
}

class FakeNode {
  constructor() {
    this.classList = new FakeClassList();
    this.listeners = new Map();
    this.attributes = new Map();
    this.children = [];
    this.disabled = false;
    this.textContent = "";
    this.innerHTML = "";
  }
  addEventListener(name, callback) {
    this.listeners.set(name, callback);
  }
  removeEventListener(name) {
    this.listeners.delete(name);
  }
  focus() {
    this.focused = true;
  }
  appendChild(child) {
    this.children.push(child);
    child.parent = this;
  }
  replaceChildren(...children) {
    this.textContent = "";
    this.children = [];
    children.forEach((child) => this.appendChild(child));
  }
  get childElementCount() {
    return this.children.length;
  }
  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }
  setPointerCapture() {}
  remove() {
    this.removed = true;
  }
}

class FakeVideo extends FakeNode {
  constructor() {
    super();
    this.muted = false;
    this.playCalls = 0;
    this.srcObject = null;
  }
  play() {
    this.playCalls++;
    return Promise.resolve();
  }
}

class FakeRoot extends FakeNode {
  constructor() {
    super();
    this.nodes = new Map(
      [
        ".name",
        ".ring-badge",
        ".version-badge",
        ".media",
        ".placeholder",
        ".placeholder-text",
        ".status",
        ".audio-info",
        ".mic-info",
        ".mic-summary",
        ".mic-detail",
        ".live-btn",
        ".play-btn",
        ".audio-btn",
        ".ptt-btn",
        ".unlock-btn",
        ".confirm-wrap",
        ".confirm-label",
        ".confirm-yes",
        ".confirm-no",
        ".call-history",
        ".history-summary",
        ".history-refresh",
        ".history-photo-switch",
        ".history-photo-label",
        ".history-latest",
        "#history-latest-picture",
        ".history-status",
        ".history-list",
      ].map((selector) => [selector, new FakeNode()])
    );
    this.nodes.get(".history-photo-switch").checked = true;
  }
  querySelector(selector) {
    return this.nodes.get(selector) || null;
  }
}

class FakeHTMLElement {
  attachShadow() {
    this.shadowRoot = new FakeRoot();
    return this.shadowRoot;
  }
}

test("native video unmute and mic-denied retry work through the real card", async (t) => {
  const registry = new Map();
  const documentListeners = new Map();
  const micTracks = [];
  const serviceCalls = [];
  let denyMic = true;
  globalThis.HTMLElement = FakeHTMLElement;
  globalThis.customElements = {
    get: (name) => registry.get(name),
    define: (name, constructor) => registry.set(name, constructor),
  };
  globalThis.window = {
    customCards: [],
    isSecureContext: true,
    addEventListener: () => {},
    removeEventListener: () => {},
    setTimeout,
    clearTimeout,
  };
  globalThis.document = {
    visibilityState: "visible",
    addEventListener: (name, callback) =>
      documentListeners.set(name, callback),
    removeEventListener: (name) => documentListeners.delete(name),
    createElement: (tag) => {
      if (tag === "video") return new FakeVideo();
      assert.ok(["li", "span", "time", "div", "button", "img", "p"].includes(tag));
      return Object.assign(new FakeNode(), { tag });
    },
  };
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: {
      mediaDevices: {
        getUserMedia: async () => {
          if (denyMic) throw new DOMException("denied", "NotAllowedError");
          const track = {
            readyState: "live",
            stops: 0,
            stop() {
              this.stops++;
              this.readyState = "ended";
            },
          };
          micTracks.push(track);
          return { getTracks: () => [track], getAudioTracks: () => [track] };
        },
      },
    },
  });

  const module = await import(process.env.ABB_CARD_TEST_MODULE ||
    "../../custom_components/abb_welcome/frontend/abb-welcome-intercom-card.js?dom-smoke");
  const Card = registry.get("abb-welcome-intercom-card");
  const card = new Card();
  card.setConfig({ camera: "camera.door", unlock_button: "button.unlock" });
  card.hass = {
    connected: true,
    connection: { connected: true },
    states: {
      "camera.door": {
        state: "idle",
        attributes: { friendly_name: "Door", talkback_ready: true },
      },
      "button.unlock": { state: "unknown", attributes: {} },
    },
    entities: {
      "camera.door": { device_id: "gateway", platform: "abb_welcome" },
    },
    devices: { gateway: { primary_config_entry: "entry" } },
    callService: async (domain, service, data) => {
      serviceCalls.push({ domain, service, data });
    },
  };
  card.connectedCallback();
  await t.test("ABB history loads only on demand and cleared photos never affect Live", async () => {
    const requests = [];
    let photoObserver;
    globalThis.IntersectionObserver = class {
      constructor(callback) { this.callback = callback; this.slots = new Set(); photoObserver = this; }
      observe(target) { this.slots.add(target); }
      unobserve(target) { this.slots.delete(target); }
      disconnect() { this.slots.clear(); }
      enter() {
        this.callback([...this.slots].map(target => ({ target, isIntersecting: true })));
      }
    };
    t.after(() => delete globalThis.IntersectionObserver);
    const calls = [
      { id: "ring-1", timestamp: "2026-11-20T11:00:00Z", station: "<b>Front door</b>", outcome: "missed", has_photo: true, photo_count: 2 },
      { id: "ring-2", station: "Garage", outcome: "ring", has_photo: false },
    ];
    const jpeg = () => new Response(new Uint8Array([255, 216, 255, 217]), {
      headers: { "content-type": "image/jpeg" },
    });
    let nextResponse = (path) => path.includes("call_id=") ? jpeg() : Response.json({
      photos_incomplete: true,
      calls: calls.map(row => ({ ...row, has_photo: false })),
    });
    card.hass = { ...card.hass, fetchWithAuth: async (path, options) => {
      requests.push({ path, ...options });
      return nextResponse(path);
    } };
    const { history, historySummary, historyList, historyRefresh, historyStatus,
      historyPhotoSwitch, historyPhotoLabel, media } = card._refs;
    const toggle = history.listeners.get("toggle");
    const togglePhotos = (enabled) => {
      historyPhotoSwitch.checked = enabled;
      historyPhotoSwitch.listeners.get("change")({ currentTarget: historyPhotoSwitch });
    };
    assert.equal(historySummary.textContent, "Call history");
    assert.equal(history.classList.contains("hidden"), false);
    assert.equal(history.open === true, false);
    assert.equal(requests.length, 0);
    history.open = true;
    const coldStart = toggle();
    assert.equal(historyStatus.textContent, "Loading from ABB…");
    assert.equal(historyStatus.classList.contains("is-loading"), true);
    await coldStart;
    assert.equal(historyStatus.classList.contains("is-loading"), false);
    assert.equal(requests[0].path, "/api/abb_welcome/call_history?camera=camera.door");
    assert.equal(requests[0].cache, "no-store");
    assert.equal(requests.length, 1);
    assert.equal(historyList.children.length, 2);
    assert.match(historyStatus.textContent, /Some photos could not be checked/);
    assert.equal(card._historyCache, null, "an incomplete response is not fresh cache");
    assert.equal(historyList.children[0].children.length, 2);
    nextResponse = (path) => path.includes("call_id=") ? jpeg() : Response.json({ calls });
    await historyRefresh.listeners.get("click")();
    assert.ok(requests[1].path.endsWith("&fresh=1"));
    assert.equal(historyStatus.textContent, "");
    const [time, detail, picture, secondPicture] = historyList.children[0].children;
    assert.equal(time.dateTime, "2026-11-20T11:00:00.000Z");
    assert.equal(detail.textContent, "<b>Front door</b> · Missed");
    assert.equal(historyList.children[1].children.length, 2);
    assert.equal(picture.tag, "div", "no per-row photo button");
    assert.match(card.shadowRoot.innerHTML, /<ha-switch class="history-photo-switch" checked>/);
    assert.doesNotMatch(card.shadowRoot.innerHTML, /type="checkbox"/);
    assert.equal(historyPhotoLabel.textContent, "Screenshots");
    assert.equal(historyPhotoSwitch.attributes.get("aria-label"), "Screenshots");
    assert.equal(historyPhotoSwitch.checked, true);
    assert.equal(requests.length, 2, "offscreen photos wait");
    photoObserver.enter();
    await new Promise(setImmediate);
    assert.equal(requests[2].path, "/api/abb_welcome/call_history?camera=camera.door&call_id=ring-1");
    assert.equal(requests[3].path, requests[2].path + "&photo_index=1");
    const [image] = picture.children;
    assert.equal(image.tag, "img");
    assert.match(image.src, /^blob:/);
    assert.equal(secondPicture.children[0].tag, "img");
    assert.deepEqual(media.children, []);
    assert.deepEqual(serviceCalls, []);
    assert.equal(card._live, false);

    let respondToPhoto;
    nextResponse = () => new Promise(resolve => { respondToPhoto = resolve; });
    togglePhotos(false);
    assert.deepEqual(picture.children, []);
    assert.deepEqual(secondPicture.children, []);
    await assert.rejects(fetch(image.src));
    togglePhotos(true);
    photoObserver.enter();
    const photoSignal = requests.at(-1).signal;
    togglePhotos(false);
    assert.equal(photoSignal.aborted, true);
    respondToPhoto(jpeg());
    await new Promise(setImmediate);
    assert.deepEqual(secondPicture.children, [], "late response cannot restore a hidden photo");

    history.open = false;
    await toggle();
    assert.equal(historyList.children.length, 0);
    assert.equal(picture.children.length, 0);

    let resolveRefresh;
    nextResponse = () => new Promise((resolve) => { resolveRefresh = resolve; });
    history.open = true;
    const revalidate = toggle();
    assert.equal(historyList.children.length, 2, "cached rows appear before ABB responds");
    assert.equal(historyStatus.textContent, "Updating from ABB…");
    assert.equal(historyStatus.classList.contains("is-loading"), true);
    resolveRefresh(new Response(null, { status: 502 }));
    await revalidate;
    assert.equal(historyStatus.textContent, "Showing last loaded calls — ABB could not be reached");
    assert.equal(historyList.children.length, 2);
    assert.equal(historyStatus.classList.contains("is-loading"), false);
    assert.deepEqual(serviceCalls, []);

    nextResponse = () => Response.json({ calls: [
      { id: "new-ring", station: "Entry", outcome: "answered", has_photo: false },
    ] });
    await historyRefresh.listeners.get("click")();
    assert.equal(historyStatus.textContent, "");
    assert.equal(historyList.children.length, 1);
    assert.equal(historyList.children[0].children[1].textContent, "Entry · Answered");
    history.open = false;
    await toggle();

    card._closeCallHistory(true); // same empty client cache as after a page reload
    let resolveFresh;
    nextResponse = (path) => path.endsWith("&fresh=1")
      ? new Promise((resolve) => { resolveFresh = resolve; })
      : Response.json({ calls: [{ id: "ha-cached", station: "Side gate", outcome: "ring" }], stale: true });
    history.open = true;
    const backgroundRefresh = toggle();
    await new Promise(setImmediate);
    assert.equal(historyList.children.length, 1);
    assert.match(historyList.children[0].children[1].textContent, /Side gate/);
    assert.equal(historyStatus.textContent, "Updating from ABB…");
    assert.equal(historyStatus.classList.contains("is-loading"), true);
    assert.ok(requests.at(-1).path.endsWith("&fresh=1"));
    resolveFresh(Response.json({ calls: [{ id: "ha-new", station: "Main gate", outcome: "missed" }] }));
    await backgroundRefresh;
    assert.match(historyList.children[0].children[1].textContent, /Main gate/);
    assert.equal(historyStatus.classList.contains("is-loading"), false);
    history.open = false;
    await toggle();

    history.open = true;
    nextResponse = () => new Response(null, { status: 403 });
    await toggle();
    assert.equal(historyStatus.textContent, "You do not have permission to view this history");
    assert.equal(card._historyCache, null);
    assert.equal(historyList.children.length, 0);
    assert.equal(historyRefresh.disabled, false);

    let respond;
    nextResponse = () => new Promise((resolve) => { respond = resolve; });
    const late = historyRefresh.listeners.get("click")();
    history.open = false;
    await toggle();
    assert.equal(requests.at(-1).signal.aborted, true);
    respond(Response.json({ calls: [{ id: "late", has_photo: true }] }));
    await late;
    assert.equal(historyList.children.length, 0);
    assert.equal(historyStatus.textContent, "");
  });
  await t.test("the idle video button starts Live once and leaves Stop focused", (t) => {
    const { placeholder, placeholderText, liveBtn } = card._refs;
    assert.match(card.shadowRoot.innerHTML, /<button class="placeholder" type="button" disabled>/);
    assert.equal(placeholder.disabled, false);
    assert.equal(placeholderText.textContent, "Start live video");
    assert.equal(card._playerEl, null);
    assert.deepEqual(serviceCalls, []);

    const startLive = t.mock.method(card, "_startLive", () => {
      card._live = "starting";
      card._render();
    });
    card.shadowRoot.activeElement = placeholder;
    const activatePlaceholder = placeholder.listeners.get("click");
    activatePlaceholder();
    assert.equal(startLive.mock.callCount(), 1);
    assert.equal(liveBtn.focused, true);
    assert.equal(liveBtn.textContent, "Stop");
    assert.equal(placeholder.disabled, true);
    assert.equal(placeholderText.textContent, "Connecting…");
    activatePlaceholder();
    assert.equal(startLive.mock.callCount(), 1);

    liveBtn.listeners.get("click")();
    assert.equal(placeholder.disabled, false);
    assert.equal(placeholderText.textContent, "Start live video");
  });
  card._mountPlayer();
  card._live = "starting";
  card._render();
  const headerMarkup =
    card.shadowRoot.innerHTML.match(
      /<div class="header">([\s\S]*?)<\/div>/
    )?.[1] || "";
  assert.match(headerMarkup, /class="version-badge"/);
  assert.equal(card._refs.versionBadge.textContent, `v${module.CARD_VERSION}`);
  assert.equal(
    card._refs.versionBadge.title,
    `ABB Welcome Intercom Card v${module.CARD_VERSION}`
  );
  assert.equal(
    card._refs.versionBadge.attributes.get("aria-label"),
    `ABB Welcome Intercom Card version ${module.CARD_VERSION}`
  );
  assert.equal(card._refs.liveBtn.textContent, "Stop");
  assert.equal(card._refs.liveBtn.disabled, false);

  card._live = true;
  card._machine.state = "mic_denied";
  card._render();

  assert.equal(card._playerEl.muted, true);
  assert.equal(card._refs.pttBtn.disabled, false);
  card._playerEl.muted = false;
  card._playerEl.volume = 1;
  card._playerEl.listeners.get("volumechange")();
  assert.equal(card._audioUnmuted, true);
  card._playerEl.muted = true;
  card._playerEl.listeners.get("volumechange")();
  assert.equal(card._audioUnmuted, false);
  card._toggleAudio();
  assert.equal(card._playerEl.muted, false);
  assert.equal(card._playerEl.playCalls, 1);
  assert.equal(card._refs.audioBtn.classList.contains("active"), true);
  assert.equal(card._refs.audioBtn.attributes.get("aria-pressed"), "true");

  globalThis.document.visibilityState = "hidden";
  documentListeners.get("visibilitychange")();
  assert.equal(card._live, false);
  assert.equal(card._playerEl, null);
  documentListeners.get("visibilitychange")();
  assert.equal(card._playerEl, null);

  card._flashStatus("stale status", true);
  assert.equal(card._statusOverride, "stale status");

  const unlockBeforeDisconnect = card._unlock;
  card.disconnectedCallback();
  assert.equal(card._playerEl, null);
  assert.equal(card._unlock, null);
  assert.equal(card._statusOverride, "");
  assert.equal(card._statusOverrideError, false);

  globalThis.document.visibilityState = "visible";
  card.connectedCallback();
  const machineAfterReconnect = card._machine;
  assert.ok(card._unlock);
  assert.notEqual(card._unlock, unlockBeforeDisconnect);
  card._unlock.tap();
  assert.equal(card._unlock.state, "confirm");
  card._unlock.cancel();
  assert.equal(card._statusOverride, "");

  card._live = true;
  let currentTrack;
  card._webRtc = {
    nativeMicReady: true,
    async setNativeMicTrack(track) { currentTrack = track; return true; },
    stop() {},
  };
  card.hass = card.hass;
  card._render();
  assert.equal(card._refs.pttBtn.disabled, false);
  const press = () => card._refs.pttBtn.listeners.get("pointerdown")({
    pointerId: 1,
    preventDefault() {},
  });
  press();
  for (let i = 0; i < 8; i++) await Promise.resolve();
  assert.equal(card._machine.state, "mic_denied");
  assert.equal(micTracks.length, 0);
  card._refs.pttBtn.listeners.get("pointerup")();
  denyMic = false;
  press();
  for (let i = 0; i < 8; i++) await Promise.resolve();
  assert.equal(card._machine, machineAfterReconnect);
  assert.equal(card._machine.state, "talking");
  assert.equal(currentTrack, micTracks.at(-1));
  assert.equal(micTracks.at(-1).stops, 0);
  card._refs.pttBtn.listeners.get("pointerup")();
  assert.equal(micTracks.at(-1).stops, 1);
  assert.equal(currentTrack, null);
  assert.equal(card._live, true);
  assert.ok(serviceCalls.every(({ service }) => !service.startsWith("talk_")));
  card.disconnectedCallback();
});
