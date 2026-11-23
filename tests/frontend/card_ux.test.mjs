/* Keyboard and confirmation UX regressions for the actual card element. */

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
  constructor(root = null) {
    this.root = root;
    this.classList = new FakeClassList();
    this.listeners = new Map();
    this.attributes = new Map();
    this.children = [];
    this.disabled = false;
    this.textContent = "";
    this.innerHTML = "";
  }
  addEventListener(name, callback) {
    if (!this.listeners.has(name)) this.listeners.set(name, new Set());
    this.listeners.get(name).add(callback);
  }
  removeEventListener(name, callback) {
    this.listeners.get(name)?.delete(callback);
  }
  dispatch(name, event = {}) {
    for (const callback of this.listeners.get(name) || []) callback(event);
  }
  appendChild(child) {
    this.children.push(child);
    child.parent = this;
  }
  replaceChildren() {
    this.children = [];
    this.textContent = "";
  }
  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }
  setPointerCapture() {}
  focus() {
    if (this.root) this.root.activeElement = this;
    if (globalThis.document) globalThis.document.activeElement = this;
  }
  remove() {
    this.removed = true;
  }
}

class FakeVideo extends FakeNode {
  removeEventListener(name, callback) {
    super.removeEventListener(name, callback);
  }
  play() {
    return Promise.resolve();
  }
}

class FakeRoot extends FakeNode {
  constructor() {
    super();
    this.nodes = new Map();
    for (const selector of [
      ".name",
      ".ring-badge",
      ".version-badge",
      ".media",
      ".placeholder",
      ".placeholder-text",
      ".status",
      ".live-btn",
      ".audio-btn",
      ".ptt-btn",
      ".play-btn",
      ".audio-info",
      ".mic-info",
      ".mic-summary",
      ".mic-detail",
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
    ]) {
      this.nodes.set(selector, new FakeNode(this));
    }
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

function listenerStore() {
  const listeners = new Map();
  return {
    listeners,
    addEventListener(name, callback) {
      if (!listeners.has(name)) listeners.set(name, new Set());
      listeners.get(name).add(callback);
    },
    removeEventListener(name, callback) {
      listeners.get(name)?.delete(callback);
    },
    dispatch(name, event = {}) {
      for (const callback of listeners.get(name) || []) callback(event);
    },
  };
}

async function settle() {
  for (let count = 0; count < 12; count++) await Promise.resolve();
}

function keyEvent(key, repeat = false) {
  return {
    key,
    repeat,
    prevented: false,
    preventDefault() {
      this.prevented = true;
    },
  };
}

test("the card preserves keyboard holds and accessible unlock confirmation UX", async () => {
  const registry = new Map();
  const windowEvents = listenerStore();
  const documentEvents = listenerStore();
  const serviceCalls = [];
  const attachments = [];
  const timers = new Map();
  let nextTimer = 0;

  globalThis.HTMLElement = FakeHTMLElement;
  globalThis.customElements = {
    get: (name) => registry.get(name),
    define: (name, constructor) => registry.set(name, constructor),
  };
  globalThis.window = {
    ...windowEvents,
    customCards: [],
    isSecureContext: true,
    setTimeout(callback, ms) {
      const id = ++nextTimer;
      timers.set(id, { callback, ms });
      return id;
    },
    clearTimeout(id) {
      timers.delete(id);
    },
  };
  globalThis.document = {
    ...documentEvents,
    visibilityState: "visible",
    activeElement: null,
    createElement(tag) {
      assert.equal(tag, "video");
      return new FakeVideo();
    },
  };
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: {
      mediaDevices: {
        getUserMedia: async () => {
          const track = { readyState: "live", stop() { this.readyState = "ended"; } };
          return { getTracks: () => [track], getAudioTracks: () => [track] };
        },
      },
    },
  });

  const module = await import(
    "../../custom_components/abb_welcome/frontend/abb-welcome-intercom-card.js?card-ux"
  );
  const Card = registry.get(module.CARD_TAG);
  const card = new Card();
  card.setConfig({ camera: "camera.door", unlock_button: "button.unlock" });
  card.hass = {
    connected: true,
    connection: { connected: true },
    states: {
      "camera.door": {
        state: "idle",
        attributes: { friendly_name: "Front door", talkback_ready: true },
      },
      "button.unlock": {
        state: "idle",
        attributes: { friendly_name: "Atrio principale" },
      },
    },
    callService: async (domain, service, data) => {
      serviceCalls.push({ domain, service, data });
    },
  };
  card.connectedCallback();
  card._live = true;
  card._webRtc = {
    nativeMicReady: true,
    async setNativeMicTrack(track) { attachments.push(track); return true; },
    stop() {},
  };
  card._machine.setReady(true);
  card._render();

  const ptt = card._refs.pttBtn;
  const spaceDown = keyEvent(" ");
  ptt.dispatch("keydown", spaceDown);
  assert.equal(spaceDown.prevented, true);
  ptt.dispatch("keydown", keyEvent(" ", true));
  await settle();
  assert.equal(attachments.length, 1);
  const firstTrack = attachments[0];
  assert.equal(firstTrack.readyState, "live");

  // A stray release must not terminate a Space hold; the matching global
  // release does, even after focus moved outside the button.
  windowEvents.dispatch("keyup", keyEvent("Enter"));
  await settle();
  assert.equal(attachments.length, 1);
  windowEvents.dispatch("keyup", keyEvent(" "));
  await settle();
  assert.equal(firstTrack.readyState, "ended");
  assert.deepEqual(attachments, [firstTrack, null]);

  const enterDown = keyEvent("Enter");
  ptt.dispatch("keydown", enterDown);
  await settle();
  assert.equal(enterDown.prevented, true);
  assert.equal(attachments.length, 3);
  const secondTrack = attachments[2];
  assert.notEqual(firstTrack, secondTrack);
  ptt.dispatch("focusout", {});
  await settle();
  assert.equal(secondTrack.readyState, "ended");
  assert.deepEqual(attachments, [firstTrack, null, secondTrack, null]);
  windowEvents.dispatch("keyup", keyEvent("Enter"));
  await settle();
  assert.equal(
    attachments.length,
    4,
    "focus loss clears the held key, so its later keyup cannot stop twice"
  );

  // The form editor invokes these callbacks with its own `this`; callers may
  // also pass hass directly while the editor has not bound one yet.
  const italianForm = Card.getConfigForm({ language: "it-IT" });
  const englishForm = Card.getConfigForm();
  assert.ok(Array.isArray(italianForm.schema));
  assert.equal(typeof italianForm.computeLabel, "function");
  assert.equal(typeof italianForm.computeHelper, "function");
  const unlockSchema = italianForm.schema.find(
    (schema) => schema.name === "unlock_button"
  );
  assert.ok(unlockSchema);
  assert.notEqual(
    italianForm.computeLabel(unlockSchema),
    englishForm.computeLabel(unlockSchema)
  );
  assert.notEqual(
    italianForm.computeHelper(unlockSchema),
    englishForm.computeHelper(unlockSchema)
  );
  assert.equal(
    englishForm.computeLabel.call({ hass: { language: "it" } }, unlockSchema),
    italianForm.computeLabel(unlockSchema)
  );
  assert.equal(
    englishForm.computeHelper.call({ hass: { language: "it" } }, unlockSchema),
    italianForm.computeHelper(unlockSchema)
  );

  const unlock = card._refs.unlockBtn;
  unlock.dispatch("click");
  assert.equal(card._unlock.state, "confirm");
  assert.equal(card.shadowRoot.activeElement, card._refs.confirmNo);
  assert.equal(globalThis.document.activeElement, card._refs.confirmNo);
  assert.match(card._refs.confirmLabel.textContent, /Atrio principale/);
  assert.match(card._refs.confirmLabel.textContent, /button\.unlock/);
  assert.match(
    card.shadowRoot.innerHTML,
    /class="confirm-wrap hidden" role="group" aria-labelledby="confirm-label"/
  );
  assert.match(card.shadowRoot.innerHTML, /class="confirm-label" id="confirm-label"/);
  assert.equal([...timers.values()].at(-1).ms, 30000);

  const escape = keyEvent("Escape");
  card._refs.confirmWrap.dispatch("keydown", escape);
  assert.equal(escape.prevented, true);
  assert.equal(card._unlock.state, "idle");
  assert.equal(card.shadowRoot.activeElement, unlock);

  // A pending unlock may finish after the user has deliberately navigated
  // elsewhere. Completion must not steal that newer focus decision.
  const pendingUnlocks = [];
  card.hass.callService = (domain, service, data) => {
    serviceCalls.push({ domain, service, data });
    if (domain === "button" && service === "press") {
      return new Promise((resolve) => pendingUnlocks.push(resolve));
    }
    return Promise.resolve();
  };
  unlock.dispatch("click");
  card._refs.confirmYes.dispatch("click");
  assert.equal(card._unlock.state, "busy");
  card._refs.liveBtn.focus();
  pendingUnlocks.shift()();
  await settle();
  assert.equal(card._unlock.state, "idle");
  assert.equal(
    card.shadowRoot.activeElement,
    card._refs.liveBtn,
    "a completed unlock does not override focus moved to another card control"
  );

  unlock.dispatch("click");
  card._refs.confirmYes.dispatch("click");
  assert.equal(card._unlock.state, "busy");
  const outsideCard = new FakeNode();
  card.shadowRoot.activeElement = null;
  globalThis.document.activeElement = outsideCard;
  pendingUnlocks.shift()();
  await settle();
  assert.equal(card._unlock.state, "idle");
  assert.equal(card.shadowRoot.activeElement, null);
  assert.equal(
    globalThis.document.activeElement,
    outsideCard,
    "a completed unlock does not pull focus back from outside the card"
  );

  assert.equal(windowEvents.listeners.get("keyup")?.size, 1);
  assert.equal(ptt.listeners.get("focusout")?.size, 1);
  card.disconnectedCallback();
  assert.equal(windowEvents.listeners.get("keyup")?.size, 0);
  assert.equal(windowEvents.listeners.get("pointerup")?.size, 0);
  assert.equal(windowEvents.listeners.get("blur")?.size, 0);
  assert.equal(documentEvents.listeners.get("visibilitychange")?.size, 0);
});
