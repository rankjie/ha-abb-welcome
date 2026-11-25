/*
 * UnlockConfirm invariants: unlock always takes two distinct interactions,
 * the confirm step auto-reverts on a timeout, a confirmed press happens
 * exactly once, a failed press is never retried (an uncertain unlock may
 * already have operated the lock), and cancel/error paths reset cleanly.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  UnlockConfirm,
  UNLOCK_CONFIRM_TIMEOUT_MS,
} from "../../custom_components/abb_welcome/frontend/abb-welcome-intercom-card.js";
import { deferred } from "./_harness.mjs";

function makeUnlock() {
  const h = { presses: [], timers: [], states: [] };
  let timerId = 0;
  const unlock = new UnlockConfirm({
    pressButton: () => {
      const d = deferred();
      h.presses.push(d);
      return d.promise;
    },
    setTimeout: (fn, ms) => {
      const id = ++timerId;
      h.timers.push({ id, fn, ms });
      return id;
    },
    clearTimeout: (id) => {
      h.timers = h.timers.filter((t) => t.id !== id);
    },
    onState: (state, errorText) => h.states.push({ state, errorText }),
  });
  return { unlock, h };
}

test("tap → confirm presses the button exactly once", async () => {
  const { unlock, h } = makeUnlock();
  unlock.tap();
  assert.equal(unlock.state, "confirm");
  assert.equal(h.presses.length, 0); // nothing pressed yet
  const confirmPromise = unlock.confirm();
  assert.equal(unlock.state, "busy");
  assert.equal(h.presses.length, 1);
  h.presses[0].resolve();
  assert.equal(await confirmPromise, true);
  assert.equal(unlock.state, "idle");
  assert.equal(h.presses.length, 1);
});

test("confirm without a prior tap is a no-op", async () => {
  const { unlock, h } = makeUnlock();
  assert.equal(await unlock.confirm(), false);
  assert.equal(h.presses.length, 0);
});

test("confirm state auto-reverts after the timeout without pressing", () => {
  const { unlock, h } = makeUnlock();
  unlock.tap();
  const timer = h.timers.find((t) => t.ms === UNLOCK_CONFIRM_TIMEOUT_MS);
  assert.ok(timer);
  timer.fn();
  assert.equal(unlock.state, "idle");
  assert.equal(h.presses.length, 0);
});

test("cancel reverts without pressing", () => {
  const { unlock, h } = makeUnlock();
  unlock.tap();
  unlock.cancel();
  assert.equal(unlock.state, "idle");
  assert.equal(h.presses.length, 0);
});

test("a failed press surfaces the error and is never retried", async () => {
  const { unlock, h } = makeUnlock();
  unlock.tap();
  const confirmPromise = unlock.confirm();
  h.presses[0].reject(new Error("Failed to unlock door: Posto esterno"));
  assert.equal(await confirmPromise, false);
  assert.equal(unlock.state, "error");
  assert.ok(unlock.errorText.includes("Failed to unlock door"));
  assert.equal(h.presses.length, 1); // no automatic retry, ever
});

test("re-tap after an error starts a fresh confirm cycle", async () => {
  const { unlock, h } = makeUnlock();
  unlock.tap();
  const confirmPromise = unlock.confirm();
  h.presses[0].reject(new Error("boom"));
  await confirmPromise;
  assert.equal(unlock.state, "error");
  unlock.tap();
  assert.equal(unlock.state, "confirm");
  assert.equal(unlock.errorText, "");
});

test("tap while busy is ignored", async () => {
  const { unlock, h } = makeUnlock();
  unlock.tap();
  const confirmPromise = unlock.confirm();
  unlock.tap(); // must not restart the flow mid-press
  assert.equal(unlock.state, "busy");
  h.presses[0].resolve();
  await confirmPromise;
  assert.equal(h.presses.length, 1);
});

test("dispose invalidates an in-flight success without a late state callback", async () => {
  const { unlock, h } = makeUnlock();
  unlock.tap();
  const confirmPromise = unlock.confirm();
  const statesBeforeDispose = h.states.length;
  unlock.dispose();
  h.presses[0].resolve();
  assert.equal(await confirmPromise, false);
  assert.equal(unlock.state, "busy");
  assert.equal(h.states.length, statesBeforeDispose);
  assert.equal(h.presses.length, 1);
});

test("dispose invalidates an in-flight failure without surfacing stale error", async () => {
  const { unlock, h } = makeUnlock();
  unlock.tap();
  const confirmPromise = unlock.confirm();
  const statesBeforeDispose = h.states.length;
  unlock.dispose();
  h.presses[0].reject(new Error("late uncertain outcome"));
  assert.equal(await confirmPromise, false);
  assert.equal(unlock.errorText, "");
  assert.equal(h.states.length, statesBeforeDispose);
  assert.equal(h.presses.length, 1);
});
