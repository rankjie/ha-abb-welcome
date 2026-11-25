/* Home Assistant custom-card public API contract. */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  AbbWelcomeIntercomCard,
  CARD_TAG,
  entitySuggestion,
} from "../../custom_components/abb_welcome/frontend/abb-welcome-intercom-card.js";

test("grid options omit rows when height is automatic", () => {
  const card = new AbbWelcomeIntercomCard();
  assert.deepEqual(card.getGridOptions(), { columns: 12, min_columns: 6 });
});

test("built-in editor exposes the supported configuration fields", () => {
  const form = AbbWelcomeIntercomCard.getConfigForm();
  assert.deepEqual(form.schema.map(({ name }) => name), [
    "camera",
    "name",
    "unlock_button",
    "ring_sensor",
    "station_id",
  ]);
  assert.equal(form.schema[0].required, true);
  assert.deepEqual(form.schema[0].selector, {
    entity: { domain: "camera", integration: "abb_welcome" },
  });
  assert.doesNotThrow(() => form.assertConfig({
    type: `custom:${CARD_TAG}`,
    camera: "camera.abb_welcome_front_station",
    entity: null,
    name: null,
    unlock_button: "button.abb_welcome_front_station",
    ring_sensor: "binary_sensor.abb_welcome_intercom_ringing",
    station_id: null,
  }));
});

test("entity suggestion follows the required { config } shape", () => {
  const hass = {
    states: {
      "camera.door": { attributes: { station_id: "door" } },
      "button.unlock": { attributes: { station_id: "door" } },
    },
    entities: {
      "camera.door": { device_id: "dev", platform: "abb_welcome" },
      "button.unlock": { device_id: "dev", platform: "abb_welcome" },
      "binary_sensor.ring": { device_id: "dev", platform: "abb_welcome" },
    },
  };
  assert.deepEqual(entitySuggestion(hass, "camera.door"), {
    config: {
      type: `custom:${CARD_TAG}`,
      camera: "camera.door",
      unlock_button: "button.unlock",
      ring_sensor: "binary_sensor.ring",
    },
  });
  assert.equal(entitySuggestion(hass, "light.nope"), null);
});
