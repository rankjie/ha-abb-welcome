/*
 * Registry helpers and localization: sibling discovery walks the camera's
 * device and skips diagnostic/config entities (the Refresh Events button must
 * never be offered as the unlock button); entry-id resolution degrades to
 * undefined; language picking defaults to English with full en/it key parity;
 * capability checks map insecure contexts to an actionable HTTPS message.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  STRINGS,
  pickLanguage,
  discoverSiblings,
  resolveEntryId,
  resolveStationId,
  resolveArmScope,
  ringMatchesStation,
  capabilityCheck,
  supportMessage,
  mapServiceError,
  makeSessionId,
} from "../../custom_components/abb_welcome/frontend/abb-welcome-intercom-card.js";

const HASS = {
  states: {
    "camera.abb_door": { attributes: { station_id: "door" } },
    "button.door_unlock": { attributes: { station_id: "door" } },
  },
  entities: {
    "camera.abb_door": { device_id: "dev1", platform: "abb_welcome" },
    "button.refresh_events": {
      device_id: "dev1",
      platform: "abb_welcome",
      entity_category: "diagnostic",
    },
    "button.door_unlock": { device_id: "dev1", platform: "abb_welcome" },
    "binary_sensor.ringing": { device_id: "dev1", platform: "abb_welcome" },
    "sensor.sip_listener": { device_id: "dev1", entity_category: "diagnostic" },
    "button.unrelated": { device_id: "dev2" },
  },
  devices: {
    dev1: { primary_config_entry: "entry123" },
    dev2: {},
  },
};

test("discoverSiblings picks same-device unlock and ring, skipping diagnostics", () => {
  const siblings = discoverSiblings(HASS, "camera.abb_door");
  assert.equal(siblings.unlockButton, "button.door_unlock");
  assert.equal(siblings.ringSensor, "binary_sensor.ringing");
});

test("discoverSiblings degrades on unknown camera or missing registry", () => {
  assert.deepEqual(discoverSiblings(HASS, "camera.nope"), {});
  assert.deepEqual(discoverSiblings({}, "camera.abb_door"), {});
  assert.deepEqual(discoverSiblings(undefined, "camera.abb_door"), {});
});

test("a lone button for another station is never selected automatically", () => {
  const singleWrong = {
    states: {
      "camera.front": { attributes: { station_id: "front" } },
      "button.back": { attributes: { station_id: "back" } },
    },
    entities: {
      "camera.front": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_camera_front",
      },
      "button.back": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_back",
      },
    },
  };
  assert.equal(
    discoverSiblings(singleWrong, "camera.front").unlockButton,
    undefined
  );
});

test("discoverSiblings matches the station unique id on a multi-door gateway", () => {
  const multi = {
    states: {
      "camera.front": { attributes: { station_id: "1001" } },
    },
    entities: {
      "camera.front": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_camera_1001",
      },
      "button.back": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_1002",
      },
      "button.front": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_1001",
      },
      "binary_sensor.ring": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_ringing",
      },
    },
  };
  assert.deepEqual(discoverSiblings(multi, "camera.front"), {
    unlockButton: "button.front",
    ringSensor: "binary_sensor.ring",
  });
});

test("multi-door unlock discovery fails closed without a station id", () => {
  const ambiguous = {
    entities: {
      "camera.front": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_camera_1001",
      },
      "button.front": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_1001",
      },
      "button.back": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_1002",
      },
    },
  };
  assert.equal(
    discoverSiblings(ambiguous, "camera.front").unlockButton,
    undefined
  );
});

test("a real station suffix camN is not mistaken for a sub-camera index", () => {
  const multi = {
    states: {
      "camera.front_cam2": {
        attributes: { station_id: "front_cam2" },
      },
    },
    entities: {
      "camera.front_cam2": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_camera_front_cam2",
      },
      "button.front": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_front",
      },
      "button.front_cam2": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_front_cam2",
      },
    },
  };
  assert.equal(
    discoverSiblings(multi, "camera.front_cam2").unlockButton,
    "button.front_cam2"
  );
});

test("station ids are matched byte-for-byte instead of slugified", () => {
  const multi = {
    states: {
      "camera.special": {
        attributes: { station_id: " Door.A+1 " },
      },
    },
    entities: {
      "camera.special": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_camera_door_a_1",
      },
      "button.correct": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_Door.A+1",
      },
      "button.slug_collision": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_door_a_1",
      },
    },
  };
  assert.equal(
    discoverSiblings(multi, "camera.special").unlockButton,
    "button.correct"
  );
});

test("station ids containing the camera marker remain unambiguous", () => {
  const multi = {
    states: {
      "camera.special": {
        attributes: { station_id: "front_camera_back" },
      },
    },
    entities: {
      "camera.special": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_camera_front_camera_back",
      },
      "button.correct": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_front_camera_back",
      },
      "button.greedy_collision": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_camera_front_back",
      },
    },
  };
  assert.equal(
    discoverSiblings(multi, "camera.special").unlockButton,
    "button.correct"
  );
});

test("discoverSiblings refuses an ambiguous unlock target", () => {
  const ambiguous = {
    entities: {
      "camera.front": { device_id: "gateway", platform: "abb_welcome" },
      "button.one": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_1001",
      },
      "button.two": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_1002",
      },
    },
  };
  assert.deepEqual(discoverSiblings(ambiguous, "camera.front"), {
    unlockButton: undefined,
    ringSensor: undefined,
  });
});

test("discoverSiblings never auto-selects same-device entities from another integration", () => {
  const foreign = {
    entities: {
      "camera.front": {
        device_id: "gateway",
        platform: "abb_welcome",
        unique_id: "gw_camera_1001",
      },
      "button.foreign": {
        device_id: "gateway",
        platform: "other_integration",
        unique_id: "gw_1001",
      },
      "binary_sensor.foreign_ring": {
        device_id: "gateway",
        platform: "other_integration",
      },
    },
  };
  assert.deepEqual(discoverSiblings(foreign, "camera.front"), {
    unlockButton: undefined,
    ringSensor: undefined,
  });
});

test("a foreign camera cannot auto-discover ABB door controls", () => {
  const foreignCamera = {
    states: {
      "camera.front": { attributes: { station_id: "front" } },
      "button.front": { attributes: { station_id: "front" } },
    },
    entities: {
      "camera.front": {
        device_id: "gateway",
        platform: "other_integration",
      },
      "button.front": {
        device_id: "gateway",
        platform: "abb_welcome",
      },
    },
  };
  assert.deepEqual(discoverSiblings(foreignCamera, "camera.front"), {});
});

test("resolveEntryId returns the device's primary entry or undefined", () => {
  assert.equal(resolveEntryId(HASS, "camera.abb_door"), "entry123");
  const noEntry = {
    entities: { "camera.x": { device_id: "dev2" } },
    devices: HASS.devices,
  };
  assert.equal(resolveEntryId(noEntry, "camera.x"), undefined);
  assert.equal(resolveEntryId(HASS, "camera.nope"), undefined);
  assert.equal(resolveEntryId({}, "camera.abb_door"), undefined);
});

test("camera attributes and registry metadata resolve a fully scoped arm target", () => {
  const fromAttributes = {
    states: {
      "camera.front": {
        attributes: {
          config_entry_id: " entry-attr ",
          station_id: " station-front ",
        },
      },
    },
    entities: {
      "camera.front": { device_id: "gateway", platform: "abb_welcome" },
    },
    devices: { gateway: { primary_config_entry: "entry-device" } },
  };
  assert.equal(resolveEntryId(fromAttributes, "camera.front"), "entry-attr");
  assert.equal(
    resolveStationId(fromAttributes, "camera.front"),
    "station-front"
  );
  assert.deepEqual(resolveArmScope(fromAttributes, "camera.front"), {
    entry_id: "entry-attr",
    station_id: "station-front",
  });

  const fromConfigAndRegistry = {
    entities: {
      "camera.back": {
        device_id: "gateway",
        config_entry_id: "entry-registry",
        platform: "abb_welcome",
      },
    },
    devices: { gateway: { primary_config_entry: "entry-device" } },
  };
  assert.deepEqual(
    resolveArmScope(fromConfigAndRegistry, "camera.back", {
      station_id: "station-back",
    }),
    { entry_id: "entry-registry", station_id: "station-back" }
  );
});

test("arm scope is fail-closed when either persistent identifier is absent", () => {
  const hass = {
    states: {
      "camera.no_station": {
        attributes: { config_entry_id: "entry-only" },
      },
      "camera.no_entry": { attributes: { station_id: "station-only" } },
    },
  };
  assert.equal(resolveArmScope(hass, "camera.no_station"), null);
  assert.equal(resolveArmScope(hass, "camera.no_entry"), null);
  assert.equal(resolveArmScope({}, "camera.unknown"), null);
});

test("arm scope rejects stale explicit identifiers that conflict with the camera", () => {
  const hass = {
    states: {
      "camera.front": {
        attributes: {
          config_entry_id: "entry-camera",
          station_id: "station-camera",
        },
      },
    },
  };
  assert.equal(
    resolveArmScope(hass, "camera.front", { station_id: "station-other" }),
    null
  );
  assert.equal(
    resolveArmScope(hass, "camera.front", {
      entry_id: "entry-other",
      station_id: "station-camera",
    }),
    null
  );
});

test("arm scope rejects camera metadata owned by another integration", () => {
  const hass = {
    states: {
      "camera.foreign": {
        attributes: {
          config_entry_id: "entry-foreign",
          station_id: "station-foreign",
        },
      },
    },
    entities: {
      "camera.foreign": {
        platform: "other_integration",
        config_entry_id: "entry-foreign",
      },
    },
  };
  assert.equal(
    resolveArmScope(hass, "camera.foreign", {
      entry_id: "entry-foreign",
      station_id: "station-foreign",
    }),
    null
  );
});

test("gateway-wide ring state is shown only on the matching station card", () => {
  const ring = {
    state: "on",
    attributes: { station_id: "station-front", station_name: "Front" },
  };
  assert.equal(ringMatchesStation(ring, "station-front"), true);
  assert.equal(ringMatchesStation(ring, "station-back"), false);
  assert.equal(ringMatchesStation({ ...ring, state: "off" }, "station-front"), false);
  assert.equal(ringMatchesStation({ state: "on", attributes: {} }, "station-front"), false);
  assert.equal(
    ringMatchesStation(
      { state: "on", attributes: { caller_user: "station-back" } },
      "station-back"
    ),
    true
  );
});

test("pickLanguage: it* → it, everything else → en", () => {
  assert.equal(pickLanguage("it"), "it");
  assert.equal(pickLanguage("it-IT"), "it");
  assert.equal(pickLanguage("IT"), "it");
  assert.equal(pickLanguage("en"), "en");
  assert.equal(pickLanguage("de"), "en");
  assert.equal(pickLanguage(undefined), "en");
});

test("en and it string tables carry identical keys", () => {
  assert.deepEqual(Object.keys(STRINGS.it).sort(), Object.keys(STRINGS.en).sort());
  for (const value of Object.values(STRINGS.en)) {
    assert.equal(typeof value, "string");
  }
});

test("capabilityCheck distinguishes HTTPS and native microphone access", () => {
  const insecure = capabilityCheck({ isSecureContext: false });
  assert.deepEqual(insecure, { ok: false, reason: "insecure-context" });
  assert.equal(
    supportMessage(insecure.reason, STRINGS.en),
    STRINGS.en.https_required
  );

  const noMedia = capabilityCheck({ isSecureContext: true });
  assert.equal(noMedia.reason, "no-media-devices");
  assert.equal(supportMessage(noMedia.reason, STRINGS.en), STRINGS.en.no_media_devices);

  const ok = capabilityCheck({
    isSecureContext: true,
    mediaDevices: { getUserMedia: () => {} },
  });
  assert.deepEqual(ok, { ok: true, reason: null });
});

test("mapServiceError translates the known backend messages", () => {
  const s = STRINGS.en;
  assert.equal(
    mapServiceError(new Error("ABB Welcome incoming-call pickup is disabled"), s),
    s.err_pickup_disabled
  );
  assert.equal(
    mapServiceError({ code: "abb_streaming_disarmed" }, s),
    s.err_disarmed
  );
  assert.equal(mapServiceError(new Error("weird"), s), `${s.err_service}: weird`);
  assert.equal(mapServiceError(undefined, s), s.err_service);
});

test("makeSessionId is unique and prefixed", () => {
  const a = makeSessionId();
  const b = makeSessionId();
  assert.match(a, /^abbcard-/);
  assert.notEqual(a, b);
  assert.equal(makeSessionId(() => "fixed"), "abbcard-fixed");
});
