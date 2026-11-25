/*
 * abb-welcome-intercom-card.js — ABB Welcome intercom Lovelace card.
 *
 * A dashboard card for ABB Welcome / Busch-Jaeger door stations: camera live
 * view (video + street audio), press-and-hold native WebRTC talkback, and door
 * unlock through the integration's existing button entity with an explicit
 * two-step confirmation.
 *
 * Safety invariants (mirrored by tests under tests/frontend/):
 * - The idle card performs zero service calls and never mounts a player;
 *   opening the stream is always a direct user gesture ("Live").
 * - Microphone capture only ever starts inside a press gesture. The UI shows
 *   local sender attachment, not remote receipt or audibility.
 * - Unlock always requires the inline confirmation step and is never retried
 *   automatically: an uncertain in-dialog outcome may already have operated
 *   the lock.
 * - Release/cancel/focus loss stop capture immediately. Native release
 *   detaches the microphone without stopping Live. Closing the card stops both.
 *
 * Module layout: the pure logic below is exported and imported directly by
 * `node --test` (no DOM at module scope); the custom element at the bottom is
 * defined only in a browser context.
 */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const CARD_TAG = "abb-welcome-intercom-card";

export const CARD_VERSION = (() => {
  try {
    return new URL(import.meta.url).searchParams.get("v") || "dev";
  } catch (_err) {
    return "dev";
  }
})();

export const UNLOCK_CONFIRM_TIMEOUT_MS = 30000;
export const LIVE_START_TIMEOUT_MS = 15000;
export const LIVE_STALL_TIMEOUT_MS = 10000;
// The lease outlives two missed renewals, so a brief WebSocket drop does not
// end Live, and a closed tab stops holding the station within a minute.
export const LIVE_LEASE_SECONDS = 60;
export const LIVE_LEASE_RENEW_MS = 20000;
const HISTORY_CACHE_MS = 5 * 60 * 1000;
const MAX_HISTORY_PHOTOS_PER_CALL = 30;
const HISTORY_PHOTO_CONCURRENCY = 3;

// ---------------------------------------------------------------------------
// Strings (en built-in default, it selected via hass.language)
// ---------------------------------------------------------------------------

export const STRINGS = {
  en: {
    name_default: "Intercom",
    live: "Live",
    stop: "Stop",
    live_starting: "Connecting…",
    video_waiting: "Waiting for video…",
    video_playing: "Video live",
    video_buffering: "Video interrupted — waiting for frames…",
    video_paused: "Video paused",
    video_blocked: "Playback blocked — press Play video",
    video_timeout: "No video received — press Live to retry",
    video_ended: "Video ended — press Live to reconnect",
    video_stalled: "Video interrupted — press Live to reconnect",
    video_error: "Video unavailable — press Live to retry",
    live_ended: "Live view ended — press Live to reconnect",
    play_video: "Play video",
    audio_blocked: "Listening blocked — press Listen to retry",
    audio_waiting: "Waiting for an incoming audio track",
    audio_missing: "No incoming audio track",
    idle_placeholder: "Start live video",
    live_unavailable:
      "Cannot start live view — check the camera and connection, then retry.",
    ptt: "Hold to talk",
    requesting_mic: "Allow microphone access…",
    connecting: "Connecting…",
    native_talking: "Microphone on — release to stop",
    native_talk_unavailable: "This live stream did not negotiate a microphone channel",
    mic_error: "Could not start the microphone",
    mic_denied: "Microphone access denied — allow it in the browser settings",
    https_required: "Microphone unavailable on HTTP",
    https_details: "To talk, open Home Assistant via HTTPS (for example Nabu Casa). Video and listening can still work on HTTP.",
    no_media_devices: "Microphone access is not supported by this browser",
    unlock: "Unlock",
    unlock_confirm: "Open {target}?",
    confirm: "Open",
    cancel: "Cancel",
    unlocking: "Unlocking…",
    unlocked: "Unlock requested",
    ringing: "Ringing",
    history: "Call history",
    history_refresh: "Refresh history",
    history_loading: "Loading from ABB…",
    history_updating: "Updating from ABB…",
    history_cached: "Showing last loaded calls — ABB could not be reached",
    history_photos_incomplete: "Some photos could not be checked — refresh history to retry",
    history_empty: "ABB returned no calls",
    history_unavailable: "Could not load ABB history — try refreshing",
    history_forbidden: "You do not have permission to view this history",
    history_no_date: "Time unavailable",
    history_ring: "Ring — outcome unknown",
    history_answered: "Answered",
    history_missed: "Missed",
    history_ended: "Ended — answer not confirmed",
    history_photos: "Screenshots",
    history_photo_alt: "Call photo",
    history_photo_loading: "Loading photo…",
    history_photo_error: "Photo unavailable",
    audio_on: "Listening enabled — mute",
    audio_off: "Listen",
    disconnected: "Home Assistant is disconnected",
    err_service: "Service call failed",
    err_pickup_disabled: "Pickup is disabled — check the Allow pickup switch",
    err_disarmed: "Streaming is disarmed — press Live to arm it",
    err_missing_scope:
      "Cannot start live view safely — the camera has no config-entry or station identifier",
    err_unlock_target: "The selected unlock button is no longer available",
    error: "Error",
  },
  it: {
    name_default: "Citofono",
    live: "Live",
    stop: "Stop",
    live_starting: "Connessione…",
    video_waiting: "In attesa del video…",
    video_playing: "Video in diretta",
    video_buffering: "Video interrotto — in attesa di immagini…",
    video_paused: "Video in pausa",
    video_blocked: "Riproduzione bloccata — premi Riproduci video",
    video_timeout: "Video non ricevuto — premi Live per riprovare",
    video_ended: "Video terminato — premi Live per riconnettere",
    video_stalled: "Video interrotto — premi Live per riconnettere",
    video_error: "Video non disponibile — premi Live per riprovare",
    live_ended: "Diretta terminata — premi Live per riconnettere",
    play_video: "Riproduci video",
    audio_blocked: "Ascolto bloccato — premi Ascolta per riprovare",
    audio_waiting: "In attesa della traccia audio in ingresso",
    audio_missing: "Nessuna traccia audio in ingresso",
    idle_placeholder: "Avvia la diretta",
    live_unavailable:
      "Impossibile avviare il video — controlla camera e connessione, poi riprova.",
    ptt: "Tieni premuto per parlare",
    requesting_mic: "Consenti l'accesso al microfono…",
    connecting: "Connessione…",
    native_talking: "Microfono attivo — rilascia per terminare",
    native_talk_unavailable: "La diretta non ha negoziato un canale per il microfono",
    mic_error: "Impossibile avviare il microfono",
    mic_denied: "Microfono negato — consentilo nelle impostazioni del browser",
    https_required: "Microfono non disponibile su HTTP",
    https_details: "Per parlare apri Home Assistant via HTTPS, ad esempio con Nabu Casa. Video e ascolto possono funzionare anche su HTTP.",
    no_media_devices: "Questo browser non supporta l'accesso al microfono",
    unlock: "Apri porta",
    unlock_confirm: "Aprire {target}?",
    confirm: "Apri",
    cancel: "Annulla",
    unlocking: "Apertura…",
    unlocked: "Apertura inviata",
    ringing: "Sta suonando",
    history: "Storico chiamate",
    history_refresh: "Aggiorna storico",
    history_loading: "Caricamento da ABB…",
    history_updating: "Aggiornamento da ABB…",
    history_cached: "Mostro le ultime chiamate caricate — aggiornamento ABB non riuscito",
    history_photos_incomplete: "Non ho potuto verificare tutte le foto — aggiorna lo storico per riprovare",
    history_empty: "ABB non ha restituito chiamate",
    history_unavailable: "Impossibile caricare lo storico ABB — prova ad aggiornare",
    history_forbidden: "Non hai il permesso per vedere questo storico",
    history_no_date: "Orario non disponibile",
    history_ring: "Squillo — esito non disponibile",
    history_answered: "Risposta",
    history_missed: "Persa",
    history_ended: "Terminata — risposta non confermata",
    history_photos: "Screenshot",
    history_photo_alt: "Foto della chiamata",
    history_photo_loading: "Caricamento foto…",
    history_photo_error: "Foto non disponibile",
    audio_on: "Ascolto abilitato — silenzia",
    audio_off: "Ascolta",
    disconnected: "Home Assistant è disconnesso",
    err_service: "Chiamata al servizio fallita",
    err_pickup_disabled: "Risposta disabilitata — controlla lo switch Allow pickup",
    err_disarmed: "Streaming disarmato — premi Live per armarlo",
    err_missing_scope:
      "Impossibile avviare il live in sicurezza — la camera non espone config entry o stazione",
    err_unlock_target: "Il pulsante di apertura selezionato non è più disponibile",
    error: "Errore",
  },
};

export function pickLanguage(lang) {
  return typeof lang === "string" && lang.toLowerCase().startsWith("it")
    ? "it"
    : "en";
}

const FORM_STRINGS = {
  en: {
    labels: { camera: "ABB camera", name: "Display name", unlock_button: "Unlock button (override)", ring_sensor: "Ring sensor (override)", station_id: "Station ID (advanced override)" },
    helpers: {
      camera: "Choose the ABB Welcome camera for this entrance.",
      name: "Optional short title, for example Entrance. Empty uses the camera name.",
      unlock_button: "Leave empty for safe automatic discovery. An override may control another button: check the target shown before confirming.",
      ring_sensor: "Leave empty to discover the ABB ring sensor. Override only when automatic discovery cannot identify it.",
      station_id: "Normally leave empty: read from the camera. Only enter the exact ABB station ID if its metadata is missing; this is not an entity ID.",
    },
  },
  it: {
    labels: { camera: "Camera ABB", name: "Nome visualizzato", unlock_button: "Pulsante apertura (override)", ring_sensor: "Sensore squillo (override)", station_id: "ID stazione (override avanzato)" },
    helpers: {
      camera: "Seleziona la camera ABB Welcome di questo ingresso.",
      name: "Titolo breve facoltativo, ad esempio Ingresso. Se vuoto usa il nome della camera.",
      unlock_button: "Lascia vuoto per il rilevamento automatico sicuro. Un override può comandare un altro pulsante: verifica il destinatario prima di confermare.",
      ring_sensor: "Lascia vuoto per rilevare il sensore squillo ABB. Impostalo solo se il rilevamento automatico non riesce a identificarlo.",
      station_id: "Normalmente lascia vuoto: viene letto dalla camera. Inserisci l'ID ABB esatto solo se manca nei metadati; non è un ID entità.",
    },
  },
};

function validateCardConfig(config) {
  if (!config || typeof config.camera !== "string" || !/^camera\.[^\s.]+$/.test(config.camera)) {
    throw new Error('abb-welcome-intercom-card: "camera" must be a camera entity id');
  }
  for (const [key, domain] of [["unlock_button", "button"], ["ring_sensor", "binary_sensor"]]) {
    // The Lovelace visual editor persists an empty optional selector as null.
    if (config[key] != null && config[key] !== "" &&
        (typeof config[key] !== "string" || !new RegExp(`^${domain}\\.[^\\s.]+$`).test(config[key]))) {
      throw new Error(`abb-welcome-intercom-card: "${key}" must be a ${domain} entity id`);
    }
  }
  for (const key of ["name", "station_id"]) {
    if (config[key] != null && typeof config[key] !== "string") {
      throw new Error(`abb-welcome-intercom-card: "${key}" must be a string`);
    }
  }
  if (config.native_talkback != null && typeof config.native_talkback !== "boolean") {
    throw new Error('abb-welcome-intercom-card: "native_talkback" must be a boolean');
  }
}

export function makeSessionId(uuidFn) {
  let raw = "";
  if (typeof uuidFn === "function") {
    raw = uuidFn();
  } else if (
    typeof crypto !== "undefined" &&
    typeof crypto.randomUUID === "function"
  ) {
    raw = crypto.randomUUID();
  } else {
    raw = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  }
  return `abbcard-${raw}`;
}

// ---------------------------------------------------------------------------
// Environment / errors / registry helpers
// ---------------------------------------------------------------------------

export function capabilityCheck(env) {
  if (!env || !env.isSecureContext) {
    return { ok: false, reason: "insecure-context" };
  }
  if (
    !env.mediaDevices ||
    typeof env.mediaDevices.getUserMedia !== "function"
  ) {
    return { ok: false, reason: "no-media-devices" };
  }
  return { ok: true, reason: null };
}

export function supportMessage(reason, strings) {
  if (reason === "insecure-context") {
    return strings.https_required;
  }
  if (reason === "no-media-devices") return strings.no_media_devices;
  return "";
}

export function mapServiceError(err, strings) {
  const message = String(
    (err && (err.message || err.error || err.code)) || err || ""
  );
  if (message.includes("pickup is disabled")) return strings.err_pickup_disabled;
  if (
    message.includes("streaming is disarmed") ||
    message.includes("abb_streaming_disarmed")
  ) {
    return strings.err_disarmed;
  }
  return message ? `${strings.err_service}: ${message}` : strings.err_service;
}

export function discoverSiblings(hassLike, cameraEntityId) {
  const registry = hassLike && hassLike.entities;
  const camera = registry && registry[cameraEntityId];
  if (
    !camera ||
    !camera.device_id ||
    camera.platform !== "abb_welcome"
  ) {
    return {};
  }
  const unlockCandidates = [];
  const ringCandidates = [];
  for (const [entityId, entry] of Object.entries(registry)) {
    if (!entry || entry.device_id !== camera.device_id) continue;
    if (entry.platform !== "abb_welcome") continue;
    const domain = entityId.split(".")[0];
    const diagnostic =
      entry.entity_category === "diagnostic" ||
      entry.entity_category === "config";
    if (domain === "button" && !diagnostic) {
      unlockCandidates.push([entityId, entry]);
    }
    if (domain === "binary_sensor" && !diagnostic) {
      ringCandidates.push([entityId, entry]);
    }
  }

  // All door stations intentionally belong to the gateway device. Never use
  // candidate count as proof of correlation: on a multi-door gateway, the one
  // enabled button may still belong to another station. New entities expose
  // the raw station_id. Legacy entities fall back to the exact unique-id
  // relationship only when no candidate exposes station metadata.
  let unlockButton;
  const attributes =
    hassLike.states &&
    hassLike.states[cameraEntityId] &&
    hassLike.states[cameraEntityId].attributes;
  const rawStationId = attributes && attributes.station_id;
  const stationKey =
    typeof rawStationId === "string" || typeof rawStationId === "number"
      ? String(rawStationId).trim()
      : "";
  if (stationKey && unlockCandidates.length) {
    const attributed = unlockCandidates.flatMap(([entityId, entry]) => {
      const state = hassLike.states && hassLike.states[entityId];
      const raw = state && state.attributes && state.attributes.station_id;
      const candidateStation =
        typeof raw === "string" || typeof raw === "number"
          ? String(raw).trim()
          : "";
      return candidateStation ? [[entityId, entry, candidateStation]] : [];
    });
    if (attributed.length) {
      const exact = attributed.filter(([, , value]) => value === stationKey);
      if (exact.length === 1) unlockButton = exact[0][0];
    } else if (camera.unique_id) {
      // Camera entity unique ids use camera.py's normalized station key,
      // while door-button unique ids deliberately retain the raw station id.
      const cameraStationKey =
        stationKey
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, "_")
          .replace(/^_+|_+$/g, "") || "station";
      const cameraIndex = Number(attributes && attributes.camera_index);
      const indexedSuffix =
        Number.isInteger(cameraIndex) && cameraIndex > 1
          ? `_cam${cameraIndex}`
          : "";
      const cameraUniqueId = String(camera.unique_id);
      const suffix = `_camera_${cameraStationKey}${indexedSuffix}`;
      if (cameraUniqueId.endsWith(suffix)) {
        const gatewayPrefix = cameraUniqueId.slice(0, -suffix.length);
        if (gatewayPrefix) {
          const expectedUniqueId = `${gatewayPrefix}_${stationKey}`;
          const exact = unlockCandidates.filter(
            ([, entry]) => entry.unique_id === expectedUniqueId
          );
          if (exact.length === 1) unlockButton = exact[0][0];
        }
      }
    }
  }

  // Ringing is gateway-wide today. Ambiguity must degrade to no automatic
  // choice, just like unlock, rather than wiring an unrelated sensor.
  const ringSensor =
    ringCandidates.length === 1 ? ringCandidates[0][0] : undefined;
  return { unlockButton, ringSensor };
}

export function resolveEntryId(hassLike, cameraEntityId) {
  const camera =
    hassLike && hassLike.entities && hassLike.entities[cameraEntityId];
  const state = hassLike && hassLike.states && hassLike.states[cameraEntityId];
  const candidates = [
    state && state.attributes && state.attributes.config_entry_id,
    camera && camera.config_entry_id,
  ];
  for (const value of candidates) {
    const entryId = typeof value === "string" ? value.trim() : "";
    if (entryId) return entryId;
  }
  if (!camera || !camera.device_id) return undefined;
  const device = hassLike.devices && hassLike.devices[camera.device_id];
  const entryId = device && device.primary_config_entry;
  return typeof entryId === "string" && entryId.trim()
    ? entryId.trim()
    : undefined;
}

export function resolveStationId(hassLike, cameraEntityId, config = {}) {
  const state = hassLike && hassLike.states && hassLike.states[cameraEntityId];
  const registry =
    hassLike && hassLike.entities && hassLike.entities[cameraEntityId];
  const candidates = [
    state && state.attributes && state.attributes.station_id,
    registry && registry.station_id,
    config && config.station_id,
  ];
  for (const value of candidates) {
    const stationId =
      typeof value === "string" || typeof value === "number"
        ? String(value).trim()
        : "";
    if (stationId) return stationId;
  }
  return undefined;
}

export function resolveArmScope(hassLike, cameraEntityId, config = {}) {
  const registry = hassLike && hassLike.entities;
  const cameraMetadata = registry && registry[cameraEntityId];
  if (cameraMetadata && cameraMetadata.platform !== "abb_welcome") {
    return null;
  }
  const explicitEntry =
    config && typeof config.entry_id === "string"
      ? config.entry_id.trim()
      : "";
  const inferredEntry = resolveEntryId(hassLike, cameraEntityId);
  if (explicitEntry && inferredEntry && explicitEntry !== inferredEntry) {
    return null;
  }
  const entryId = inferredEntry || explicitEntry;
  const explicitStation =
    config &&
    (typeof config.station_id === "string" ||
      typeof config.station_id === "number")
      ? String(config.station_id).trim()
      : "";
  const inferredStation = resolveStationId(hassLike, cameraEntityId);
  if (
    explicitStation &&
    inferredStation &&
    explicitStation !== inferredStation
  ) {
    return null;
  }
  const stationId = inferredStation || explicitStation;
  if (!entryId || !stationId) return null;
  return { entry_id: entryId, station_id: stationId };
}

export function ringMatchesStation(ringState, stationId) {
  const target =
    typeof stationId === "string" || typeof stationId === "number"
      ? String(stationId).trim()
      : "";
  if (!target || !ringState || ringState.state !== "on") return false;
  const attributes = ringState.attributes || {};
  const source = String(
    attributes.station_id || attributes.caller_user || ""
  ).trim();
  return !!source && source === target;
}

export function entitySuggestion(hass, entityId) {
  if (typeof entityId !== "string" || !entityId.startsWith("camera.")) {
    return null;
  }
  const entry = hass && hass.entities && hass.entities[entityId];
  if (!entry || entry.platform !== "abb_welcome") return null;
  const config = { type: `custom:${CARD_TAG}`, camera: entityId };
  const siblings = discoverSiblings(hass, entityId);
  if (siblings.unlockButton) config.unlock_button = siblings.unlockButton;
  if (siblings.ringSensor) config.ring_sensor = siblings.ringSensor;
  return { config };
}

// ---------------------------------------------------------------------------
// Unlock confirmation state machine
// ---------------------------------------------------------------------------

export class UnlockConfirm {
  constructor(ports) {
    this._press = ports.pressButton;
    this._snapshotTarget = ports.snapshotTarget || null;
    this._validateTarget = ports.validateTarget || (() => true);
    this._invalidTargetMessage =
      ports.invalidTargetMessage || "unlock target is no longer available";
    this._setTimeout = ports.setTimeout;
    this._clearTimeout = ports.clearTimeout;
    this._onState = ports.onState || (() => {});
    this._timeoutMs = ports.timeoutMs ?? UNLOCK_CONFIRM_TIMEOUT_MS;
    this.state = "idle"; // idle | confirm | busy | error
    this.errorText = "";
    this._timer = null;
    this._generation = 0;
    this._disposed = false;
    this._target = null;
  }

  _set(state, errorText = "") {
    if (this._disposed) return;
    this.state = state;
    this.errorText = errorText;
    this._onState(state, errorText);
  }

  _clearTimer() {
    if (this._timer !== null) {
      this._clearTimeout(this._timer);
      this._timer = null;
    }
  }

  tap() {
    if (this._disposed) return;
    if (this.state === "busy" || this.state === "confirm") return;
    this._clearTimer();
    const target = this._snapshotTarget ? this._snapshotTarget() : undefined;
    if (this._snapshotTarget && !target) return false;
    this._target = target;
    const generation = ++this._generation;
    this._set("confirm");
    this._timer = this._setTimeout(() => {
      this._timer = null;
      if (
        !this._disposed &&
        this._generation === generation &&
        this.state === "confirm"
      ) {
        this._target = null;
        this._set("idle");
      }
    }, this._timeoutMs);
    return true;
  }

  cancel() {
    if (this._disposed) return;
    if (this.state !== "confirm") return;
    this._clearTimer();
    this._target = null;
    this._set("idle");
  }

  async confirm() {
    if (this._disposed || this.state !== "confirm") return false;
    this._clearTimer();
    const generation = this._generation;
    const target = this._target;
    if (!this._validateTarget(target)) {
      this._target = null;
      this._set("error", this._invalidTargetMessage);
      return false;
    }
    this._set("busy");
    try {
      await this._press(target);
      if (this._disposed || this._generation !== generation) return false;
      this._target = null;
      this._set("idle");
      return true;
    } catch (err) {
      if (this._disposed || this._generation !== generation) return false;
      this._target = null;
      // Never retry: an uncertain unlock may already have opened the door.
      this._set("error", String((err && err.message) || err));
      return false;
    }
  }

  dispose() {
    this._clearTimer();
    this._disposed = true;
    this._generation++;
    this._target = null;
  }
}

// ---------------------------------------------------------------------------
// Home Assistant WebRTC signaling (pure, dependency-injected controller)
// ---------------------------------------------------------------------------

// Playback evidence is independent of signaling success and microphone state.
// No wall-clock timer may revive a player from an earlier card generation.
export class VideoPlaybackMonitor {
  constructor(video, ports = {}) {
    this.video = video;
    this._onState = ports.onState || (() => {});
    this._onError = ports.onError || (() => {});
    this._setTimeout = ports.setTimeout || setTimeout;
    this._clearTimeout = ports.clearTimeout || clearTimeout;
    this._now = ports.now || (() => performance.now());
    this._generation = 0;
    this._timer = null;
    this._frameCallback = null;
    this._listeners = [];
    this.state = "idle";
  }

  _set(state) {
    if (state === this.state) return;
    this.state = state;
    this._onState(state);
  }

  start() {
    this.stop();
    const generation = this._generation;
    const current = () => generation === this._generation;
    this._active = true;
    this._receivedFrame = false;
    this._lastFrameAt = this._now();
    this._lastMediaTime = null;
    this._lastPresentedFrames = 0;
    this._set("waiting");
    const listen = (name, callback) => {
      const guarded = (...args) => { if (current()) callback(...args); };
      this.video.addEventListener(name, guarded);
      this._listeners.push([name, guarded]);
    };
    const frame = (mediaTime, presentedFrames) => {
      if (!current() || this.video.paused === true) return;
      // A media timestamp can repeat even when the browser presents new
      // frames. Once a frame counter is available, only its progress counts.
      if (Number.isInteger(presentedFrames) && presentedFrames > 0) {
        if (presentedFrames <= this._lastPresentedFrames) return;
        this._lastPresentedFrames = presentedFrames;
      } else {
        if (this._lastPresentedFrames > 0 || !Number.isFinite(mediaTime) ||
            mediaTime === this._lastMediaTime) return;
        this._lastMediaTime = mediaTime;
      }
      this._lastFrameAt = this._now();
      const first = !this._receivedFrame;
      this._receivedFrame = true;
      this._set("playing");
      if (first) {
        this._clearTimeout(this._timer);
        this._timer = this._setTimeout(check, LIVE_STALL_TIMEOUT_MS);
      }
    };
    const check = () => {
      if (!current()) return;
      this._timer = null;
      const limit = this._receivedFrame ? LIVE_STALL_TIMEOUT_MS : LIVE_START_TIMEOUT_MS;
      const remaining = limit - (this._now() - this._lastFrameAt);
      if (remaining <= 0) this._fail(this._receivedFrame ? "stalled" : "timeout");
      else this._timer = this._setTimeout(check, remaining);
    };
    const hasFrameCallback = typeof this.video.requestVideoFrameCallback === "function";
    if (hasFrameCallback) {
      const next = (_now, metadata) => {
        if (!current()) return;
        this._frameCallback = null;
        if (metadata.width > 0 && metadata.height > 0) {
          frame(metadata.mediaTime, metadata.presentedFrames);
        }
        if (current()) this._frameCallback = this.video.requestVideoFrameCallback(next);
      };
      this._frameCallback = this.video.requestVideoFrameCallback(next);
    }
    const fallbackFrame = () => {
      if (hasFrameCallback || this.video.readyState < 2 || this.video.videoWidth <= 0 ||
          this.video.videoHeight <= 0 || this.video.paused) return;
      // Audio may advance currentTime while video is frozen. Prefer the
      // presented-frame counter when the browser exposes playback quality.
      const quality = this.video.getVideoPlaybackQuality?.();
      if (quality) {
        const presented = quality.totalVideoFrames - quality.droppedVideoFrames;
        if (presented > 0) frame(undefined, presented);
      } else frame(this.video.currentTime);
    };
    for (const name of ["loadeddata", "playing", "timeupdate"]) listen(name, fallbackFrame);
    for (const name of ["waiting", "stalled"]) {
      listen(name, () => this._set(this._receivedFrame ? "buffering" : "waiting"));
    }
    listen("pause", () => this._set("paused"));
    listen("ended", () => this._fail("ended"));
    listen("error", () => this._fail("video-error"));
    this._timer = this._setTimeout(check, LIVE_START_TIMEOUT_MS);
    fallbackFrame();
  }

  playRejected(error) {
    if (!this._active) return;
    if (error?.name === "NotAllowedError") this._set("blocked");
    else this._fail("playback-error");
  }

  _fail(reason) {
    if (!this._active) return;
    this.stop();
    this._onError(reason);
  }

  stop() {
    this._generation++;
    this._active = false;
    if (this._timer !== null) this._clearTimeout(this._timer);
    this._timer = null;
    if (this._frameCallback !== null) this.video.cancelVideoFrameCallback?.(this._frameCallback);
    this._frameCallback = null;
    for (const [name, fn] of this._listeners) this.video.removeEventListener(name, fn);
    this._listeners = [];
    this.state = "idle";
  }
}

// The capture belongs to a hold, not to the Live session. Releasing a hold
// stops the actual device synchronously, even if the sender is still busy.
export class NativeTalkbackMachine {
  constructor(ports) {
    this._session = ports.session;
    this._acquire = ports.acquire;
    this._onState = ports.onState || (() => {});
    this._ready = false;
    this._support = { ok: true };
    this._hold = null;
    this._disposed = false;
    this.state = "blocked";
    this.detail = "";
  }

  get supportReason() { return this._support.reason; }

  _set(state, detail = "") {
    if (this._disposed || (this.state === state && this.detail === detail)) return;
    this.state = state;
    this.detail = detail;
    this._onState();
  }

  _idle() {
    this._set(!this._support.ok ? "unsupported" : this._ready ? "idle" : "blocked");
  }

  setSupport(check) {
    this._support = check;
    if (!check.ok) this.notify();
    else if (!this._hold) this._idle();
  }

  setReady(ready) {
    if (this._ready === ready) return;
    this._ready = ready;
    if (!ready) this.notify();
    else if (!this._hold) this._idle();
  }

  async press() {
    if (this._disposed || this._hold || !this._ready || !this._support.ok) return;
    const session = this._session();
    if (!session?.nativeMicReady) return;
    const hold = { session, stream: null, track: null, detach: null };
    const current = () => this._hold === hold && !this._disposed && this._session() === session;
    this._hold = hold;
    this._set("requesting_mic");
    try {
      const stream = await this._acquire();
      if (!current()) {
        for (const track of stream.getTracks()) this._silence(track);
        return;
      }
      hold.stream = stream;
      const track = stream.getAudioTracks()[0];
      for (const extra of stream.getTracks()) if (extra !== track) this._silence(extra);
      if (!track || track.readyState !== "live") throw Error("Microphone track unavailable");
      hold.track = track;
      const ended = () => { if (current()) this.notify(); };
      track.addEventListener?.("ended", ended);
      hold.detach = () => track.removeEventListener?.("ended", ended);
      this._set("starting");
      if (!await session.setNativeMicTrack(track, current)) {
        if (current()) throw Error("Native microphone channel unavailable");
        return;
      }
      if (current()) this._set("talking");
    } catch (err) {
      // The permission prompt often ends the hold before the user denies it,
      // so a released hold still reports its failure. A newer hold or an
      // ended Live owns the state instead.
      if (
        this._disposed || !this._ready || this._session() !== session ||
        (this._hold !== hold && this._hold !== null)
      ) return;
      if (this._hold === hold) this._release();
      const micDenied = err?.name === "NotAllowedError" || err?.name === "SecurityError";
      this._set(micDenied ? "mic_denied" : "error", err?.message || String(err));
    }
  }

  _silence(track) {
    track.enabled = false;
    if (track.readyState !== "ended") track.stop();
  }

  _release() {
    const hold = this._hold;
    this._hold = null;
    if (!hold) return;
    hold.detach?.();
    for (const track of hold.stream?.getTracks() || []) this._silence(track);
    // Serialised by this Live's sender; a late detach from an older hold
    // cannot remove the microphone of a newer hold.
    if (hold.track) void hold.session.setNativeMicTrack(null).catch(() => {});
  }

  notify() {
    this._release();
    this._idle();
  }

  // Ends the user's hold. A mic_denied or error state stays visible.
  release() {
    if (!this._hold) return;
    this._release();
    this._idle();
  }

  dispose() {
    this._disposed = true;
    this._release();
  }
}

export class WebRtcSession {
  constructor(ports) {
    this.entityId = ports.entityId;
    this._callWS = ports.callWS;
    this._subscribeMessage = ports.subscribeMessage;
    this._createPeerConnection = ports.createPeerConnection;
    this._createMediaStream = ports.createMediaStream;
    this._onStream = ports.onStream || (() => {});
    this._onError = ports.onError || (() => {});
    this._useNativeMic = ports.nativeTalkback === true;
    this._onNativeMicReady = ports.onNativeMicReady || (() => {});
    this._nativeMic = null;
    this._peer = null;
    this._remoteStream = null;
    this._unsubscribe = null;
    this._sessionId = "";
    this._localCandidates = [];
    this._remoteCandidates = [];
    this._remoteDescriptionSet = false;
    this._generation = 0;
    this._trackListeners = [];
  }

  async start() {
    this.stop();
    const generation = this._generation;
    try {
      const clientConfig = await this._callWS({
        type: "camera/webrtc/get_client_config",
        entity_id: this.entityId,
      });
      if (generation !== this._generation) return false;
      let nativeSupported = false;
      if (this._useNativeMic) {
        try {
          const camera = await this._callWS({ type: "camera/capabilities", entity_id: this.entityId });
          nativeSupported = camera?.two_way_audio === true;
        } catch (_err) {
          // Cores without this capability still support receive-only playback.
        }
        if (generation !== this._generation) return false;
      }

      const peer = this._createPeerConnection(clientConfig.configuration);
      this._peer = peer;
      this._remoteStream = this._createMediaStream();
      if (clientConfig.dataChannel) {
        peer.createDataChannel(clientConfig.dataChannel);
      }
      peer.onicecandidate = (event) =>
        this._handleLocalCandidate(event, generation);
      peer.oniceconnectionstatechange = () => {
        if (["failed", "closed"].includes(peer.iceConnectionState)) {
          this._fail(new Error("WebRTC ICE connection failed"), generation);
        }
      };
      peer.onconnectionstatechange = () => {
        if (["failed", "closed"].includes(peer.connectionState)) {
          this._fail(new Error("WebRTC connection ended"), generation);
        }
        // A transient disconnected state is not terminal. Playback deadlines
        // detect persistent loss without tearing down on a brief network dip.
      };
      peer.ontrack = (event) => {
        if (generation !== this._generation || !this._remoteStream) return;
        // Always retain both tracks. Home Assistant's current internal player
        // drops audio here when mounted muted, making a later unmute unable to
        // recover street audio.
        this._remoteStream.addTrack(event.track);
        const changed = () => {
          if (generation !== this._generation || !this._remoteStream) return;
          if (event.track.kind === "video" && event.track.readyState === "ended") {
            this._fail(new Error("Video track ended"), generation);
          } else this._onStream(this._remoteStream, event.track);
        };
        for (const name of ["ended", "mute", "unmute"]) {
          event.track.addEventListener?.(name, changed);
          this._trackListeners.push([event.track, name, changed]);
        }
        this._onStream(this._remoteStream, event.track);
      };

      const audio = peer.addTransceiver("audio", { direction: nativeSupported ? "sendrecv" : "recvonly" });
      if (nativeSupported && typeof audio?.sender?.replaceTrack === "function") {
        this._nativeMic = { audio, tail: Promise.resolve(), track: null };
      }
      peer.addTransceiver("video", { direction: "recvonly" });
      const offer = await peer.createOffer({
        offerToReceiveAudio: true,
        offerToReceiveVideo: true,
      });
      if (generation !== this._generation) return false;
      await peer.setLocalDescription(offer);
      if (generation !== this._generation) return false;

      const unsubscribe = this._subscribeMessage(
        (event) => {
          this._handleOfferEvent(event, generation).catch((err) =>
            this._fail(err, generation)
          );
        },
        {
          type: "camera/webrtc/offer",
          entity_id: this.entityId,
          offer: offer.sdp,
        }
      );
      this._unsubscribe = Promise.resolve(unsubscribe);
      await this._unsubscribe;
      if (generation !== this._generation) return false;
      return true;
    } catch (err) {
      this._fail(err, generation);
      return false;
    }
  }

  async _handleOfferEvent(event, generation) {
    if (generation !== this._generation || !event) return;
    if (event.type === "session") {
      this._sessionId = event.session_id;
      const candidates = this._localCandidates;
      this._localCandidates = [];
      await Promise.all(
        candidates.map((candidate) => this._sendLocalCandidate(candidate))
      );
      return;
    }
    if (event.type === "answer") {
      if (!this._peer || ["stable", "closed"].includes(this._peer.signalingState)) {
        return;
      }
      await this._peer.setRemoteDescription({
        type: "answer",
        sdp: event.answer,
      });
      if (generation !== this._generation || !this._peer) return;
      this._remoteDescriptionSet = true;
      if (this._useNativeMic) this._onNativeMicReady(this.nativeMicReady);
      const candidates = this._remoteCandidates;
      this._remoteCandidates = [];
      await Promise.all(
        candidates.map((candidate) => this._peer.addIceCandidate(candidate))
      );
      return;
    }
    if (event.type === "candidate" && this._peer) {
      const candidate = { ...event.candidate };
      if (candidate.sdpMid == null && candidate.sdpMLineIndex == null) {
        candidate.sdpMid = "0";
      }
      if (!this._remoteDescriptionSet) {
        this._remoteCandidates.push(candidate);
      } else {
        await this._peer.addIceCandidate(candidate);
      }
      return;
    }
    if (event.type === "error") {
      throw new Error(event.message || event.code || "WebRTC signaling failed");
    }
  }

  _handleLocalCandidate(event, generation) {
    if (
      generation !== this._generation ||
      !event ||
      !event.candidate ||
      !event.candidate.candidate
    ) {
      return;
    }
    const candidate =
      typeof event.candidate.toJSON === "function"
        ? event.candidate.toJSON()
        : event.candidate;
    if (!this._sessionId) {
      this._localCandidates.push(candidate);
      return;
    }
    this._sendLocalCandidate(candidate).catch((err) =>
      this._fail(err, generation)
    );
  }

  _sendLocalCandidate(candidate) {
    return this._callWS({
      type: "camera/webrtc/candidate",
      entity_id: this.entityId,
      session_id: this._sessionId,
      candidate,
    });
  }

  _fail(err, generation) {
    if (generation !== this._generation) return;
    const message = String((err && err.message) || err || "WebRTC failed");
    this.stop();
    this._onError(message);
  }

  get nativeMicReady() {
    return !!this._nativeMic && this._remoteDescriptionSet &&
      ["sendrecv", "sendonly"].includes(this._nativeMic.audio.currentDirection);
  }

  get nativeMicNegotiated() { return this._remoteDescriptionSet; }

  setNativeMicTrack(track, isCurrent = () => true) {
    const mic = this._nativeMic;
    if (!mic || (track && (!this.nativeMicReady || !isCurrent()))) return Promise.resolve(false);
    // Remember an attachment even if replaceTrack is pending, so closing
    // the whole peer also silences it immediately.
    if (track) mic.track = track;
    else mic.track = null;
    const op = mic.tail.then(async () => {
      if (this._nativeMic !== mic || (track && (!isCurrent() || track.readyState !== "live"))) return false;
      await mic.audio.sender.replaceTrack(track);
      return this._nativeMic === mic && (!track || isCurrent());
    });
    mic.tail = op.catch(() => {});
    return op;
  }

  stop() {
    this._generation++;
    const mic = this._nativeMic;
    this._nativeMic = null;
    if (mic?.track) {
      mic.track.enabled = false;
      if (mic.track.readyState !== "ended") mic.track.stop();
    }
    for (const [track, name, fn] of this._trackListeners) track.removeEventListener?.(name, fn);
    this._trackListeners = [];
    const unsubscribe = this._unsubscribe;
    this._unsubscribe = null;
    if (unsubscribe) {
      unsubscribe.then((fn) => {
        if (typeof fn === "function") fn();
      }).catch(() => {});
    }
    if (this._remoteStream) {
      for (const track of this._remoteStream.getTracks()) track.stop();
      this._remoteStream = null;
    }
    if (this._peer) {
      this._peer.onicecandidate = null;
      this._peer.oniceconnectionstatechange = null;
      this._peer.onconnectionstatechange = null;
      this._peer.ontrack = null;
      this._peer.close();
      this._peer = null;
    }
    this._sessionId = "";
    this._localCandidates = [];
    this._remoteCandidates = [];
    this._remoteDescriptionSet = false;
  }
}

// ---------------------------------------------------------------------------
// Custom element (browser only)
// ---------------------------------------------------------------------------

const BaseElement = typeof HTMLElement === "undefined" ? class {} : HTMLElement;

// Hand-drawn geometric glyphs (hexagon speaker cone + arcs/lines), not traced
// from any icon set — safe to inline without attribution.
const SPEAKER_ON_SVG = `
  <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true" focusable="false">
    <polygon points="3,9 7,9 12,4 12,20 7,15 3,15" fill="currentColor"/>
    <path d="M15.5 8.5a5 5 0 0 1 0 7" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
    <path d="M18 6a9 9 0 0 1 0 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
  </svg>
`;
const SPEAKER_OFF_SVG = `
  <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true" focusable="false">
    <polygon points="3,9 7,9 12,4 12,20 7,15 3,15" fill="currentColor"/>
    <path d="M16 9l5 5M21 9l-5 5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
  </svg>
`;
const PLACEHOLDER_ICON_SVG = `
  <svg viewBox="0 0 24 24" width="40" height="40" aria-hidden="true" focusable="false">
    <rect x="2.5" y="7" width="13" height="10" rx="2" fill="none" stroke="currentColor" stroke-width="1.6"/>
    <circle cx="9" cy="12" r="2.4" fill="none" stroke="currentColor" stroke-width="1.6"/>
    <path d="M16.5 10.2l5-2.7v9l-5-2.7z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>
  </svg>
`;

const CARD_CSS = `
  :host { display: block; }
  ha-card { overflow: hidden; }
  .header {
    display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between;
    gap: 12px; padding: 12px 16px 8px;
  }
  .name {
    flex: 1 1 180px; min-width: 0; overflow-wrap: anywhere;
    font-size: 1.1em; font-weight: 500; color: var(--primary-text-color);
  }
  .header-meta {
    display: inline-flex; align-items: center; justify-content: flex-end;
    flex: 0 0 auto; flex-wrap: wrap; gap: 8px; max-width: 100%; margin-left: auto;
  }
  .ring-badge {
    display: inline-flex; align-items: center; gap: 6px;
    background: var(--warning-color, #ffa600); color: var(--text-primary-color, #fff);
    border-radius: 12px; padding: 2px 10px; font-size: 0.85em;
    animation: abb-pulse 1s ease-in-out infinite alternate;
  }
  @keyframes abb-pulse { from { opacity: 1; } to { opacity: 0.55; } }
  @media (prefers-reduced-motion: reduce) { .ring-badge { animation: none; } }
  .media {
    position: relative; background: #000; aspect-ratio: 16 / 9;
    display: flex; align-items: center; justify-content: center;
  }
  .media > * { width: 100%; height: 100%; }
  .media > video { display: block; object-fit: contain; background: #000; }
  .media > .placeholder { position: absolute; inset: 0; }
  .placeholder {
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    gap: 8px; color: rgba(255, 255, 255, 0.65);
    appearance: none; margin: 0; padding: 12px; border: 0;
    background: transparent; font: inherit; cursor: pointer; touch-action: manipulation;
  }
  .placeholder:enabled:hover { color: #fff; background: rgba(255, 255, 255, 0.06); }
  .placeholder:focus-visible {
    outline: 2px solid var(--primary-color, #03a9f4); outline-offset: -4px;
  }
  .placeholder:disabled { cursor: default; }
  .placeholder svg { opacity: 0.8; }
  .placeholder-text { font-size: 0.9em; }
  .status {
    min-height: 1.4em; padding: 6px 16px 0; font-size: 0.92em;
    color: var(--secondary-text-color);
  }
  .status.error { color: var(--error-color, #b3261e); }
  .mic-info, .audio-info { padding: 4px 16px; font-size: 0.85em; color: var(--secondary-text-color); }
  .mic-info summary { cursor: pointer; min-height: 24px; }
  .mic-info p { margin: 4px 0; }
  .controls {
    display: flex; flex-wrap: wrap; gap: 8px; padding: 10px 16px 16px;
  }
  button.btn {
    min-height: 44px; min-width: 44px; padding: 0 16px;
    border: 1px solid var(--divider-color, #444); border-radius: 10px;
    background: var(--secondary-background-color, #333);
    color: var(--primary-text-color, #eee);
    font: inherit; cursor: pointer;
    touch-action: manipulation; user-select: none; -webkit-user-select: none;
  }
  button.btn:focus-visible {
    outline: 2px solid var(--primary-color, #03a9f4); outline-offset: 2px;
  }
  button.btn[disabled] { opacity: 0.5; cursor: not-allowed; }
  button.icon-btn {
    display: inline-flex; align-items: center; justify-content: center;
    padding: 0; width: 44px;
  }
  button.icon-btn svg { display: block; }
  button.live-btn.active { background: var(--primary-color, #03a9f4); color: #fff; }
  button.audio-btn.active { background: var(--primary-color, #03a9f4); color: #fff; }
  button.audio-btn.attention {
    border-color: var(--warning-color, #ffa600);
    color: var(--warning-color, #ffa600);
  }
  button.ptt-btn { flex: 1 1 40%; touch-action: none; }
  button.ptt-btn.talking {
    background: var(--success-color, #0f9d58); color: #fff;
    border-color: var(--success-color, #0f9d58);
  }
  button.ptt-btn.connecting { background: var(--warning-color, #ffa600); color: #fff; }
  button.unlock-btn { border-color: var(--error-color, #b3261e); }
  .confirm-wrap { display: flex; flex: 1 1 100%; flex-wrap: wrap; gap: 8px; align-items: center; min-width: 0; }
  .confirm-label { flex: 1 1 100%; overflow-wrap: anywhere; font-size: 0.92em; color: var(--primary-text-color); }
  button.confirm-yes { background: var(--error-color, #b3261e); color: #fff; }
  .call-history { padding: 0 16px 12px; border-top: 1px solid var(--divider-color, #444); }
  .history-summary { line-height: 44px; cursor: pointer; }
  .history-summary:focus-visible { outline: 2px solid var(--primary-color, #03a9f4); }
  .history-controls { display: flex; align-items: center; flex-wrap: wrap; gap: 8px 16px; }
  .history-photo-toggle { min-height: 44px; display: inline-flex; align-items: center; gap: 8px; }
  .history-status, .history-row-detail { color: var(--secondary-text-color); font-size: 0.9em; }
  .history-status.is-loading { display: flex; align-items: center; gap: 8px; padding: 8px 0; }
  .history-status.is-loading::before {
    content: ""; flex: none; width: 14px; height: 14px; box-sizing: border-box;
    border: 2px solid currentColor; border-inline-end-color: transparent; border-radius: 50%;
    animation: history-spinner 0.8s linear infinite;
  }
  @keyframes history-spinner { to { transform: rotate(360deg); } }
  @media (prefers-reduced-motion: reduce) {
    .history-status.is-loading::before { animation: none; }
  }
  .history-list { list-style: none; margin: 0; padding: 0; }
  .history-row { padding: 10px 0; border-bottom: 1px solid var(--divider-color, #444); overflow-wrap: anywhere; }
  .history-row:last-child { border-bottom: 0; }
  .history-picture:not(.hidden) { min-height: 24px; margin-top: 8px; }
  .history-picture img { display: block; max-width: min(100%, 480px); max-height: 360px; object-fit: contain; border-radius: 6px; }
  .hidden { display: none !important; }
`;

export class AbbWelcomeIntercomCard extends BaseElement {
  constructor() {
    super();
    this._config = null;
    this._hass = null;
    this._strings = STRINGS.en;
    this._live = false; // false | "starting" | true (signaling, NOT playback)
    this._mediaState = "idle";
    this._mediaMonitor = null;
    this._liveStartTimer = null;
    this._hasIncomingAudio = false;
    this._audioBlocked = false;
    this._playAttempt = 0;
    this._pttKey = "";
    this._wasUnlockConfirm = false;
    this._restoreUnlockFocus = false;
    this._unlockTargetLabel = "";
    this._liveGeneration = 0;
    this._armLease = null;
    this._audioUnmuted = false;
    this._playerEl = null;
    this._webRtc = null;
    this._machine = null;
    this._unlock = null;
    this._statusOverride = "";
    this._statusOverrideError = false;
    this._statusTimer = null;
    this._built = false;
    this._windowListeners = null;
    this._historyRequest = null;
    this._historyPhotosEnabled = true;
    this._historyPhotoSlots = new Map();
    this._historyPhotoBatch = null;
    this._historyRowsVerified = false;
    this._historyCache = null;
  }

  // -- Lovelace card API ---------------------------------------------------

  setConfig(config) {
    validateCardConfig(config);
    const isChange = !!this._config;
    if (isChange) {
      this._closeCallHistory(true);
      if (this._machine) this._machine.dispose("config-changed");
      this._machine = null;
      this._stopLive();
    }
    this._config = { ...config };
    this._buildMachines();
    this._render();
  }

  getCardSize() {
    return 5;
  }

  getGridOptions() {
    return { columns: 12, min_columns: 6 };
  }

  static getConfigForm(hass) {
    const stringsFor = (context) => {
      const current = context?.hass || hass;
      return FORM_STRINGS[pickLanguage(current?.language || current?.locale?.language)];
    };
    return {
      schema: [
        {
          name: "camera",
          required: true,
          selector: { entity: { domain: "camera", integration: "abb_welcome" } },
        },
        { name: "name", selector: { text: {} } },
        {
          name: "unlock_button",
          selector: { entity: { domain: "button" } },
        },
        {
          name: "ring_sensor",
          selector: { entity: { domain: "binary_sensor" } },
        },
        { name: "station_id", selector: { text: {} } },
      ],
      // HA calls these as methods of its form editor, supplying this.hass.
      computeLabel(schema) { return stringsFor(this).labels[schema.name]; },
      computeHelper(schema) { return stringsFor(this).helpers[schema.name]; },
      assertConfig: validateCardConfig,
    };
  }

  static getStubConfig(hass, entities = [], entitiesFallback = []) {
    const pool = [...entities, ...entitiesFallback];
    const isAbbCamera = (id) =>
      typeof id === "string" &&
      id.startsWith("camera.") &&
      hass &&
      hass.entities &&
      hass.entities[id] &&
      hass.entities[id].platform === "abb_welcome";
    let camera = pool.find(isAbbCamera);
    if (!camera && hass && hass.entities) {
      camera = Object.keys(hass.entities).find(isAbbCamera);
    }
    const config = { camera: camera || "" };
    if (camera) {
      const siblings = discoverSiblings(hass, camera);
      if (siblings.unlockButton) config.unlock_button = siblings.unlockButton;
      if (siblings.ringSensor) config.ring_sensor = siblings.ringSensor;
    }
    return config;
  }

  set hass(hass) {
    const previous = this._hass;
    if (previous && previous.user?.id !== hass?.user?.id) this._closeCallHistory(true);
    this._hass = hass;
    if (!this._config) return;
    if (!hass) {
      this._closeCallHistory(true);
      if (this._machine) this._machine.dispose("hass-disconnected");
      this._machine = null;
      if (this._unlock) this._unlock.dispose();
      this._unlock = null;
      if (this._live) this._stopLive();
      this._render();
      return;
    }
    const language =
      hass.language || (hass.locale && hass.locale.language) || "en";
    this._strings = STRINGS[pickLanguage(language)];

    const connected =
      hass.connected !== false &&
      !(hass.connection && hass.connection.connected === false);
    const wasConnected =
      !!previous &&
      (previous.connected !== false &&
        !(previous.connection && previous.connection.connected === false));
    if (!connected) {
      this._closeCallHistory(true);
      if (this._machine) this._machine.dispose("hass-disconnected");
      this._machine = null;
      if (this._unlock) this._unlock.dispose();
      this._unlock = null;
      if (this._live) this._stopLive();
      if (wasConnected) {
        this._flashStatus(this._strings.disconnected, true);
      }
    } else {
      if (!wasConnected) this._clearDisconnectedStatus();
      if (!this._machine) this._buildMachines();
      else if (!this._unlock) this._buildUnlockMachine();
    }

    this._syncTalkReady();
    this._render();
  }

  get hass() {
    return this._hass;
  }

  // -- lifecycle -----------------------------------------------------------

  connectedCallback() {
    this._build();
    if (this._config && !this._machine) this._buildMachines();
    else if (this._config && !this._unlock) this._buildUnlockMachine();
    if (this._windowListeners) return;
    const onPointerUp = () => this._machine?.release();
    const onBlur = () => {
      this._releaseKeyboardHold();
      this._machine?.release();
    };
    const onKeyUp = (event) => {
      if (this._pttKey && event.key === this._pttKey) this._releaseKeyboardHold();
    };
    const onVisibility = () => this._handleVisibilityChange();
    window.addEventListener("pointerup", onPointerUp);
    window.addEventListener("blur", onBlur);
    window.addEventListener("keyup", onKeyUp);
    document.addEventListener("visibilitychange", onVisibility);
    this._windowListeners = { onPointerUp, onBlur, onVisibility, onKeyUp };
    this._render();
  }

  disconnectedCallback() {
    this._closeCallHistory(true);
    if (this._machine) this._machine.dispose("disconnected");
    this._machine = null;
    if (this._unlock) this._unlock.dispose();
    this._unlock = null;
    this._stopLive();
    if (this._windowListeners) {
      window.removeEventListener("pointerup", this._windowListeners.onPointerUp);
      window.removeEventListener("blur", this._windowListeners.onBlur);
      window.removeEventListener("keyup", this._windowListeners.onKeyUp);
      document.removeEventListener(
        "visibilitychange",
        this._windowListeners.onVisibility
      );
      this._windowListeners = null;
    }
    if (this._statusTimer !== null) {
      window.clearTimeout(this._statusTimer);
      this._statusTimer = null;
    }
    this._statusOverride = "";
    this._statusOverrideError = false;
  }

  // -- machines ------------------------------------------------------------

  _syncTalkReady() {
    const state = this._hass?.states?.[this._config?.camera];
    const nativeReady = this._webRtc?.nativeMicReady === true;
    this._machine?.setReady(this._live === true && state?.attributes?.talkback_ready === true && nativeReady);
  }

  _buildMachines() {
    if (this._machine) this._machine.dispose();
    if (this._unlock) this._unlock.dispose();
    const connected =
      !this._hass ||
      (this._hass.connected !== false &&
        !(
          this._hass.connection &&
          this._hass.connection.connected === false
        ));
    if (!connected) {
      this._machine = null;
      this._unlock = null;
      return;
    }
    this._machine = new NativeTalkbackMachine({
      session: () => this._webRtc,
      acquire: () => navigator.mediaDevices.getUserMedia({
        audio: { channelCount: 1, echoCancellation: true, noiseSuppression: true },
        video: false,
      }),
      onState: () => this._render(),
    });
    this._machine.setSupport(capabilityCheck({
      isSecureContext: typeof window !== "undefined" && window.isSecureContext,
      mediaDevices: typeof navigator !== "undefined" ? navigator.mediaDevices : undefined,
    }));
    this._buildUnlockMachine();
  }

  _buildUnlockMachine() {
    if (!this._config) return;
    if (this._unlock) this._unlock.dispose();
    const connected =
      !this._hass ||
      (this._hass.connected !== false &&
        !(
          this._hass.connection &&
          this._hass.connection.connected === false
        ));
    if (!connected) {
      this._unlock = null;
      return;
    }
    const rerender = () => this._render();
    this._unlock = new UnlockConfirm({
      snapshotTarget: () => this._snapshotUnlockEntity(),
      validateTarget: (entityId) => this._isUnlockEntityValid(entityId),
      invalidTargetMessage: this._strings.err_unlock_target,
      pressButton: (entityId) => {
        const hass = this._hass;
        if (
          !hass ||
          typeof hass.callService !== "function" ||
          !this._isUnlockEntityValid(entityId)
        ) {
          return Promise.reject(new Error(this._strings.err_unlock_target));
        }
        return hass.callService("button", "press", { entity_id: entityId });
      },
      setTimeout: (fn, ms) => window.setTimeout(fn, ms),
      clearTimeout: (id) => window.clearTimeout(id),
      onState: rerender,
    });
  }

  _clearDisconnectedStatus() {
    if (
      ![STRINGS.en.disconnected, STRINGS.it.disconnected].includes(
        this._statusOverride
      )
    ) {
      return;
    }
    if (this._statusTimer !== null) {
      window.clearTimeout(this._statusTimer);
      this._statusTimer = null;
    }
    this._statusOverride = "";
    this._statusOverrideError = false;
  }

  _handleVisibilityChange() {
    if (typeof document === "undefined") return;
    if (document.visibilityState !== "hidden") {
      if (this._config && !this._unlock) this._buildUnlockMachine();
      return;
    }
    this._machine?.release();
    if (this._unlock) this._unlock.dispose();
    this._unlock = null;
    if (this._live) this._stopLive();
    else this._render();
  }

  _unlockEntity() {
    if (this._config.unlock_button) return this._config.unlock_button;
    const siblings = discoverSiblings(this._hass, this._config.camera);
    return siblings.unlockButton || "";
  }

  _isUnlockEntityValid(entityId) {
    if (
      typeof entityId !== "string" ||
      !entityId.startsWith("button.") ||
      !this._hass ||
      !this._hass.states
    ) {
      return false;
    }
    const state = this._hass.states[entityId];
    // A button that was never pressed is "unknown"; it can still unlock.
    return !!state && state.state !== "unavailable";
  }

  _snapshotUnlockEntity() {
    const entityId = this._unlockEntity();
    if (!this._isUnlockEntityValid(entityId)) return "";
    const name = this._hass.states[entityId].attributes?.friendly_name;
    this._unlockTargetLabel = name ? `${name} (${entityId})` : entityId;
    return entityId;
  }

  _ringEntity() {
    if (this._config.ring_sensor) return this._config.ring_sensor;
    const siblings = discoverSiblings(this._hass, this._config.camera);
    return siblings.ringSensor || "";
  }

  // -- live view -----------------------------------------------------------

  _sendArmRelease(lease, phase) {
    if (!lease || lease.releasePhases.has(phase)) return;
    lease.releasePhases.add(phase);
    try {
      Promise.resolve(
        lease.hass.callService("abb_welcome", "arm_streaming", {
          ...lease.scope,
          owner_token: lease.ownerToken,
          release: true,
        })
      ).catch(() => {});
    } catch (_err) {
      /* release is best-effort and owner-scoped */
    }
  }

  _requestArmRelease(lease = this._armLease) {
    if (!lease) return;
    lease.releaseRequested = true;
    if (lease.renewTimer !== null) window.clearTimeout(lease.renewTimer);
    lease.renewTimer = null;
    if (!lease.armSettled) {
      lease.releaseWhilePending = true;
      this._sendArmRelease(lease, "eager");
      return;
    }
    this._sendArmRelease(lease, "settled");
    if (this._armLease === lease) this._armLease = null;
  }

  _scheduleLeaseRenewal(lease) {
    const owns = () => this._armLease === lease && !lease.releaseRequested;
    lease.renewTimer = window.setTimeout(async () => {
      lease.renewTimer = null;
      if (!owns()) return;
      try {
        await lease.hass.callService("abb_welcome", "arm_streaming", {
          ...lease.scope,
          owner_token: lease.ownerToken,
          duration: LIVE_LEASE_SECONDS,
          renew: true,
        });
      } catch (err) {
        if (!owns()) return;
        // The integration refused the renewal: the window has ended, for
        // example when a borrowed ring window closed. Anything else, such as
        // a dropped connection, is retried while the lease still runs.
        if (err?.code === "home_assistant_error") {
          this._stopLive();
          this._flashStatus(this._strings.live_ended, true, 10000);
          return;
        }
      }
      if (owns()) this._scheduleLeaseRenewal(lease);
    }, LIVE_LEASE_RENEW_MS);
  }

  async _startLive() {
    if (this._live || !this._hass || !this._config) return;
    const generation = ++this._liveGeneration;
    const hass = this._hass;
    const config = { ...this._config };
    const strings = this._strings;
    const ownsLive = () => generation === this._liveGeneration;
    const isCurrent = () => ownsLive() && this._live === "starting";
    this._live = "starting";
    this._mediaState = "connecting";
    this._clearStatus();
    // Covers a hung arm request or signaling subscription as well as video.
    this._liveStartTimer = window.setTimeout(() => {
      if (ownsLive()) this._endVideo("timeout");
    }, LIVE_START_TIMEOUT_MS);
    this._render();
    let scope;
    try {
      scope = resolveArmScope(hass, config.camera, config);
      if (!scope) throw new Error(strings.err_missing_scope);
    } catch (err) {
      if (!isCurrent()) return;
      this._stopLive();
      this._flashStatus(mapServiceError(err, strings), true);
      return;
    }
    if (
      typeof RTCPeerConnection === "undefined" ||
      typeof MediaStream === "undefined" ||
      !hass.connection ||
      typeof hass.connection.subscribeMessage !== "function"
    ) {
      this._stopLive();
      this._flashStatus(strings.live_unavailable, true, 10000);
      return;
    }
    const lease = {
      hass,
      scope,
      ownerToken: makeSessionId(),
      armSettled: false,
      releaseRequested: false,
      releaseWhilePending: false,
      releasePhases: new Set(),
      renewTimer: null,
    };
    this._armLease = lease;
    let armError = null;
    try {
      await hass.callService("abb_welcome", "arm_streaming", {
        ...scope,
        owner_token: lease.ownerToken,
        duration: LIVE_LEASE_SECONDS,
      });
    } catch (err) {
      armError = err;
    }
    lease.armSettled = true;
    if (lease.releaseRequested) this._requestArmRelease(lease);
    if (armError) {
      this._requestArmRelease(lease);
      if (!isCurrent()) return;
      this._stopLive();
      this._flashStatus(mapServiceError(armError, strings), true);
      return;
    }
    if (!isCurrent()) {
      this._requestArmRelease(lease);
      return;
    }
    this._scheduleLeaseRenewal(lease);

    this._mountPlayer();
    const session = new WebRtcSession({
      entityId: config.camera,
      nativeTalkback: config.native_talkback !== false && !this._machine?.supportReason,
      onNativeMicReady: () => {
        if (!ownsLive() || this._webRtc !== session) return;
        this._syncTalkReady();
        this._render();
      },
      callWS: (message) => hass.callWS(message),
      subscribeMessage: (callback, message) =>
        hass.connection.subscribeMessage(callback, message),
      createPeerConnection: (configuration) =>
        new RTCPeerConnection(configuration),
      createMediaStream: () => new MediaStream(),
      onStream: (stream) => {
        if (!ownsLive() || this._webRtc !== session || !this._playerEl) return;
        this._hasIncomingAudio = stream.getTracks().some(
          (track) => track.kind === "audio" && track.readyState !== "ended" && !track.muted
        );
        // A second ontrack adds audio to the same stream. Reassigning srcObject
        // would reset playback and could discard the first-frame observation.
        if (this._playerEl.srcObject !== stream) {
          this._playerEl.srcObject = stream;
          this._playVideo();
        }
        this._render();
      },
      onError: (message) => {
        if (!ownsLive() || this._webRtc !== session) return;
        this._stopLive();
        this._flashStatus(
          `${strings.live_unavailable} ${message}`,
          true,
          10000
        );
      },
    });
    this._webRtc = session;
    const started = await session.start();
    if (!isCurrent() || this._webRtc !== session) return;
    if (!started) {
      this._stopLive();
      return;
    }
    this._live = true;
    this._syncTalkReady();
    this._render();
  }

  _mountPlayer() {
    this._unmountPlayer();
    const el = document.createElement("video");
    el.controls = true;
    el.autoplay = true;
    el.playsInline = true;
    // Muting the native element permits autoplay but does not affect WebRTC
    // track attachment. The Audio button can therefore recover street audio.
    this._audioUnmuted = false;
    el.muted = true;
    el.addEventListener("volumechange", () => {
      const unmuted = !el.muted && el.volume > 0;
      if (unmuted === this._audioUnmuted) return;
      this._audioUnmuted = unmuted;
      this._render();
    });
    this._refs.media.appendChild(el);
    this._playerEl = el;
    const generation = this._liveGeneration;
    const ownsPlayer = () => generation === this._liveGeneration && this._playerEl === el;
    this._mediaMonitor = new VideoPlaybackMonitor(el, {
      setTimeout: (fn, ms) => window.setTimeout(fn, ms),
      clearTimeout: (id) => window.clearTimeout(id),
      onState: (state) => {
        if (!ownsPlayer()) return;
        this._mediaState = state;
        if (state === "playing") {
          this._clearLiveStartTimer();
        }
        this._render();
      },
      onError: (reason) => { if (ownsPlayer()) this._endVideo(reason); },
    });
    this._mediaMonitor.start();
    this._render();
  }

  _clearLiveStartTimer() {
    if (this._liveStartTimer !== null) window.clearTimeout(this._liveStartTimer);
    this._liveStartTimer = null;
  }

  _endVideo(reason) {
    const keys = { timeout: "video_timeout", stalled: "video_stalled", ended: "video_ended" };
    this._stopLive();
    this._flashStatus(this._strings[keys[reason] || "video_error"], true, 10000);
  }

  _playVideo(audioGesture = false) {
    const el = this._playerEl;
    const generation = this._liveGeneration;
    if (!el) return;
    const attempt = ++this._playAttempt;
    const current = () => this._playerEl === el &&
      this._liveGeneration === generation && this._playAttempt === attempt;
    // Call synchronously to preserve the browser's user-activation context.
    let playback;
    try { playback = el.play(); }
    catch (err) { playback = Promise.reject(err); }
    Promise.resolve(playback).then(() => {
      if (!current()) return;
      if (audioGesture) this._audioBlocked = false;
      this._render();
    }).catch((err) => {
      if (!current()) return;
      if (audioGesture && err?.name === "NotAllowedError") {
        el.muted = true;
        this._audioUnmuted = false;
        this._audioBlocked = true;
        // Preserve muted video when only the attempt to listen was blocked.
        this._playVideo();
        this._render();
      } else {
        this._mediaMonitor?.playRejected(err);
      }
    });
  }

  _toggleAudio() {
    this._audioUnmuted = !this._audioUnmuted;
    this._applyAudio();
    this._render();
  }

  _applyAudio() {
    const el = this._playerEl;
    if (!el) return;
    el.muted = !this._audioUnmuted;
    if (this._audioUnmuted) {
      el.volume = 1;
      this._playVideo(true);
    } else {
      // An older unmute attempt must not overwrite a later mute action.
      this._playAttempt++;
    }
  }

  _unmountPlayer() {
    if (this._mediaMonitor) this._mediaMonitor.stop();
    this._mediaMonitor = null;
    const session = this._webRtc;
    this._webRtc = null;
    if (session) session.stop();
    if (this._playerEl) {
      this._playerEl.srcObject = null;
      this._playerEl.remove();
      this._playerEl = null;
    }
  }

  _stopLive() {
    this._liveGeneration++;
    this._clearLiveStartTimer();
    this._pttKey = "";
    this._machine?.setReady(false);
    this._requestArmRelease();
    this._unmountPlayer();
    this._live = false;
    this._mediaState = "idle";
    this._hasIncomingAudio = false;
    this._audioBlocked = false;
    this._render();
  }

  // -- rendering -----------------------------------------------------------

  _historyUrl(callId, photoIndex) {
    const query = new URLSearchParams({ camera: this._config.camera });
    if (callId) query.set("call_id", callId);
    if (photoIndex > 0) query.set("photo_index", String(photoIndex));
    return `/api/abb_welcome/call_history?${query}`;
  }

  _clearHistoryPhotos() {
    const batch = this._historyPhotoBatch;
    this._historyPhotoBatch = null;
    batch?.observer?.disconnect();
    batch?.controller.abort();
    for (const slot of this._historyPhotoSlots.values()) {
      if (slot.url) URL.revokeObjectURL(slot.url);
      slot.url = null;
      slot.container.replaceChildren();
      slot.container.classList.toggle("hidden", true);
    }
  }

  _closeCallHistory(discardCache = false) {
    this._historyRequest?.abort();
    this._historyRequest = null;
    if (discardCache) this._historyCache = null;
    this._clearHistoryPhotos();
    this._historyPhotoSlots.clear();
    this._historyRowsVerified = false;
    if (!this._refs?.history) return;
    this._refs.history.open = false;
    this._refs.historyStatus.textContent = "";
    this._refs.historyStatus.classList.toggle("is-loading", false);
    this._refs.historyList.replaceChildren();
    this._refs.historyRefresh.disabled = false;
  }

  _renderCallHistoryRows(calls) {
    this._clearHistoryPhotos();
    this._historyPhotoSlots.clear();
    this._refs.historyList.replaceChildren(...calls.map((call) => this._historyRow(call)));
  }

  async _refreshCallHistory(force = false) {
    const { history, historyStatus, historyList, historyRefresh } = this._refs;
    if (!history.open || typeof this._hass?.fetchWithAuth !== "function") return;
    this._historyRequest?.abort();
    if (this._historyCache?.expiresAt <= Date.now()) this._historyCache = null;
    let visibleRows = this._historyCache?.calls ?? null;
    let visibleFingerprint = this._historyCache?.fingerprint;
    const controller = new AbortController();
    this._historyRequest = controller;
    if (visibleRows) {
      if (!historyList.childElementCount) this._renderCallHistoryRows(visibleRows);
    } else this._renderCallHistoryRows([]);
    historyStatus.textContent = visibleRows ? this._strings.history_updating : this._strings.history_loading;
    historyStatus.classList.toggle("is-loading", true);
    historyRefresh.disabled = true;
    const current = () => this._historyRequest === controller && history.open;

    const load = async (fresh = false) => {
      const url = this._historyUrl() + (fresh ? "&fresh=1" : "");
      const response = await this._hass.fetchWithAuth(url, {
        cache: "no-store", signal: controller.signal,
      });
      if (!current()) return null;
      if (response.status === 401 || response.status === 403) {
        this._historyCache = null;
        this._renderCallHistoryRows([]);
        this._historyRowsVerified = false;
        historyStatus.textContent = this._strings.history_forbidden;
        return null;
      }
      if (!response.ok) throw new Error("Call history request failed");
      const result = await response.json();
      if (!current()) return null;
      if (!Array.isArray(result?.calls)) throw new Error("Invalid call history");
      return result;
    };
    const show = (result) => {
      const rows = result.calls.slice(0, 20);
      const fingerprint = JSON.stringify(rows);
      if (visibleFingerprint !== fingerprint) this._renderCallHistoryRows(rows);
      visibleRows = rows;
      visibleFingerprint = fingerprint;
      if (result.stale !== true && result.photos_incomplete !== true) {
        this._historyCache = { calls: rows, fingerprint, expiresAt: Date.now() + HISTORY_CACHE_MS };
      } else if (result.photos_incomplete === true) this._historyCache = null;
    };
    try {
      let result = await load(force);
      if (!result || !current()) return;
      show(result);
      if (!force && result.stale === true) {
        historyStatus.textContent = this._strings.history_updating;
        const refreshed = await load(true);
        if (!refreshed || !current()) return;
        result = refreshed;
        show(result);
      }
      this._historyRowsVerified = true;
      if (force) this._clearHistoryPhotos();
      this._showHistoryPhotos();
      historyStatus.textContent = result.photos_incomplete === true
        ? this._strings.history_photos_incomplete
        : result.stale === true
          ? this._strings.history_cached
          : visibleRows.length ? "" : this._strings.history_empty;
    } catch (_error) {
      if (current()) {
        historyStatus.textContent = visibleRows?.length
          ? this._strings.history_cached : this._strings.history_unavailable;
      }
    } finally {
      if (current()) {
        historyStatus.classList.toggle("is-loading", false);
        historyRefresh.disabled = false;
        this._historyRequest = null;
      }
    }
  }

  _historyRow(call) {
    const s = this._strings;
    const row = document.createElement("li");
    row.className = "history-row";
    const date = call.timestamp ? new Date(call.timestamp) : null;
    const validDate = date && Number.isFinite(date.getTime());
    const time = document.createElement(validDate ? "time" : "span");
    if (validDate) time.dateTime = date.toISOString();
    time.textContent = validDate
      ? date.toLocaleString(pickLanguage(this._hass?.language || this._hass?.locale?.language), {
          dateStyle: "medium", timeStyle: "short",
        })
      : s.history_no_date;
    row.appendChild(time);
    const detail = document.createElement("div");
    detail.className = "history-row-detail";
    const outcomes = { ring: s.history_ring, answered: s.history_answered,
      missed: s.history_missed, ended: s.history_ended };
    detail.textContent = [call.station, outcomes[call.outcome] || s.history_ring]
      .filter(Boolean).join(" · ");
    row.appendChild(detail);
    if (call.has_photo === true && typeof call.id === "string" && call.id) {
      const count = Number.isInteger(call.photo_count)
        ? Math.max(1, Math.min(call.photo_count, MAX_HISTORY_PHOTOS_PER_CALL)) : 1;
      for (let index = 0; index < count; index++) {
        const container = document.createElement("div");
        container.className = "history-picture hidden";
        this._historyPhotoSlots.set(container, { container, callId: call.id, index, capturedAt: time.textContent, url: null });
        row.appendChild(container);
      }
    }
    return row;
  }

  _showHistoryPhotos() {
    if (!this._historyPhotosEnabled || !this._historyRowsVerified || this._historyPhotoBatch ||
        !this._refs.history.open || !this._historyPhotoSlots.size) return;
    const batch = { controller: new AbortController(), observer: null, pending: [], active: 0 };
    this._historyPhotoBatch = batch;
    const drain = () => {
      while (this._historyPhotoBatch === batch && this._refs.history.open &&
             batch.active < HISTORY_PHOTO_CONCURRENCY && batch.pending.length) {
        const slot = batch.pending.shift();
        batch.active++;
        void this._loadHistoryPhoto(batch, slot).finally(() => {
          batch.active--;
          drain();
        });
      }
    };
    if (typeof IntersectionObserver === "function") {
      batch.observer = new IntersectionObserver((entries) => {
        if (this._historyPhotoBatch !== batch) return;
        for (const entry of entries) {
          if (!entry.isIntersecting) continue;
          batch.observer.unobserve(entry.target);
          const slot = this._historyPhotoSlots.get(entry.target);
          if (!slot || slot.queued) continue;
          slot.queued = true;
          batch.pending.push(slot);
        }
        drain();
      }, { rootMargin: "160px 0px" });
    }
    for (const slot of this._historyPhotoSlots.values()) {
      slot.queued = false;
      slot.container.classList.toggle("hidden", false);
      if (batch.observer) batch.observer.observe(slot.container);
      else batch.pending.push(slot);
    }
    drain();
  }

  async _loadHistoryPhoto(batch, slot) {
    const { container, callId, index, capturedAt } = slot;
    const current = () => this._historyPhotoBatch === batch && this._refs.history.open;
    container.textContent = this._strings.history_photo_loading;
    try {
      const response = await this._hass.fetchWithAuth(this._historyUrl(callId, index), {
        cache: "no-store", signal: batch.controller.signal,
      });
      if (!current()) return;
      if (!response.ok || response.headers.get("content-type")?.split(";")[0] !== "image/jpeg") {
        throw new Error("Call photo request failed");
      }
      const blob = await response.blob();
      if (!current()) return;
      if (!blob.size || blob.size > 2 * 1024 * 1024) throw new Error("Invalid photo size");
      const image = document.createElement("img");
      image.alt = `${this._strings.history_photo_alt} · ${capturedAt}`;
      image.decoding = "async";
      image.addEventListener("error", () => {
        if (!current()) return;
        if (slot.url) URL.revokeObjectURL(slot.url);
        slot.url = null;
        container.textContent = this._strings.history_photo_error;
      });
      slot.url = URL.createObjectURL(blob);
      image.src = slot.url;
      container.replaceChildren(image);
    } catch (_error) {
      if (current()) container.textContent = this._strings.history_photo_error;
    }
  }

  _build() {
    if (this._built) return;
    this._built = true;
    const root = this.attachShadow({ mode: "open" });
    root.innerHTML = `
      <style>${CARD_CSS}</style>
      <ha-card>
        <div class="header">
          <span class="name"></span>
          <span class="header-meta">
            <span class="ring-badge hidden" role="status"></span>
          </span>
        </div>
        <div class="media">
          <button class="placeholder" type="button" disabled>
            ${PLACEHOLDER_ICON_SVG}
            <span class="placeholder-text"></span>
          </button>
        </div>
        <div class="status" role="status" aria-live="polite"></div>
        <div class="audio-info hidden" role="status"></div>
        <details class="mic-info hidden">
          <summary class="mic-summary"></summary>
          <p class="mic-detail"></p>
        </details>
        <div class="controls">
          <button class="btn live-btn" type="button"></button>
          <button class="btn play-btn hidden" type="button"></button>
          <button class="btn icon-btn audio-btn hidden" type="button" aria-pressed="false"></button>
          <button class="btn ptt-btn" type="button" aria-pressed="false"></button>
          <button class="btn unlock-btn" type="button"></button>
          <span class="confirm-wrap hidden" role="group" aria-labelledby="confirm-label">
            <span class="confirm-label" id="confirm-label"></span>
            <button class="btn confirm-yes" type="button"></button>
            <button class="btn confirm-no" type="button"></button>
          </span>
        </div>
        <details class="call-history hidden">
          <summary class="history-summary"></summary>
          <div class="history-controls">
            <button class="btn history-refresh" type="button"></button>
            <div class="history-photo-toggle">
              <ha-switch class="history-photo-switch" checked></ha-switch>
              <span class="history-photo-label" aria-hidden="true"></span>
            </div>
          </div>
          <div class="history-status" role="status"></div>
          <ul class="history-list" role="list"></ul>
        </details>
      </ha-card>
    `;
    this._refs = {
      name: root.querySelector(".name"),
      ringBadge: root.querySelector(".ring-badge"),
      media: root.querySelector(".media"),
      placeholder: root.querySelector(".placeholder"),
      placeholderText: root.querySelector(".placeholder-text"),
      status: root.querySelector(".status"),
      audioInfo: root.querySelector(".audio-info"),
      micInfo: root.querySelector(".mic-info"),
      micSummary: root.querySelector(".mic-summary"),
      micDetail: root.querySelector(".mic-detail"),
      liveBtn: root.querySelector(".live-btn"),
      playBtn: root.querySelector(".play-btn"),
      audioBtn: root.querySelector(".audio-btn"),
      pttBtn: root.querySelector(".ptt-btn"),
      unlockBtn: root.querySelector(".unlock-btn"),
      confirmWrap: root.querySelector(".confirm-wrap"),
      confirmLabel: root.querySelector(".confirm-label"),
      confirmYes: root.querySelector(".confirm-yes"),
      confirmNo: root.querySelector(".confirm-no"),
      history: root.querySelector(".call-history"),
      historySummary: root.querySelector(".history-summary"),
      historyRefresh: root.querySelector(".history-refresh"),
      historyPhotoSwitch: root.querySelector(".history-photo-switch"),
      historyPhotoLabel: root.querySelector(".history-photo-label"),
      historyStatus: root.querySelector(".history-status"),
      historyList: root.querySelector(".history-list"),
    };

    this._refs.history.addEventListener("toggle", () => {
      if (this._refs.history.open) return this._refreshCallHistory();
      else this._closeCallHistory();
    });
    this._refs.historyRefresh.addEventListener("click", () => this._refreshCallHistory(true));
    this._refs.historyPhotoSwitch.addEventListener("change", (event) => {
      this._historyPhotosEnabled = event.currentTarget.checked === true;
      if (this._historyPhotosEnabled) this._showHistoryPhotos();
      else this._clearHistoryPhotos();
    });
    this._refs.liveBtn.addEventListener("click", () => {
      if (this._live) this._stopLive();
      else this._startLive();
    });
    this._refs.placeholder.addEventListener("click", () => {
      if (this._refs.placeholder.disabled) return;
      if (root.activeElement === this._refs.placeholder) this._refs.liveBtn.focus();
      void this._startLive();
    });
    this._refs.audioBtn.addEventListener("click", () => this._toggleAudio());
    this._refs.playBtn.addEventListener("click", () => this._playVideo());

    const ptt = this._refs.pttBtn;
    ptt.addEventListener("pointerdown", (event) => {
      event.preventDefault();
      if (ptt.disabled) return;
      try {
        ptt.setPointerCapture(event.pointerId);
      } catch (_err) {
        /* ignore */
      }
      this._machine.press();
    });
    for (const name of ["pointerup", "pointercancel", "pointerleave", "lostpointercapture"]) {
      ptt.addEventListener(name, () => this._machine?.release());
    }
    ptt.addEventListener("contextmenu", (event) => event.preventDefault());
    ptt.addEventListener("keydown", (event) => {
      if (event.key === " " || event.key === "Enter") {
        event.preventDefault();
        if (ptt.disabled || event.repeat || this._pttKey) return;
        this._pttKey = event.key;
        this._machine.press();
      }
    });
    ptt.addEventListener("keyup", (event) => {
      if (this._pttKey && event.key === this._pttKey) {
        event.preventDefault();
        this._releaseKeyboardHold();
      }
    });
    ptt.addEventListener("focusout", () => {
      this._releaseKeyboardHold();
      // Pointer holds are also released if focus moves away from the control.
      this._machine?.release();
    });

    this._refs.unlockBtn.addEventListener("click", () => {
      if (this._unlock) this._unlock.tap();
    });
    this._refs.confirmYes.addEventListener("click", async () => {
      const unlock = this._unlock;
      if (!unlock) return;
      const confirmed = await unlock.confirm();
      if (confirmed && this._unlock === unlock) {
        this._flashStatus(this._strings.unlocked, false);
      }
    });
    this._refs.confirmNo.addEventListener("click", () => {
      if (this._unlock) this._unlock.cancel();
    });
    this._refs.confirmWrap.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && this._unlock?.state === "confirm") {
        event.preventDefault();
        this._unlock.cancel();
      }
    });
  }

  _releaseKeyboardHold() {
    if (!this._pttKey) return;
    this._pttKey = "";
    this._machine?.release();
  }

  _clearStatus() {
    if (this._statusTimer !== null) window.clearTimeout(this._statusTimer);
    this._statusTimer = null;
    this._statusOverride = "";
    this._statusOverrideError = false;
  }

  _flashStatus(text, isError, ms = 6000) {
    this._statusOverride = text;
    this._statusOverrideError = !!isError;
    if (this._statusTimer !== null) window.clearTimeout(this._statusTimer);
    this._statusTimer = window.setTimeout(() => {
      this._statusTimer = null;
      this._statusOverride = "";
      this._statusOverrideError = false;
      this._render();
    }, ms);
    this._render();
  }

  _statusText() {
    const s = this._strings;
    if (this._statusOverride) {
      return { text: this._statusOverride, error: this._statusOverrideError };
    }
    if (this._unlock) {
      if (this._unlock.state === "busy") return { text: s.unlocking, error: false };
      if (this._unlock.state === "error") {
        return { text: `${s.error}: ${this._unlock.errorText}`, error: true };
      }
    }
    if (this._config.native_talkback !== false && this._machine) {
      switch (this._machine.state) {
        case "unsupported":
          break; // Microphone capability is shown separately from video state.
        case "mic_denied":
          return { text: s.mic_denied, error: true };
        case "requesting_mic":
          return { text: s.requesting_mic, error: false };
        case "starting":
          return { text: s.connecting, error: false };
        case "talking":
          return { text: s.native_talking, error: false };
        case "error":
          return {
            text: s.mic_error,
            error: true,
          };
        default:
          break;
      }
    }
    const mediaText = {
      connecting: s.live_starting, waiting: s.video_waiting,
      playing: s.video_playing, buffering: s.video_buffering,
      paused: s.video_paused, blocked: s.video_blocked,
    }[this._mediaState];
    if (mediaText) return { text: mediaText, error: false };
    if (this._live === "starting") return { text: s.live_starting, error: false };
    if (this._live !== true) return { text: "", error: false };
    return { text: "", error: false };
  }

  _render() {
    if (!this._built || !this._config) return;
    const s = this._strings;
    const refs = this._refs;
    const stateObj =
      this._hass && this._hass.states && this._hass.states[this._config.camera];

    refs.name.textContent =
      this._config.name ||
      (stateObj &&
        (stateObj.attributes.friendly_name || this._config.camera)) ||
      s.name_default;
    refs.history.classList.toggle("hidden", typeof this._hass?.fetchWithAuth !== "function");
    refs.historySummary.textContent = s.history;
    refs.historyRefresh.textContent = s.history_refresh;
    refs.historyPhotoLabel.textContent = s.history_photos;
    refs.historyPhotoSwitch.setAttribute("aria-label", s.history_photos);

    // ring badge
    const ringId = this._hass ? this._ringEntity() : "";
    const ringState = ringId && this._hass.states && this._hass.states[ringId];
    const stationId = resolveStationId(
      this._hass,
      this._config.camera,
      this._config
    );
    const ringing = ringMatchesStation(ringState, stationId);
    refs.ringBadge.classList.toggle("hidden", !ringing);
    if (ringing) {
      const station =
        (ringState.attributes &&
          (ringState.attributes.station_name || ringState.attributes.station)) ||
        "";
      refs.ringBadge.textContent = station ? `${s.ringing} · ${station}` : s.ringing;
    }

    // The idle control starts live video and never shows a stale screenshot.
    const showPlaceholder = !this._playerEl;
    refs.placeholder.classList.toggle("hidden", !showPlaceholder);
    refs.placeholder.disabled = !showPlaceholder || !this._hass || Boolean(this._live);
    if (showPlaceholder) {
      refs.placeholderText.textContent =
        this._live === "starting" ? s.live_starting : s.idle_placeholder;
    }

    // live button
    refs.liveBtn.textContent = this._live ? s.stop : s.live;
    refs.liveBtn.classList.toggle("active", this._mediaState === "playing");
    // A slow arm/signaling request must remain cancellable by the user.
    refs.liveBtn.disabled = !this._hass;
    refs.playBtn.classList.toggle("hidden", !["paused", "blocked"].includes(this._mediaState));
    refs.playBtn.textContent = s.play_video;

    // audio toggle (only meaningful while the player is mounted)
    refs.audioBtn.classList.toggle("hidden", this._live !== true);
    refs.audioBtn.disabled = !this._hasIncomingAudio;
    refs.audioBtn.innerHTML = this._audioUnmuted
      ? SPEAKER_ON_SVG
      : SPEAKER_OFF_SVG;
    const audioLabel = this._audioUnmuted ? s.audio_on : s.audio_off;
    refs.audioBtn.setAttribute("aria-label", audioLabel);
    refs.audioBtn.title = audioLabel;
    refs.audioBtn.classList.toggle("active", this._audioUnmuted);
    refs.audioBtn.classList.toggle(
      "attention",
      this._live === true && this._hasIncomingAudio && !this._audioUnmuted
    );
    refs.audioBtn.setAttribute(
      "aria-pressed",
      this._audioUnmuted ? "true" : "false"
    );
    const audioMessage = this._audioBlocked ? s.audio_blocked :
      this._live === true && !this._hasIncomingAudio ?
        (this._mediaState === "playing" ? s.audio_missing : s.audio_waiting) : "";
    refs.audioInfo.textContent = audioMessage;
    refs.audioInfo.classList.toggle("hidden", !audioMessage);

    // ptt button
    const machineState = this._machine ? this._machine.state : "blocked";
    const pttEnabled =
      this._live === true &&
      ["idle", "mic_denied", "requesting_mic", "starting", "talking", "error"].includes(
        machineState
      );
    refs.pttBtn.disabled = !pttEnabled;
    refs.pttBtn.classList.toggle("hidden", this._config.native_talkback === false);
    refs.pttBtn.textContent =
      machineState === "talking"
        ? s.native_talking
        : machineState === "starting"
          ? s.connecting
          : machineState === "requesting_mic"
            ? s.requesting_mic
            : s.ptt;
    refs.pttBtn.classList.toggle("talking", machineState === "talking");
    refs.pttBtn.classList.toggle(
      "connecting",
      machineState === "starting"
    );
    refs.pttBtn.setAttribute(
      "aria-pressed",
      machineState === "talking" ? "true" : "false"
    );
    refs.pttBtn.setAttribute("aria-label", s.ptt);
    const unsupported = this._config.native_talkback !== false && machineState === "unsupported";
    const noNativeChannel = this._config.native_talkback !== false && this._live === true &&
      this._webRtc?.nativeMicNegotiated && !this._webRtc.nativeMicReady;
    refs.micInfo.classList.toggle("hidden", !unsupported && !noNativeChannel);
    refs.micSummary.textContent = unsupported ? supportMessage(this._machine.supportReason, s) :
      noNativeChannel ? s.native_talk_unavailable : "";
    refs.micDetail.textContent = this._machine?.supportReason === "insecure-context" ? s.https_details :
      supportMessage(this._machine?.supportReason, s);

    // unlock
    const unlockEntity = this._hass ? this._unlockEntity() : "";
    const unlockAvailable = this._isUnlockEntityValid(unlockEntity);
    const unlockState = this._unlock ? this._unlock.state : "idle";
    const confirming = unlockState === "confirm";
    const active = this.shadowRoot?.activeElement;
    if (this._wasUnlockConfirm && !confirming &&
        [refs.confirmNo, refs.confirmYes].includes(active)) this._restoreUnlockFocus = true;
    if (this._restoreUnlockFocus) {
      const outerActive = document.activeElement;
      const focusStillHere = [refs.confirmNo, refs.confirmYes].includes(active) ||
        (!active && (!outerActive || outerActive === document.body || outerActive === this));
      // Do not steal focus if the user moved elsewhere while unlock was busy.
      if (!focusStillHere) this._restoreUnlockFocus = false;
    }
    refs.unlockBtn.textContent = s.unlock;
    refs.unlockBtn.disabled =
      !unlockAvailable || !this._unlock || unlockState === "busy";
    refs.unlockBtn.classList.toggle(
      "hidden",
      unlockState === "confirm" || !unlockAvailable
    );
    refs.confirmWrap.classList.toggle("hidden", unlockState !== "confirm");
    refs.confirmLabel.textContent = s.unlock_confirm.replace("{target}", this._unlockTargetLabel);
    refs.confirmYes.textContent = s.confirm;
    refs.confirmNo.textContent = s.cancel;
    if (confirming && !this._wasUnlockConfirm) refs.confirmNo.focus();
    else if (this._restoreUnlockFocus && !refs.unlockBtn.disabled && unlockAvailable) {
      refs.unlockBtn.focus();
      this._restoreUnlockFocus = false;
    }
    this._wasUnlockConfirm = confirming;

    // status line
    const status = this._statusText();
    refs.status.textContent = status.text;
    refs.status.classList.toggle("error", status.error);
  }
}

// ---------------------------------------------------------------------------
// Registration (browser only)
// ---------------------------------------------------------------------------

if (typeof window !== "undefined" && typeof customElements !== "undefined") {
  if (!customElements.get(CARD_TAG)) {
    customElements.define("abb-welcome-intercom-card", AbbWelcomeIntercomCard);
  }
  window.customCards = window.customCards || [];
  if (!window.customCards.some((card) => card.type === CARD_TAG)) {
    window.customCards.push({
      type: CARD_TAG,
      name: "ABB Welcome Intercom",
      description:
        "Doorbell camera with live audio/video, hold-to-talk and confirmed unlock.",
      preview: false,
      documentationURL: "https://github.com/rankjie/ha-abb-welcome",
      getEntitySuggestion: (hass, entityId) => {
        try {
          return entitySuggestion(hass, entityId);
        } catch (_err) {
          return null;
        }
      },
    });
  }
  // eslint-disable-next-line no-console
  console.info(
    `%c ABB-WELCOME-INTERCOM-CARD %c v${CARD_VERSION}`,
    "background:#1c4587;color:#fff;padding:2px 6px;border-radius:3px",
    ""
  );
}
