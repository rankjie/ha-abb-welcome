"""Constants and gateway capabilities for the ABB Welcome integration."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass

DOMAIN = "abb_welcome"

CONF_ABB_USERNAME = "abb_username"
CONF_ABB_PASSWORD = "abb_password"
CONF_GATEWAY_IP = "gateway_ip"
CONF_GATEWAY_UUID_OVERRIDE = "gateway_uuid_override"
CONF_GATEWAY_PASSWORD = "gateway_password"  # config-flow field name
CONF_GATEWAY_PROFILE = "gateway_profile"

GATEWAY_PROFILE_WEB_ADMIN = "web_admin"
GATEWAY_PROFILE_APP_MANAGED = "app_managed"
GATEWAY_PROFILES = (
    GATEWAY_PROFILE_WEB_ADMIN,
    GATEWAY_PROFILE_APP_MANAGED,
)

GEO_URL = "https://geo.mybuildings.abb.com"
DEFAULT_PORTAL_URL = "https://api.eu.mybuildings.abb.com"

CLIENT_TYPE = "com.abb.ispf.client.globalip.app.abb.android"
GATEWAY_CLIENT_TYPE = "com.abb.ispf.client.welcome.gateway"

EVENT_TYPE_DISCOVERY = "com.abb.ispf.event.discovery"
EVENT_TYPE_CONNECT = "com.abb.ispf.event.welcome.connect"
EVENT_TYPE_ACL_UPDATE = "com.abb.ispf.event.welcome.acl-update"

SIP_PORT = 5060
SIP_PORT_TLS = 5061

DATA_PORTAL_STATE = "portal_state"

EVENT_DISCOVERY_CHANGED = f"{DOMAIN}_discovery_changed"

GO2RTC_RTSP_HOST = "127.0.0.1"
GO2RTC_RTSP_PORT = 18554

CONF_LAN_RTSP_HOST = "lan_rtsp_host"
CONF_LAN_RTSP_PORT = "lan_rtsp_port"
DEFAULT_LAN_RTSP_BIND_HOST = "0.0.0.0"
DEFAULT_LAN_RTSP_PORT = 18556
DEFAULT_LAN_RTSP_PORT_PICK_ATTEMPTS = 100

CONF_ALLOW_PICKUP = "allow_pickup"
DEFAULT_ALLOW_PICKUP = True

CONF_TALKBACK_OUTPUT_GAIN_DB = "talkback_output_gain_db"
MIN_TALKBACK_OUTPUT_GAIN_DB = 0.0
MAX_TALKBACK_OUTPUT_GAIN_DB = 3.0

# Native ring-clip recorder: captures the ring-moment video directly from
# RTP (see ring_clip.py) instead of relying on HA's stream/go2rtc pipeline,
# which is too slow to produce a first frame before a short ring call ends.
CONF_RECORD_RING_CLIPS = "record_ring_clips"
DEFAULT_RECORD_RING_CLIPS = False

CONF_RING_CLIP_SECONDS = "ring_clip_seconds"
DEFAULT_RING_CLIP_SECONDS = 10
MIN_RING_CLIP_SECONDS = 2
MAX_RING_CLIP_SECONDS = 60

CONF_RING_CLIP_DIR = "ring_clip_dir"
DEFAULT_RING_CLIP_DIR = "www/abb_doorbell"

CONF_RING_CLIP_CONTINUE_AFTER_HANGUP = "ring_clip_continue_after_hangup"
DEFAULT_RING_CLIP_CONTINUE_AFTER_HANGUP = False

# Per-integration option: which unlock strategy to use.
#   hybrid   — fast plain MESSAGE for an explicit physical-default station,
#              INVITE-then-MESSAGE for the rest. Legacy web-admin entries use
#              their historical first-stored-door fallback.
#   fast     — always use the plain MESSAGE path. Lowest latency overall, but
#              not all gateways target it; app-managed multi-door use is blocked.
#   standard — always set up an INVITE first (mirrors the official mobile app).
#              Most compatible; ~1-2s extra per unlock.
CONF_UNLOCK_STRATEGY = "unlock_strategy"
CONF_DEFAULT_UNLOCK_STATION_ID = "default_unlock_station_id"
UNLOCK_STRATEGY_HYBRID = "hybrid"
UNLOCK_STRATEGY_FAST = "fast"
UNLOCK_STRATEGY_STANDARD = "standard"
UNLOCK_STRATEGIES = (
    UNLOCK_STRATEGY_HYBRID,
    UNLOCK_STRATEGY_FAST,
    UNLOCK_STRATEGY_STANDARD,
)
DEFAULT_UNLOCK_STRATEGY = UNLOCK_STRATEGY_HYBRID
APP_MANAGED_TOPOLOGY_REFRESH_ERROR = (
    "Door topology refresh is not supported for app-managed M2240x/ASI22 "
    "devices; re-pair the integration after topology changes"
)
TOPOLOGY_REFRESH_ACTION_REFRESH = "refresh"
TOPOLOGY_REFRESH_ACTION_SKIP = "skip"
TOPOLOGY_REFRESH_ACTION_ERROR = "error"


@dataclass(frozen=True, slots=True)
class GatewayCapabilities:
    """Behavior that differs between ABB Welcome gateway families."""

    probe_port: int
    approval_method: str
    admin_available: bool
    topology_refresh: bool
    model: str
    default_unlock_strategy: str
    default_talkback_output_gain_db: float


GATEWAY_CAPABILITIES = {
    GATEWAY_PROFILE_WEB_ADMIN: GatewayCapabilities(
        probe_port=443,
        approval_method="cgi",
        admin_available=True,
        topology_refresh=True,
        model="IP Gateway (MRANGE)",
        default_unlock_strategy=UNLOCK_STRATEGY_HYBRID,
        default_talkback_output_gain_db=0.0,
    ),
    GATEWAY_PROFILE_APP_MANAGED: GatewayCapabilities(
        probe_port=SIP_PORT_TLS,
        approval_method="automatic_acl",
        admin_available=False,
        topology_refresh=False,
        model="Wi-Fi Indoor Station (M2240x / ASI22)",
        default_unlock_strategy=UNLOCK_STRATEGY_STANDARD,
        default_talkback_output_gain_db=3.0,
    ),
}


def gateway_profile(data: Mapping[str, object]) -> str:
    """Return a supported persisted profile, defaulting only legacy entries."""
    value = data.get(CONF_GATEWAY_PROFILE)
    if value is None or value == "":
        return GATEWAY_PROFILE_WEB_ADMIN
    if not isinstance(value, str) or value not in GATEWAY_CAPABILITIES:
        raise ValueError(f"Unsupported ABB Welcome gateway profile: {value!r}")
    return value


def gateway_capabilities(data: Mapping[str, object]) -> GatewayCapabilities:
    """Return capabilities for a config-entry-like data mapping."""
    return GATEWAY_CAPABILITIES[gateway_profile(data)]


def talkback_output_gain_db(
    data: Mapping[str, object], options: Mapping[str, object]
) -> float:
    """Return the persisted talkback gain or the profile-specific default."""
    default = gateway_capabilities(data).default_talkback_output_gain_db
    try:
        gain_db = float(options.get(CONF_TALKBACK_OUTPUT_GAIN_DB, default))
    except (TypeError, ValueError):
        return default
    if not math.isfinite(gain_db):
        return default
    return max(
        MIN_TALKBACK_OUTPUT_GAIN_DB,
        min(MAX_TALKBACK_OUTPUT_GAIN_DB, gain_db),
    )


def ring_clip_seconds(options: Mapping[str, object]) -> int:
    """Return the configured ring-clip duration, clamped to a safe range."""
    try:
        seconds = int(options.get(CONF_RING_CLIP_SECONDS, DEFAULT_RING_CLIP_SECONDS))
    except (TypeError, ValueError):
        return DEFAULT_RING_CLIP_SECONDS
    return max(MIN_RING_CLIP_SECONDS, min(MAX_RING_CLIP_SECONDS, seconds))


def unlockable_station_ids(doors: object) -> tuple[str, ...]:
    """Return stable station IDs for doors that may expose unlock controls."""
    if not isinstance(doors, list):
        return ()
    station_ids: list[str] = []
    for door in doors:
        if not isinstance(door, Mapping) or door.get("can_unlock") is False:
            continue
        station_type = str(door.get("type", "")).strip()
        if station_type and station_type != "1":
            continue
        station_id = str(door.get("station_id", "")).strip()
        if station_id and station_id not in station_ids:
            station_ids.append(station_id)
    return tuple(station_ids)


def normalized_unlock_routing(
    data: Mapping[str, object], options: Mapping[str, object]
) -> tuple[str, str]:
    """Return a safe strategy and explicit hybrid-fast station ID."""
    capabilities = gateway_capabilities(data)
    strategy = str(
        options.get(CONF_UNLOCK_STRATEGY, capabilities.default_unlock_strategy)
    )
    if strategy not in UNLOCK_STRATEGIES:
        strategy = capabilities.default_unlock_strategy

    if gateway_profile(data) != GATEWAY_PROFILE_APP_MANAGED:
        # Preserve legacy MRANGE behavior: hybrid uses the first stored door.
        return strategy, ""

    station_ids = unlockable_station_ids(data.get("doors"))
    selected = str(options.get(CONF_DEFAULT_UNLOCK_STATION_ID, "")).strip()
    selected_is_valid = bool(selected and selected in station_ids)

    if strategy == UNLOCK_STRATEGY_FAST and len(station_ids) > 1:
        return UNLOCK_STRATEGY_STANDARD, ""
    if strategy == UNLOCK_STRATEGY_HYBRID and not selected_is_valid:
        return UNLOCK_STRATEGY_STANDARD, ""
    return strategy, selected if selected_is_valid else ""


def topology_refresh_error(data: Mapping[str, object]) -> str | None:
    """Return the user-facing refresh limitation, or None when supported."""
    if gateway_capabilities(data).topology_refresh:
        return None
    return APP_MANAGED_TOPOLOGY_REFRESH_ERROR


def topology_refresh_action(
    data: Mapping[str, object], *, explicitly_targeted: bool = False
) -> str:
    """Return whether refresh should run, skip, or raise for an entry."""
    if topology_refresh_error(data) is None:
        return TOPOLOGY_REFRESH_ACTION_REFRESH
    if explicitly_targeted:
        return TOPOLOGY_REFRESH_ACTION_ERROR
    return TOPOLOGY_REFRESH_ACTION_SKIP
