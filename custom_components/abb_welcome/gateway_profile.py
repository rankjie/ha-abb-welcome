"""Gateway profiles and capability lookup.

Profiles are the single composition root for model-specific behavior.  Config
entries persist only the stable ``kind`` string; Python objects and adapter
instances stay in memory.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType

GATEWAY_KIND_MRANGE = "mrange_ip_gateway"
GATEWAY_KIND_M22401 = "m22401_wifi_station"


class GatewayCapability(str, Enum):
    """Behavior that a gateway profile exposes to the integration."""

    ADMIN_CGI = "admin_cgi"
    PORTAL_PAIRING = "portal_pairing"
    CLOUD_EVENTS = "cloud_events"
    REALTIME_RING = "realtime_ring"
    VIDEO_STREAM = "video_stream"
    TALKBACK = "talkback"
    UNLOCK = "unlock"
    PICKUP_CONTROL = "pickup_control"
    DOOR_REFRESH = "door_refresh"
    ONVIF_BACKCHANNEL = "onvif_backchannel"


@dataclass(frozen=True, slots=True)
class GatewayProfile:
    """Immutable description of one supported gateway family."""

    kind: str
    name: str
    manufacturer: str
    model: str
    capabilities: frozenset[GatewayCapability]
    platforms: tuple[str, ...]

    def supports(self, capability: GatewayCapability) -> bool:
        """Return whether this profile exposes ``capability``."""
        return capability in self.capabilities


_MRANGE_PROFILE = GatewayProfile(
    kind=GATEWAY_KIND_MRANGE,
    name="ABB Welcome Gateway",
    manufacturer="ABB / Busch-Jaeger",
    model="IP Gateway (MRANGE)",
    capabilities=frozenset(
        {
            GatewayCapability.ADMIN_CGI,
            GatewayCapability.PORTAL_PAIRING,
            GatewayCapability.CLOUD_EVENTS,
            GatewayCapability.REALTIME_RING,
            GatewayCapability.VIDEO_STREAM,
            GatewayCapability.TALKBACK,
            GatewayCapability.UNLOCK,
            GatewayCapability.PICKUP_CONTROL,
            GatewayCapability.DOOR_REFRESH,
        }
    ),
    platforms=(
        "binary_sensor",
        "button",
        "camera",
        "image",
        "event",
        "sensor",
        "switch",
    ),
)

GATEWAY_PROFILES: Mapping[str, GatewayProfile] = MappingProxyType(
    {_MRANGE_PROFILE.kind: _MRANGE_PROFILE}
)


def get_gateway_profile(kind: str) -> GatewayProfile:
    """Resolve a gateway profile or fail closed for an unknown kind."""
    try:
        return GATEWAY_PROFILES[kind]
    except (KeyError, TypeError) as err:
        raise ValueError(f"Unsupported ABB Welcome gateway kind: {kind!r}") from err


def resolve_gateway_kind(data: Mapping[str, object]) -> str:
    """Resolve the persisted kind, defaulting only truly legacy entries.

    Version-1 rankjie entries have no discriminator and are MRANGE entries.
    An explicit non-empty value is never silently reinterpreted.
    """
    raw_kind = data.get("gateway_kind")
    if raw_kind is None or raw_kind == "":
        return GATEWAY_KIND_MRANGE
    kind = str(raw_kind)
    get_gateway_profile(kind)
    return kind
