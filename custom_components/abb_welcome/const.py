"""Constants for the ABB Welcome integration."""

from .gateway_profile import GATEWAY_KIND_M22401, GATEWAY_KIND_MRANGE

DOMAIN = "abb_welcome"

CONF_ABB_USERNAME = "abb_username"
CONF_ABB_PASSWORD = "abb_password"
CONF_GATEWAY_IP = "gateway_ip"
CONF_GATEWAY_UUID_OVERRIDE = "gateway_uuid_override"
CONF_GATEWAY_KIND = "gateway_kind"

GATEWAY_KINDS = (GATEWAY_KIND_MRANGE, GATEWAY_KIND_M22401)

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

# Per-integration option: which unlock strategy to use.
#   hybrid   — fast plain MESSAGE for the first outdoor station, INVITE-then-MESSAGE for the rest.
#              Tested working on the reference gateway; lowest latency on the main door.
#   fast     — always use the plain MESSAGE path. Lowest latency overall, but
#              not all gateways accept a MESSAGE without an active call session.
#   standard — always set up an INVITE first (mirrors the official mobile app).
#              Most compatible; ~1-2s extra per unlock.
CONF_UNLOCK_STRATEGY = "unlock_strategy"
UNLOCK_STRATEGY_HYBRID = "hybrid"
UNLOCK_STRATEGY_FAST = "fast"
UNLOCK_STRATEGY_STANDARD = "standard"
UNLOCK_STRATEGIES = (
    UNLOCK_STRATEGY_HYBRID,
    UNLOCK_STRATEGY_FAST,
    UNLOCK_STRATEGY_STANDARD,
)
DEFAULT_UNLOCK_STRATEGY = UNLOCK_STRATEGY_HYBRID
