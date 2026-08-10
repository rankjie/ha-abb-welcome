"""Constants for the ABB Welcome integration."""

DOMAIN = "abb_welcome"

CONF_ABB_USERNAME = "abb_username"
CONF_ABB_PASSWORD = "abb_password"
CONF_GATEWAY_IP = "gateway_ip"
CONF_GATEWAY_UUID_OVERRIDE = "gateway_uuid_override"

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

# Publish the door station's audio on the local RTSP stream.  Only relevant
# for WiFi panels, whose audio payload is AES-encrypted; turn it off if a
# particular panel model sends a codec go2rtc refuses to negotiate.
CONF_PANEL_AUDIO = "panel_audio"
DEFAULT_PANEL_AUDIO = True

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

# Device type: distinguish between the IP gateway (with web admin) and the
# WiFi panel (no web admin, pairing approved on the panel touchscreen).
CONF_DEVICE_TYPE = "device_type"
DEVICE_TYPE_IP_GATEWAY = "ip_gateway"
DEVICE_TYPE_WIFI_PANEL = "wifi_panel"
DEVICE_TYPES = (
    DEVICE_TYPE_IP_GATEWAY,
    DEVICE_TYPE_WIFI_PANEL,
)
DEFAULT_DEVICE_TYPE = DEVICE_TYPE_IP_GATEWAY
