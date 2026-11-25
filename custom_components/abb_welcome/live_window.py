"""Websocket subscription that holds one station open for a live view.

The subscription is the lease: Home Assistant drops it when the browser
unsubscribes, closes or disconnects, so a vanished client cannot keep the
station armed and no renewal timer is needed.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import voluptuous as vol
from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect

from .const import DOMAIN
from .streaming_state import (
    acquire_live,
    is_stream_allowed,
    release_live,
    signal_armed_changed,
)

WS_TYPE_LIVE = f"{DOMAIN}/live"


@websocket_api.websocket_command(
    {
        vol.Required("type"): WS_TYPE_LIVE,
        vol.Required("entry_id"): str,
        vol.Required("station_id"): str,
    }
)
@callback
def ws_live(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Arm one station while subscribed and report when its window ends."""
    entry_id = msg["entry_id"]
    station_id = msg["station_id"].strip()
    if not station_id or entry_id not in hass.data.get(DOMAIN, {}):
        connection.send_error(
            msg["id"], websocket_api.ERR_NOT_FOUND, "Unknown ABB Welcome station"
        )
        return
    owner = uuid4().hex
    try:
        acquire_live(hass, entry_id, station_id, owner)
    except ValueError as err:
        connection.send_error(msg["id"], "station_busy", str(err))
        return

    ended = False

    @callback
    def _armed_changed() -> None:
        nonlocal ended
        if ended or is_stream_allowed(hass, entry_id, station_id):
            return
        ended = True
        connection.send_message(websocket_api.event_message(msg["id"], {"ended": True}))

    unsub_armed = async_dispatcher_connect(
        hass, signal_armed_changed(entry_id), _armed_changed
    )

    @callback
    def _unsubscribe() -> None:
        unsub_armed()
        release_live(hass, entry_id, owner)

    connection.subscriptions[msg["id"]] = _unsubscribe
    connection.send_result(msg["id"])
