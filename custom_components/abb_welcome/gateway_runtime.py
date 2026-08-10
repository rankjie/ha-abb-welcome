"""Runtime contract shared by gateway profiles and entity platforms."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .gateway_profile import GatewayProfile


class UnlockAdapter(Protocol):
    """Strategy used to operate one door without exposing model branches."""

    async def async_unlock(
        self,
        hass: Any,
        runtime: GatewayRuntime,
        door: dict[str, Any],
    ) -> bool:
        """Operate ``door`` and return a confirmed result."""


class MRangeUnlockAdapter:
    """Run the existing synchronous MRANGE unlock client off the event loop."""

    async def async_unlock(
        self,
        hass: Any,
        runtime: GatewayRuntime,
        door: dict[str, Any],
    ) -> bool:
        if runtime.sip_client is None:
            return False
        return bool(
            await hass.async_add_executor_job(runtime.sip_client.unlock_door, door)
        )


@dataclass(slots=True)
class GatewayRuntime:
    """Entry-scoped components exposed through one stable contract."""

    profile: GatewayProfile
    coordinator: Any
    unlock_adapter: UnlockAdapter
    sip_client: Any | None = None
    sip_listener: Any | None = None
    intercom_dialer: Any | None = None

    async def async_unlock(self, hass: Any, door: dict[str, Any]) -> bool:
        """Unlock through the profile-selected strategy."""
        return await self.unlock_adapter.async_unlock(hass, self, door)
