"""A failed startup read of the gateway device list is retried in the background."""

from __future__ import annotations

import asyncio
import types

import pytest

from test_second_lock import _topology


def _retry_harness(results):
    namespace = _topology()
    refreshes, scheduled, cancelled, unload = [], [], [], []

    async def refresh(_hass, _entry, *, reload_on_change):
        refreshes.append(reload_on_change)
        return results.pop(0)

    def call_later(_hass, delay, action):
        scheduled.append((delay, action))
        return lambda: cancelled.append(delay)

    namespace["_async_refresh_doors_for_entry"] = refresh
    namespace["async_call_later"] = call_later
    entry = types.SimpleNamespace(async_on_unload=unload.append)
    namespace["_schedule_topology_retry"](object(), entry)
    return refreshes, scheduled, cancelled, unload


def _fire(scheduled):
    asyncio.run(scheduled[-1][1](None))


@pytest.mark.parametrize("outcome", [True, False])
def test_retry_backs_off_until_the_gateway_answers(outcome):
    refreshes, scheduled, _cancelled, _unload = _retry_harness(
        [None, None, None, None, outcome]
    )
    for _ in range(5):
        _fire(scheduled)
    assert [delay for delay, _ in scheduled] == [60, 300, 900, 3600, 3600]
    assert refreshes == [True] * 5


def test_unloading_the_entry_cancels_a_pending_retry():
    _refreshes, scheduled, cancelled, unload = _retry_harness([None])
    _fire(scheduled)
    [stop] = unload
    stop()
    assert cancelled == [300]
