"""Bound mitmweb's flow list.

mitmweb keeps every flow it has seen - headers and bodies - in memory, so the
UI can show them. That is the point of it, and it has no cap: left attached to
a session that runs for weeks, it grows until the host runs out of memory, and
it holds body content that the rest of this design deliberately never stores
(``save_stream_file=`` and ``store_streamed_bodies=false`` are set for exactly
that reason).

So the view is trimmed to the most recent flows. This addon is loaded only in
web mode; mitmdump keeps no flow list and needs none of it.
"""

from __future__ import annotations

import logging

from mitmproxy import ctx, http

#: Flows to keep. Enough to debug with, small enough that bodies cannot
#: accumulate unboundedly over a long session.
MAX_FLOWS = 2000

#: Trim in batches rather than one per flow: removing from the view is O(n) in
#: mitmproxy, so doing it on every request would be its own overload.
TRIM_BATCH = 200

logger = logging.getLogger(__name__)


class ViewCap:
    def __init__(self, max_flows: int = MAX_FLOWS) -> None:
        self.max_flows = max_flows

    def response(self, flow: http.HTTPFlow) -> None:
        self._trim()

    def error(self, flow: http.HTTPFlow) -> None:
        self._trim()

    def _trim(self) -> None:
        view = getattr(ctx.master, "addons", None)
        if view is None or not ctx.master.addons.has_addon("view"):
            return  # mitmdump: no flow list to trim
        flows = ctx.master.addons.get("view")
        excess = len(flows) - self.max_flows
        if excess < TRIM_BATCH:
            return
        oldest = [flows[i] for i in range(excess)]
        try:
            ctx.master.commands.call("view.flows.remove", oldest)
        except Exception as exc:  # noqa: BLE001 - never take the proxy down
            logger.warning("agentsandbox: could not trim the mitmweb view: %s", exc)


addons = [ViewCap()]
