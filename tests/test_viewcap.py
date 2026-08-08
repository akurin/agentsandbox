"""ViewCap: bounding mitmweb's in-memory flow list.

Exercised against mitmproxy's own real `View` addon and `taddons.context`,
not a hand-rolled fake - a fake `ctx.master.addons` would happily expose
whatever method the test author guessed at (``has_addon``, say) rather than
the real installed `AddonManager`'s actual surface (``.get()`` only). That
gap is exactly how the addon shipped calling a method that does not exist:
every real run threw `AttributeError` on every response and error event, and
the flow-list cap it exists for never once fired.
"""

from __future__ import annotations

from mitmproxy.addons import view
from mitmproxy.test import taddons, tflow

from agentsandbox.proxy.viewcap import ViewCap


def test_trim_does_not_crash_against_the_real_addon_manager():
    """Regression test for the `has_addon` AttributeError: calling `_trim`
    against a real `AddonManager` (which has no such method) must not raise,
    whether or not a `view` addon happens to be registered."""
    cap = ViewCap()
    with taddons.context(cap):
        cap._trim()  # no view addon registered - must be a no-op, not a crash

    with taddons.context(cap, view.View()):
        cap._trim()  # a view addon registered - also must not crash


def test_the_view_is_trimmed_once_it_grows_past_the_cap():
    """viewcap.py only trims once the excess reaches a full `TRIM_BATCH`
    (200), by design - removal is O(n), so it batches rather than trimming
    on every single flow. 250 flows over a cap of 10 clears that bar."""
    cap = ViewCap(max_flows=10)
    real_view = view.View()
    with taddons.context(cap, real_view) as tctx:
        for _ in range(260):
            real_view.add([tflow.tflow()])
        assert len(real_view) == 260

        cap._trim()

        assert 0 < len(real_view) < 260
        tctx.master.shutdown()


def test_a_view_under_the_cap_is_left_alone():
    cap = ViewCap(max_flows=10)
    real_view = view.View()
    with taddons.context(cap, real_view) as tctx:
        for _ in range(5):
            real_view.add([tflow.tflow()])

        cap._trim()

        assert len(real_view) == 5
        tctx.master.shutdown()
