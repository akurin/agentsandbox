"""Shared fixtures.

Two things every test needs: an ``ASBX_HOME`` that is a temp directory, and no
real DNS.  The second matters more than it looks - policy checks resolve names,
and a test suite that depends on the network resolves differently on a plane.
"""

from __future__ import annotations

import ipaddress

import pytest

from agentsandbox import netpolicy
from agentsandbox.audit import redactor
from agentsandbox.broker.core import BrokerCore
from agentsandbox.capabilities import CapabilitySpec, CapabilityStore, SecretRef
from agentsandbox.keychain import StaticResolver
from agentsandbox.netpolicy import DestinationPolicy
from agentsandbox.session import Session
from helpers import RecordingExecutor  # noqa: E402

#: Names the fake resolver knows about. Anything else "does not resolve",
#: which is itself a policy outcome worth testing.
FAKE_DNS = {
    "api.github.com": ["140.82.121.6"],
    "api.example.com": ["93.184.216.34"],
    "example.com": ["93.184.216.34"],
    "other.example.net": ["93.184.216.35"],
    "evil.test": ["93.184.216.36"],
    # Deliberately hostile answers used by the rebinding tests.
    "rebind.test": ["93.184.216.34", "127.0.0.1"],
    "internal.test": ["10.1.2.3"],
    "metadata.test": ["169.254.169.254"],
}


@pytest.fixture(autouse=True)
def asbx_home(tmp_path, monkeypatch):
    home = tmp_path / "asbx-home"
    home.mkdir()
    monkeypatch.setenv("ASBX_HOME", str(home))
    monkeypatch.delenv("ASBX_SESSION", raising=False)

    # profiles.py falls back to Path.home() / ".config/asbx/profiles" when
    # ASBX_PROFILE_DIR isn't set - without this, a test that resolves a
    # profile by name without setting that env var reads whatever actually
    # exists in the real machine's home directory instead of the shipped
    # examples, which is exactly as hermetic as it sounds.
    real_home = tmp_path / "real-home"
    real_home.mkdir()
    monkeypatch.setenv("HOME", str(real_home))
    monkeypatch.delenv("ASBX_PROFILE_DIR", raising=False)

    # A built default image, because that is the state of a host where anything
    # can be created: `asbx create` refuses an image that does not exist rather
    # than deferring the failure to the first boot. Tests that care about the
    # empty case delete it.
    from agentsandbox.vm.vfkit import DEFAULT_IMAGE

    images = home / "images"
    images.mkdir(parents=True, exist_ok=True)
    (images / f"{DEFAULT_IMAGE}.raw").write_bytes(b"not a real disk")
    (images / f"{DEFAULT_IMAGE}.json").write_text(
        '{"name": "%s", "distro": "debian", "prepared": true}' % DEFAULT_IMAGE
    )
    yield home


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    def resolve(host: str):
        literal = netpolicy._as_ip(host)
        if literal is not None:
            return [literal]
        addresses = FAKE_DNS.get(host.lower())
        if not addresses:
            raise netpolicy.PolicyDenied("dns_resolution_failed", f"cannot resolve {host}")
        return [ipaddress.ip_address(a) for a in addresses]

    monkeypatch.setattr(netpolicy, "resolve_host", resolve)
    return FAKE_DNS


@pytest.fixture(autouse=True)
def clean_redactor():
    redactor.forget_all()
    yield
    redactor.forget_all()


@pytest.fixture
def policy() -> DestinationPolicy:
    return DestinationPolicy(allow_hosts=["api.github.com", "*.example.com", "example.com"])


@pytest.fixture
def session(policy) -> Session:
    session = Session(session_id="test-session", policy=policy)
    session.save()
    return session


@pytest.fixture
def store(session) -> CapabilityStore:
    return CapabilityStore(session.paths.capabilities, session.session_id)


@pytest.fixture
def executor() -> RecordingExecutor:
    return RecordingExecutor()


@pytest.fixture
def resolver() -> StaticResolver:
    return StaticResolver({"github-token": "ghp_realsecretvalue0123456789"})


@pytest.fixture
def broker(session, store, executor, resolver) -> BrokerCore:
    return BrokerCore(
        session.session_id,
        store,
        session.policy,
        resolver,
        executor=executor,
    )


@pytest.fixture
def github_capability(store):
    """A read-only capability for one repo on api.github.com."""
    spec = CapabilitySpec(
        label="github",
        hosts=["api.github.com"],
        resources=["repo:acme/api"],
        methods=["GET", "HEAD"],
        path_globs=["/repos/*"],
        secret=SecretRef(backend="static", service="github-token"),
    )
    return store.issue(spec)
