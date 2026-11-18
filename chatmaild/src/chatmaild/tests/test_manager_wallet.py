"""Optional bot signing availability never gates the ordinary owner portal."""

import pytest

from chatmaild.backup.manager import BrokerSigner
from chatmaild.backup.model import ArchiveError
from chatmaild.tests.test_manager_backend import setup as manager_setup


def test_locked_bot_wallet_preserves_portal_sign_in_and_fails_actual_key_use(tmp_path):
    context = manager_setup.__wrapped__(tmp_path)
    calls = []

    class Locked:
        def call(self, operation, **_fields):
            calls.append(operation)
            raise ArchiveError("broker_unavailable")

    signer = BrokerSigner(Locked(), "opaque-signing-reference")
    context.manager.signer = signer
    context.scenario.portal.manager = context.manager
    _cookie, anonymous = context.scenario.portal.session()
    assert b"Sign in" in context.scenario.portal.page(anonymous)
    assert context.scenario.portal.begin(anonymous).startswith("https://")
    assert calls == []
    with pytest.raises(ArchiveError, match="broker_unavailable"):
        _public = signer.public
    with pytest.raises(ArchiveError, match="broker_unavailable"):
        signer.sign(b"fixed nonsecret test message")
    assert calls == ["manager-public", "manager-sign"]
