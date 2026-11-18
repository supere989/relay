from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from cmdeploy.runtime24 import Runtime24Paths, render


def config():
    return SimpleNamespace(
        mail_domain="synthetic.test",
        mailboxes_dir=Path("/mail/synthetic.test"),
        doveauth_http_port=10084,
    )


def test_runtime_requires_private_prefix_and_safe_listener():
    with pytest.raises(ValueError, match="private"):
        render(config(), replace(Runtime24Paths(), prefix="/usr"))
    with pytest.raises(ValueError, match="listener"):
        render(
            config(), replace(Runtime24Paths(), listen_address="unqualified.example")
        )


def test_runtime_rejects_config_injection_before_render():
    unsafe = config()
    unsafe.mail_domain = "synthetic.test\nssl = no"
    with pytest.raises(ValueError):
        render(unsafe)


def test_storage_security_contract_cannot_be_downgraded_by_old_config_attribute():
    original = config()
    original.dovecot_storage_version = "2.4.0"
    result = render(original)
    storage = [
        line.split("=", 1)[1].strip()
        for line in result["dovecot.conf"].splitlines()
        if line.startswith("dovecot_storage_version =")
    ]
    assert storage == ["2.4.5"]
    assert "quota_warning" not in result["dovecot.conf"]
    assert "mail_fsync" not in result["dovecot.conf"]
    assert 'request_timeout = "5s"' in result["auth.lua"]
    assert 'request_absolute_timeout = "5s"' in result["auth.lua"]
