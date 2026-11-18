from types import SimpleNamespace

import pytest

from cmdeploy import basedeploy, deployers
from cmdeploy.dovecot.deployer import DovecotDeployer
from cmdeploy.platforms import ALMA10


@pytest.fixture
def alma(monkeypatch):
    monkeypatch.setattr(basedeploy, "deployment_platform", lambda: ALMA10)
    monkeypatch.delenv("CMDEPLOY_RUNTIME_LOCK", raising=False)
    monkeypatch.delenv("CMDEPLOY_RUNTIME_PROFILE", raising=False)
    monkeypatch.delenv("CMDEPLOY_ADDON_MANIFEST", raising=False)


def test_global_entry_refuses_before_configuration_or_operations(
    alma, monkeypatch, tmp_path
):
    monkeypatch.setattr(
        deployers,
        "read_config",
        lambda *args: pytest.fail("config/deployment side effect reached"),
    )
    with pytest.raises(RuntimeError, match="candidate"):
        deployers.deploy_chatmail(tmp_path / "unused.ini", False, False)


@pytest.mark.parametrize("stage", ["install", "configure", "activate"])
def test_direct_dovecot_stage_refuses_before_effects(alma, monkeypatch, stage):
    deployer = DovecotDeployer(SimpleNamespace(), False)
    monkeypatch.setattr(
        deployer,
        "put_file",
        lambda *args, **kwargs: pytest.fail("remote write reached"),
    )
    monkeypatch.setattr(
        deployer,
        "put_template",
        lambda *args, **kwargs: pytest.fail("remote template reached"),
    )
    monkeypatch.setattr(
        deployer,
        "ensure_service",
        lambda *args, **kwargs: pytest.fail("service operation reached"),
    )
    with pytest.raises(RuntimeError, match="candidate"):
        getattr(deployer, stage)()


def test_generic_deployment_refuses_before_user_creation(alma, monkeypatch):
    monkeypatch.setattr(
        basedeploy.server, "user", lambda **kwargs: pytest.fail("user creation reached")
    )
    with pytest.raises(RuntimeError, match="candidate"):
        basedeploy.Deployment().perform_stages(
            [SimpleNamespace(required_users=[("vmail", None, None)])]
        )


def test_policy_rc_d_is_not_claimed_on_alma(alma, monkeypatch):
    monkeypatch.setattr(
        basedeploy.files, "put", lambda **kwargs: pytest.fail("policy file reached")
    )
    with pytest.raises(RuntimeError, match="Debian-specific"):
        with basedeploy.blocked_service_startup():
            pytest.fail("context must not activate")
