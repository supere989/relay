"""Pure rendering for the separately qualified private Dovecot 2.4.5 runtime."""

import re
from dataclasses import dataclass, fields
from pathlib import Path

from jinja2 import Environment, StrictUndefined


@dataclass(frozen=True)
class Runtime24Paths:
    version: str = "2.4.5"
    prefix: str = "/opt/chatmail-dovecot/2.4.5"
    config_dir: str = "/etc/chatmail-dovecot/2.4.5"
    run_dir: str = "/run/chatmail-dovecot-2.4.5"
    state_dir: str = "/var/lib/chatmail-dovecot-2.4.5"
    standard_users: str = "/etc/dovecot/standard-users"
    metadata_socket: str = "/run/chatmail-metadata/metadata.socket"
    lastlogin_socket: str = "/run/chatmail-lastlogin/lastlogin.socket"
    auth_socket: str = "/var/spool/postfix/private/auth"
    lmtp_socket: str = "/var/spool/postfix/private/dovecot-lmtp"
    ssl_cert: str = "/etc/letsencrypt/live/active-iq.com/fullchain.pem"
    ssl_key: str = "/etc/letsencrypt/live/active-iq.com/privkey.pem"
    mail_user: str = "vmail"
    mail_group: str = "vmail"
    postfix_user: str = "postfix"
    postfix_group: str = "postfix"
    listen_address: str = "* ::"
    imaps_port: int = 993


def render(config, runtime=None):
    runtime = runtime or Runtime24Paths()
    if (
        not re.fullmatch(r"2\.4\.(?:[5-9]|[1-9][0-9]+)", runtime.version)
        or runtime.prefix != f"/opt/chatmail-dovecot/{runtime.version}"
    ):
        raise ValueError(
            "runtime must use its exact validated private 2.4 point-release prefix"
        )
    for field in fields(runtime):
        value = getattr(runtime, field.name)
        if field.name == "version":
            continue
        if field.name == "imaps_port":
            if not isinstance(value, int) or not 1 <= value <= 65535:
                raise ValueError("invalid private IMAPS listener")
        elif field.name == "listen_address":
            if value not in ("* ::", "127.0.0.1"):
                raise ValueError("unqualified runtime listener address")
        elif not isinstance(value, str) or not re.fullmatch(
            r"[A-Za-z0-9_./@-]+", value
        ):
            raise ValueError(f"invalid runtime configuration field: {field.name}")
        elif (
            field.name
            not in ("mail_user", "mail_group", "postfix_user", "postfix_group")
            and not Path(value).is_absolute()
        ):
            raise ValueError("runtime filesystem paths must be absolute")
    if not re.fullmatch(r"[a-zA-Z0-9.-]+", config.mail_domain):
        raise ValueError("invalid relay mail domain")
    if not re.fullmatch(r"/[A-Za-z0-9_./@-]+", str(config.mailboxes_dir)):
        raise ValueError("invalid relay mail root")
    if not 1 <= int(config.doveauth_http_port) <= 65535:
        raise ValueError("invalid local doveauth port")
    directory = Path(__file__).with_name("dovecot")
    environment = Environment(
        undefined=StrictUndefined, autoescape=False, keep_trailing_newline=True
    )
    return {
        name: environment.from_string((directory / source).read_text()).render(
            config=config, runtime=runtime
        )
        for name, source in (
            ("dovecot.conf", "dovecot24.conf.j2"),
            ("auth.lua", "auth24.lua.j2"),
        )
    }
