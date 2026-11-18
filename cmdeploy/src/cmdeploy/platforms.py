"""Explicit platform/package intent; an unknown distribution never means DNF."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Platform:
    name: str
    backend: str
    web_user: str
    candidate: bool = False


DEBIAN = Platform("debian", "apt", "www-data")
ALMA10 = Platform("alma10", "dnf", "nginx", candidate=True)


def select_platform(distribution):
    if not isinstance(distribution, dict):
        raise ValueError("missing distribution facts")
    name = str(distribution.get("name", "")).lower().replace(" ", "")
    major = str(distribution.get("major", ""))
    if name in {"debian", "ubuntu"}:
        return DEBIAN
    if name in {"almalinux", "almalinuxos"} and major == "10":
        return ALMA10
    raise ValueError("unsupported distribution; no package-manager fallback")


# Carry the existing EL10 fork's package mapping intent explicitly. None marks
# an unresolved platform qualification; it must never fall back to stock DNF.
PACKAGE_PLANS = {
    "debian": {
        "curl": ("curl",),
        "rsync": ("rsync",),
        "python-venv": ("python3-virtualenv",),
        "python-build": ("gcc", "python3-dev"),
        "postfix": ("postfix",),
        "opendkim": ("opendkim", "opendkim-tools"),
        "nginx": ("nginx", "libnginx-mod-stream"),
        "acmetool": ("acmetool",),
    },
    "alma10": {
        "curl": ("curl",),
        "rsync": ("rsync",),
        "python-venv": None,
        "python-build": ("gcc", "python3-devel"),
        "postfix": ("postfix", "postfix-pcre"),
        "opendkim": None,
        "nginx": None,
        "acmetool": None,
    },
}


def package_plan(platform, component):
    packages = PACKAGE_PLANS[platform.name].get(component)
    if not packages:
        raise ValueError(f"unqualified {platform.name} package plan: {component}")
    return list(packages)
