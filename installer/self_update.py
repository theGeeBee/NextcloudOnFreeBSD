"""Stage an official installer release and atomically select its retained path."""

import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tomllib
import uuid

from .discovery import fetch_releases
from .paths import PROJECT_ROOT
from .host import read_private
from .state import atomic_write


PROJECT = "theGeeBee/NextcloudOnFreeBSD"
LATEST = f"https://api.github.com/repos/{PROJECT}/releases/latest"
CURRENT = "current-installer"
SEMVER = r"(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){2}"


def available_release():
    release = json.loads(fetch_releases(LATEST))
    if (not isinstance(release, dict) or release.get("draft") is not False
            or release.get("prerelease") is not False or release.get("immutable") is not True
            or not isinstance(release.get("tag_name"), str)
            or not re.fullmatch("v" + SEMVER, release["tag_name"])
            or not isinstance(release.get("assets"), list)):
        raise ValueError("Official stable release metadata is unavailable or unverified")
    tag = release["tag_name"]
    asset_name = f"NextcloudOnFreeBSD-{tag[1:]}.tar.gz"
    url = f"https://github.com/{PROJECT}/releases/download/{tag}/{asset_name}"
    matches = [asset for asset in release["assets"] if isinstance(asset, dict) and asset.get("name") == asset_name]
    if (len(matches) != 1 or matches[0].get("browser_download_url") != url
            or matches[0].get("state") != "uploaded"
            or not re.fullmatch(r"sha256:[a-f0-9]{64}", str(matches[0].get("digest")))):
        raise ValueError("Official release has no unique verified SHA256 archive")
    return tag[1:], url, matches[0]["digest"][7:]


def _version(payload):
    project = tomllib.loads((payload / "pyproject.toml").read_text())["project"]
    version = project.get("version", "")
    if (project.get("name") != "freebsd-cloud-installer" or not isinstance(version, str)
            or not re.fullmatch(SEMVER, version)):
        raise ValueError("Installer payload does not declare a stable project version")
    return version


def _retained_payload(root, payload):
    from .maintenance_staging import _ancestors, _directory, _file

    if (not payload.is_absolute() or ".." in payload.parts or payload.name != "cloud-installer"
            or payload.parent.parent != root / "downloads"
            or not re.fullmatch(r"[a-f0-9]{12}-[a-zA-Z0-9_]+", payload.parent.name)):
        raise ValueError("Installer selection does not name a retained release")
    _ancestors(payload)
    for directory in (root, payload.parent.parent, payload.parent, payload):
        _directory(directory, private=True)
    _file((payload / "install.sh").lstat(), 1024 * 1024)
    return payload


def _read_selection(root, link):
    if not os.path.lexists(link):
        return None
    if not link.is_symlink() or link.lstat().st_uid != os.geteuid():
        raise ValueError("Installer selection is not an owned symlink")
    return _retained_payload(root, Path(os.readlink(link)))


def _stage(url, digest):
    result = subprocess.run(
        ["/bin/sh", str(PROJECT_ROOT / "install.sh"), "--archive", url, "--sha256", digest, "_stage-self-update"],
        check=True, text=True, stdout=subprocess.PIPE,
    )
    return Path(result.stdout.rstrip("\n"))


def _sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _activate(link, target):
    pending = link.with_name(".pending-installer-" + uuid.uuid4().hex)
    pending.symlink_to(target)
    try:
        os.replace(pending, link)
        _sync(link.parent)
    finally:
        if pending.is_symlink():
            pending.unlink()


def _launcher(root):
    path = root / "install.sh"
    link = shlex.quote(str(root / CURRENT))
    downloads = shlex.quote(str(root / "downloads"))
    text = f"""#!/bin/sh
set -eu
target=$(/usr/bin/readlink {link}) || {{ echo 'No active verified installer' >&2; exit 1; }}
case "$target" in
    {downloads}/*/cloud-installer) exec /bin/sh "$target/install.sh" "$@" ;;
    *) echo 'Invalid active installer selection' >&2; exit 1 ;;
esac
"""
    if os.path.lexists(path):
        if read_private(path) != text:
            raise ValueError("Stable installer launcher differs; refusing replacement")
    else:
        atomic_write(path, text, mode=0o700)
    return path


def run(registry, ui, *, rollback=False):
    registry._require_lock()
    root = registry.root
    link = root / CURRENT
    active = _read_selection(root, link)
    if active is not None and active != PROJECT_ROOT:
        raise ValueError(f"Use sh {root / 'install.sh'} self-update to manage the active installer")
    running = _version(PROJECT_ROOT)
    if rollback:
        previous = _read_selection(root, active.parent / "previous") if active is not None else None
        if previous is None or previous == active:
            raise ValueError("No previous installer selection is available for rollback")
        selected = _version(previous)
        if ui.confirm(f"Switch installer from v{running} back to v{selected}? No instances will change."):
            _launcher(root)
            _activate(link, previous)
            ui.message(f"Active installer: v{selected}")
        return

    selected, url, digest = available_release()
    ui.message(f"Current installer: v{running}\nAvailable stable installer: v{selected}")
    if tuple(map(int, selected.split("."))) < tuple(map(int, running.split("."))):
        ui.message("No newer official stable installer. No downgrade performed.")
        return
    if selected == running and active is not None:
        ui.message("Already using the available stable version.")
        return
    if not ui.confirm(f"Verify and activate installer v{selected}? No instances will change."):
        return
    target = _retained_payload(root, _stage(url, digest))
    if (_version(target) != selected or not (target / "installer/self_update.py").is_file()
            or not target.parent.name.startswith(digest[:12] + "-") or target == active):
        raise ValueError("Staged installer does not match the selected stable release")
    # The static plan path needs no root host probes, bootstrap or application writes.
    subprocess.run(["/bin/sh", str(target / "install.sh"), "plan",
                    str(target / "examples/nextcloud-only.json")], check=True, timeout=30, stdout=subprocess.DEVNULL)
    for directory, _, files in os.walk(target, topdown=False):
        parent = Path(directory)
        for name in files:
            _sync(parent / name)
        _sync(parent)
    _sync(target.parent / "release.tar.gz")
    if active is not None:
        (target.parent / "previous").symlink_to(active)
    _sync(target.parent)
    _sync(target.parent.parent)
    launcher = _launcher(root)
    _activate(link, target)
    ui.message(f"Active installer: v{selected}\nUse: sh {launcher}")
