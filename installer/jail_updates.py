"""Attended native ports updates, with no package plan replay."""

import re
import subprocess

from .lifecycle import _checked_jails
from .management import installed_guard
from .operations import _refuse_pending_restore
from .upgrade_packages import parse_repository


REPOSITORY = "FreeBSD-ports"
PKG = (
    "/usr/bin/env", "-i", "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin", "LC_ALL=C",
    "/usr/local/sbin/pkg",
    "-o", "ASSUME_ALWAYS_YES=no", "-o", "DEFAULT_ALWAYS_YES=no",
    "-o", "PKG_ENABLE_PLUGINS=no", "-o", "AUTOREMOVE=no", "-o", "HANDLE_RC_SCRIPTS=no",
)


def _check_ports_repository(deployment, name):
    text = deployment.jail(name, *PKG, "repositories", REPOSITORY, hide_output=True).stdout
    # Check the effective signing configuration, not the saved install ABI or
    # branch. Native pkg handles the jail's current ABI and catalogue.
    matches = re.findall(
        r'(?im)^\s*url\s*:\s*"pkg\+https://pkg\.freebsd\.org/([^/"\s]+)/(latest|quarterly)"', text)
    if len(matches) != 1:
        raise ValueError("No unambiguous official FreeBSD-ports repository in the owned jail")
    parse_repository(text, *matches[0])


def _require_targets(deployment, names):
    if tuple(name for name, _ in _checked_jails(deployment, names)) != names:
        raise ValueError("Every selected jail must have its owned Bastille root")
    for name in names:
        deployment.require_running_jail(name)


def update_jails(deployment, ui):
    """Return a small run-local summary; never alter installation evidence."""
    c, registry = deployment.config, deployment.registry
    registry._require_lock()
    if registry.status(c.instance)["state"] != "ready" or installed_guard(registry, c) is None:
        raise ValueError("Ports updates require a completed v1.1 management receipt and a ready instance")
    deployment.require_control_resolution()
    restore = deployment.state / "restore.json"
    if restore.exists() or restore.is_symlink():
        _refuse_pending_restore(deployment)
    names = c.jails
    _require_targets(deployment, names)
    for name in names:
        _check_ports_repository(deployment, name)
    origins = deployment.jail(c.nextcloud_jail, *PKG, "query", "-a", "%o", hide_output=True).stdout.splitlines()
    if not origins or any(origin.partition("@")[0] == "www/nextcloud" for origin in origins):
        raise ValueError("Cannot establish an archive-managed Nextcloud core; package-managed core is not supported")

    report = {"instance": c.instance, "state": "completed", "jails": []}
    ui.message("Ports updates in: " + ", ".join(names) + ".\n"
               "Review each actual pkg transaction, including removals or conflicts. "
               "Decline any change outside your intended ports maintenance, including base or Nextcloud core.\n"
               "Native package scripts and triggers may affect services. "
               "The installer does not restart services automatically; manual setup, "
               "compatibility checks or restarts may be necessary. "
               "No host, jail base or Nextcloud core upgrade is initiated.")
    if not ui.confirm("Refresh the selected jail repositories and start the attended pkg sessions?"):
        report["state"] = "cancelled"
        ui.message("Cancelled before refreshing repositories.")
        return report

    for jail in names:
        row = {"jail": jail}
        report["jails"].append(row)
        for stage, args in (("refresh", ("update", "-r", REPOSITORY)),
                            ("upgrade", ("upgrade", "-U", "-r", REPOSITORY))):
            row["stage"] = stage
            ui.message(f"{jail}: {stage} (FreeBSD-ports)")
            try:
                _require_targets(deployment, (jail,))
                # Inherit the terminal. Only pkg can ask for transaction approval;
                # do not pipe answers, use -y, or capture the live proposal.
                result = deployment.jail(jail, *PKG, *args, capture=False, check=False)
            except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
                row.update(state="failed", error=type(error).__name__)
                report["state"] = "failed"
                ui.message(f"{jail}: {stage} failed: {error}. Later jails were not attempted.")
                return report
            row["exit_code"] = result.returncode
            if result.returncode:
                # Native pkg uses exit 1 for both a declined upgrade and errors.
                row["state"] = "failed" if stage == "refresh" else "declined-or-failed"
                report["state"] = row["state"]
                ui.message(f"{jail}: {stage} did not complete ({row['state']}; pkg exit {result.returncode}). "
                           "See pkg output. Later jails were not attempted.")
                return report
        row["state"] = "completed"
        ui.message(f"{jail}: pkg completed. Follow any pkg instructions above. "
                   "If service packages changed, running services may still use old binaries. "
                   "Arrange downtime as needed and restart only the affected services. "
                   f"After maintenance, run Verify: sh install.sh verify {c.instance}.")
    return report
