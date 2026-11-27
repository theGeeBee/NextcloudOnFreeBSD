"""Advisory, secret-free registry inspection. Never initialize, lock or repair.

This projection is not an ownership/adoption decision. Mutation paths must reload
the original registry and revalidate it under their existing operation lock.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat

from .config import Config, SCHEMA_VERSION


STATES = frozenset(("configured", "installing", "failed", "ready", "removing", "removed"))
MAX_RECORD = 16 * 1024 * 1024


def _directory(path, *, optional=False):
    try:
        info = path.lstat()
    except FileNotFoundError:
        if optional:
            return False
        raise
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("Unsafe registry directory")
    return True


def _read(path, *, optional=False):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        if optional:
            return None
        raise
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > MAX_RECORD):
            raise ValueError("Unsafe registry record")
        raw = stream.read(MAX_RECORD + 1)
        if len(raw) > MAX_RECORD:
            raise ValueError("Registry record too large")
        def unique(pairs):
            result = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError("Duplicate registry field")
                result[key] = item
            return result
        try:
            value = json.loads(raw, object_pairs_hook=unique)
        except RecursionError:
            raise ValueError("Excessively nested registry record") from None
        if not isinstance(value, dict):
            raise ValueError("Unexpected registry record")
        return value


def _time(value):
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc).isoformat()
    except ValueError:
        return None


def instance_names(registry):
    """Enumerate only safe registered names, without creating a missing root."""
    if registry.lifecycle_enabled():
        return registry.lifecycle_names()
    root = Path(registry.root)
    if any(parent.is_symlink() for parent in (root, *root.parents)):
        raise ValueError("Symlink in registry path")
    if not _directory(root, optional=True) or not _directory(root / "instances", optional=True):
        return []
    names = []
    for path in sorted((root / "instances").iterdir()):
        if path.name.startswith(".pending-"):
            continue
        if not re.fullmatch(r"[a-z][a-z0-9]{0,7}", path.name):
            raise ValueError("Unexpected registry entry; inspection requires review")
        # Report a broken per-instance directory in snapshot(), not as an empty host.
        names.append(path.name)
    return names


def _installer_version():
    from .paths import PROJECT_ROOT
    from .self_update import _version
    try:
        return _version(PROJECT_ROOT)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None


def _saved_plan(registry, name, *, lifecycle):
    # Optional historical display data. Missing/corrupt plan evidence is not a
    # live failure and must not hide unrelated actions or expose raw contents.
    try:
        # Enrolled evidence_path(..., "versions.json") can resolve a successor.
        path = (registry._store().resolve(name)["evidence_path"] / "versions.json"
                if lifecycle else registry.evidence_path(name, "versions.json"))
        return _read(path, optional=True) or {}
    except (OSError, ValueError, TypeError, KeyError):
        return {}


def _retained_actions(registry, config, row, path, *, lifecycle):
    """Only offer actions whose static gates can be checked without live probes."""
    if row["state"] != "ready" or not config.native_office or config.has_native_services:
        return []
    from types import SimpleNamespace
    from .maintenance import entry_guard, require_instance_adapter
    from .operations import _restore_journal

    if row["pending"] not in ([], ["database restore"]):
        return []
    try:
        if lifecycle:
            entry_guard("backup", registry=registry)
            require_instance_adapter(registry, config.instance)
        restore = (_restore_journal(SimpleNamespace(config=config, state=path))
                   if os.path.lexists(path / "restore.json") else None)
    except (OSError, ValueError, TypeError, KeyError):
        return []
    if row["pending"] or restore and restore["state"] == "pending":
        return ["restore"] if restore and restore["state"] == "pending" else []
    return ["backup", "restore"] if lifecycle else ["backup", "restore", "upgrade"]


def _enrollment_candidates(registry, rows, *, lifecycle):
    """Screen the host and first-readiness evidence; CLI still verifies live state."""
    from .deploy import source_digest
    from .enrollment import ADAPTER, BASELINE, _bytes

    try:
        graph = registry._store().graph()["instances"] if lifecycle else {}
        ready = [row for row in rows if row["state"] not in ("configured", "removed")]
        # The CLI checks the original guard on every extant pair, not just the
        # selected entry. Native services and interrupted installs cannot join.
        if any(row["state"] != "ready" or row.get("service_profile")
               or row["office_backend"] != "onlyoffice" for row in ready):
            return set()
        candidates = {}
        for row in ready:
            name = row["instance"]
            if graph.get(name, {}).get("kind") == "managed" or row["pending"]:
                continue
            path = registry.instance_path(name)
            if any(os.path.lexists(path / filename) for filename in (
                    "enrollment-unavailable.json", "restore.json", "removal.json", "purge.json",
                    "allow-start.initialization-recovery")) or any(path.glob("allow-start.enrollment-*")):
                continue
            try:
                baseline = _read(path / BASELINE, optional=True)
                bindings = ("source_sha256", "executor_sha256", "config_sha256", "versions_sha256", "inputs_sha256")
                if (baseline and set(baseline) == {"schema", "adapter", "origin", "instance", "observation",
                                                   "plugins_sha256", *bindings}
                        and type(baseline["schema"]) is int and baseline["schema"] == 1 and baseline["adapter"] == ADAPTER
                        and baseline.get("origin") == "first-install-readiness" and baseline.get("instance") == name
                        and isinstance(baseline["observation"], dict)
                        and all(isinstance(baseline[key], str) and re.fullmatch(r"[0-9a-f]{64}", baseline[key])
                                for key in bindings)):
                    candidates[name] = baseline["source_sha256"]
            except (OSError, ValueError, TypeError):
                continue
        if candidates:
            original = source_digest().encode()
            for row in ready:
                name = row["instance"]
                if graph.get(name, {}).get("kind") != "managed":
                    if _bytes(registry.evidence_path(name, "source.sha256")) != original:
                        return set()
            return {name for name, source in candidates.items() if source == original.decode().strip()}
        return set()
    except (OSError, ValueError, TypeError, KeyError):
        return set()


def snapshot(registry):
    """Return bounded public facts; incomplete/unsafe records remain visible."""
    from .management import installed_guard

    view = {"instances": [], "errors": [], "pending_network": [], "host_policy": "unknown",
            "installer_version": _installer_version(), "self_update": False}
    try:
        lifecycle = registry.lifecycle_enabled()
        names = instance_names(registry)
        if Path(registry.root).exists():
            host = _read(Path(registry.root) / "host.json", optional=True)
            if host is not None:
                view["host_policy"] = "retained (not live-verified)"
        from .firewall import pending_transactions
        view["pending_network"] = [item.name for item in pending_transactions(registry.root)]
    except (OSError, ValueError, TypeError, KeyError):
        view["errors"].append("Registry/network inspection failed; no mutation is safe from this dashboard")
        return view
    for name in names:
        row = {"instance": name, "state": "inspection-error", "pending": [],
               "last_installation_check": None, "live_health": "not checked", "error": None}
        try:
            path = registry.instance_path(name)
            _directory(path)
            config_path = registry.evidence_path(name, "config.json")
            original = _read(config_path)
            config = registry.load(name)
            if config.instance != name:
                raise ValueError("Instance identity mismatch")
            status = registry.status(name)
            if status.get("state") not in STATES:
                raise ValueError("Unknown instance state")
            journal = _read(path / "deployment.json", optional=True)
            if journal is not None:
                if (journal.get("schema_version") != SCHEMA_VERSION
                        or journal.get("config_sha256") != registry.deployment_config_digest(name)
                        or not isinstance(journal.get("steps"), dict)):
                    raise ValueError("Deployment binding/schema mismatch")
                for record in journal["steps"].values():
                    if not isinstance(record, dict) or record.get("state") not in ("running", "failed", "complete"):
                        raise ValueError("Invalid deployment phase")
                if any(record["state"] != "complete" for record in journal["steps"].values()):
                    row["pending"].append("installation")
                check = journal["steps"].get("readiness checks", {})
                if check.get("state") == "complete":
                    row["last_installation_check"] = _time(check.get("completed"))
            for filename, label in (("restore.json", "database restore"),
                                    ("initialization.json", "initialization recovery"),
                                    ("removal.json", "removal"), ("purge.json", "data purge")):
                record = _read(path / filename, optional=True)
                if record is None:
                    continue
                if record.get("state") in ("pending", "running", "failed"):
                    row["pending"].append(label)
                steps = record.get("steps", {})
                if not isinstance(steps, dict) or any(not isinstance(step, dict) for step in steps.values()):
                    raise ValueError("Invalid maintenance journal")
                if any(step.get("state") in ("running", "failed") for step in steps.values()):
                    row["pending"].append(label)
                recoveries = record.get("recoveries", [])
                if not isinstance(recoveries, list) or any(not isinstance(item, dict) for item in recoveries):
                    raise ValueError("Invalid recovery journal")
                if recoveries and recoveries[-1].get("state") in ("running", "failed"):
                    row["pending"].append(label)
            plan = _saved_plan(registry, name, lifecycle=lifecycle)
            try:
                row["managed_ready"] = (status["state"] == "ready" and not row["pending"]
                                        and installed_guard(registry, config) is not None)
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                row["managed_ready"] = False
            # Detect common lock-free observation races. This is advisory; every
            # mutation still reloads state and resources while holding its lock.
            if original != _read(registry.evidence_path(name, "config.json")) or status != registry.status(name):
                raise ValueError("Registry changed during inspection")
            apps = plan.get("applications")
            nextcloud = apps.get("nextcloud") if isinstance(apps, dict) else None
            recorded = (nextcloud if isinstance(nextcloud, str)
                        and re.fullmatch(r"[0-9]{1,8}(?:\.[0-9]{1,8}){2}", nextcloud) else None)
            row.update(state=status["state"], public_url=config.public_url,
                        nextcloud_jail=config.nextcloud_jail, office_jail=config.onlyoffice_jail if config.native_office else None,
                       recorded_release=config.release, state_updated=_time(status.get("updated")),
                       office_backend=config.backend, recorded_nextcloud=recorded,
                       legacy_advisory=bool(plan) and config.native_office and not config.has_native_services
                       and not ({"app_installation", "package_installation", "services"} & plan.keys()))
            if config.has_native_services:
                row.update(service_profile=config.service_profile, client_push=True,
                           talk_jail=config.talk_jail if config.talk else None)
            row["pending"] = sorted(set(row["pending"]))
            row["actions"] = _retained_actions(registry, config, row, path, lifecycle=lifecycle)
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            # Never echo private JSON, raw exceptions or journals' error payloads.
            row["error"] = "Unsafe, changed or unsupported instance records; inspect privately"
        view["instances"].append(row)
    blocked = bool(view["pending_network"] or any(row["error"] for row in view["instances"]))
    view["self_update"] = not blocked and not lifecycle
    candidates = _enrollment_candidates(registry, view["instances"], lifecycle=lifecycle) if not blocked else set()
    for row in view["instances"]:
        actions = [] if blocked else row.get("actions", [])
        if row["instance"] in candidates:
            actions.append("maintenance-register")
        if not blocked and not lifecycle and row["state"] != "configured":
            actions.append("remove")
        if not blocked and not lifecycle and row.get("managed_ready"):
            actions.append("update-jails")
            if row["office_backend"] in ("eurooffice", "collabora"):
                actions.append("update-vm")
        row["actions"] = actions
    return view


def render(view, *, host_release=None, updates=None, compact=False):
    from .config import OFFICE_LABELS

    version = view.get("installer_version")
    lines = ["Installer: " + ("v" + version if version else "Unknown")]
    if compact:
        rows = view["instances"]
        lines[0] += " | Live versions and updates: Not checked"
        lines.append(f"{len(rows)} instances | Recorded Nextcloud / office / jail")
        for row in rows[:3]:
            line = f"{row['instance']}: {row['state']}"
            if not row["error"]:
                line += (f" | {row['recorded_nextcloud'] or 'Unknown'} | {row['office_backend']} "
                         f"| {row['recorded_release']}")
            lines.append(line)
        if len(rows) > 3:
            lines.append(f"{len(rows) - 3} more; choose List or Status.")
        return "\n".join(lines)

    lines.append("Managed host dashboard (advisory; no repair or update discovery)")
    lines.append("Installer self-update: " + ("available on request" if view["self_update"] else "unavailable")
                 + " | Latest stable installer: Not checked")
    lines.append("Package availability: Not checked | Previous package update result: Unknown")
    if isinstance(host_release, str) and re.fullmatch(r"(?:[0-9]+\.[0-9]+-RELEASE(?:-p[0-9]+)?|15\.2-STABLE|16\.0-CURRENT)", host_release):
        lines.append("Host userland: " + host_release)
    elif host_release is not None:
        lines.append("Host userland: unknown")
    lines.append("Shared host policy: " + view["host_policy"])
    for error in view["errors"]:
        lines.append("ATTENTION: " + error)
    if view["pending_network"]:
        lines.append("ATTENTION: unresolved network transaction(s); inspect status/recover-network")
    reports = {row["instance"]: row for row in (updates or {}).get("instances", [])}
    if not view["instances"] and not view["errors"]:
        lines.append("No registered instances. Choose Install or Configure.")
    for row in view["instances"]:
        lines.append(f"{row['instance']}: {row['state']}")
        if row["error"]:
            lines.append("  " + row["error"])
            continue
        if row.get("office_backend") == "none":
            lines.append(f"  {row['public_url']} | {row['nextcloud_jail']} | Nextcloud only — no integrated document server")
        elif row.get("office_backend") in ("eurooffice", "collabora"):
            lines.append(f"  {row['public_url']} | {row['nextcloud_jail']} | {row['office_backend']} dedicated VM (fresh-install only)")
        else:
            lines.append(f"  {row['public_url']} | {row['nextcloud_jail']} + dedicated {row['office_jail']}")
        lines.append("  Office backend: " + OFFICE_LABELS[row["office_backend"]])
        lines.append("  Originally selected Nextcloud: " + (row["recorded_nextcloud"] or "Unknown")
                     + " | Live Nextcloud: Not checked")
        lines.append("  Recorded jail release: " + row["recorded_release"])
        if row.get("service_profile"):
            lines.append("  Native services: Client Push" +
                         (" + dedicated Talk/TURN " + row["talk_jail"] if row.get("talk_jail") else ""))
            lines.append("  Native service backup/restore/upgrade enrollment unavailable; external media acceptance not inferred.")
        lines.append("  Live health: not checked. Last installation readiness check: "
                     + (row["last_installation_check"] or "unknown") + " (historical)")
        if row["pending"]:
            lines.append("  ATTENTION: " + ", ".join(row["pending"]))
        lines.append("  Maintenance actions: " + (", ".join(row.get("actions", ())) or "none offered"))
        if row["legacy_advisory"]:
            report = reports.get(row["instance"], {})
            freshness = report.get("freshness")
            if freshness == "stale":
                note = "Stale (not evidence of current availability)"
            elif freshness == "fresh" and _time(report.get("checked_at")):
                note = str(report.get("status", "Unknown")) + " (cached)"
            else:
                note = "Unknown" if freshness == "unknown" else "Not checked"
            lines.append("  Legacy advisory (recorded plan only): " + note
                         + " | checked: " + (_time(report.get("checked_at")) or "never"))
    lines.append("Actions are advisory; commands recheck eligibility and ownership when selected.")
    return "\n".join(lines)
