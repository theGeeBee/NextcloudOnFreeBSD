"""Hand off completed v1.0.1 instances to the unchanged published remover."""

import os
from pathlib import Path
import shlex

from .deploy import COMPLETE_MESSAGE, source_digest
from .host import read_private
from .state import private_json


# The published archive (see docs/engineering/v1.0.1-baseline.md) binds both
# the deployment source digest and the executor digest (which adds install.sh).
SOURCE = "6baf55defb42506dddac40756011d147189b5c514f18013f39215e68eff3debf\n"
EXECUTOR = "a991433a97e679afaee5a8073232dbafb89b1d89d6eefcc76a5cc64389893abe"
TOP_LEVEL = {"install.sh", "installer", "resources", "assets", "examples", "tools",
             "LICENSE", "README.md", "pyproject.toml"}
ORIGINAL = "Use the verified v1.0.1 installer at its independently known original absolute path"


def _saved_source(registry, name):
    path = registry.evidence_path(name, "source.sha256")
    try:
        return read_private(path)
    except FileNotFoundError:
        return None


def _entrypoint(value):
    from .maintenance_staging import _source

    root = Path(value)
    if not root.is_absolute() or ".." in root.parts or not value.isprintable():
        raise ValueError(f"{ORIGINAL}; enter the unpacked directory, not the archive")
    try:
        _, digest, executor = _source(root, include_branding=True)
        # -I -B does not prevent loading existing bytecode or top-level
        # modules shadowing stdlib imports. Execute only a clean release tree.
        if (digest + "\n" != SOURCE or executor != EXECUTOR
                or {item.name for item in root.iterdir()} != TOP_LEVEL
                or any(item.name == "__pycache__" or item.suffix == ".pyc"
                       for directory in ("installer", "resources")
                       for item in (root / directory).rglob("*"))):
            raise ValueError("Unexpected files or release identity")
    except (OSError, ValueError):
        raise ValueError(f"Cannot authenticate the retained v1.0.1 payload. {ORIGINAL}; "
                         "do not guess the path or substitute a different release.") from None
    return root / "install.sh"


def _verify_retained_path(root, config, status, entrypoint):
    from .lifecycle import _owned_file
    from .service_deadlines import GUARD_DIRECTORY
    from .state import Journal

    name = config.instance
    path = Path(GUARD_DIRECTORY) / (name + "-storage-guard")
    guard = _owned_file(path, mode=0o700)
    if guard is None and status in ("removing", "removed"):
        record = Journal(root / "instances" / name / "removal-config.json", config).data
        checkpoint = record.get("files", {}).get("storage_guard", {})
        if checkpoint.get("path") == str(path) and checkpoint.get("state") in ("authorized", "removed"):
            return  # The original cleanup may already have unlinked its guard.
    if guard is not None:
        try:
            # The published guard's Python command binds its payload path.
            # Compare to the operator's input; never choose a path from this file.
            command = shlex.split(guard[0].decode().splitlines()[3])
            if (command[:4] == ["/usr/local/bin/python3", "-I", "-B", "-c"]
                    and command[5:] == [str(entrypoint.parent), str(root), name, "${1:-}",
                                        EXECUTOR, "||", "exit", "1"]):
                return
        except (IndexError, ValueError):
            pass
    raise ValueError(f"Retained storage guard does not confirm that path. {ORIGINAL}")


def delegate(registry, ui, args, *, plain):
    """Return for the current remover; otherwise replace this process."""
    name = args.instance
    source = _saved_source(registry, name)
    if source != SOURCE:
        require_local_removal(registry, name)
        return
    path = _entrypoint(ui.input("Original v1.0.1 installer directory (absolute path)"))
    # Inspect coherently without creating state; release this preflight lock
    # before exec so the original CLI can acquire its own operation lock.
    with registry.locked(create=False):
        config = registry.load(name)
        state = registry.instance_path(name)
        status = registry.status(name)["state"]
        try:
            journal = private_json(state / "deployment.json")
            complete = (read_private(state / "complete") == COMPLETE_MESSAGE
                        and journal["schema_version"] == config.schema_version
                        and journal["steps"].get("boot activation", {}).get("state") == "complete")
        except FileNotFoundError:
            complete = False
        if (_saved_source(registry, name) != SOURCE
                or status not in ("ready", "removing", "removed") or not complete):
            raise ValueError(f"Delegation requires a completed v1.0.1 installation. {ORIGINAL}")
        _verify_retained_path(registry.root, config, status, path)
        peers = {c.instance for c, status in registry.entries()
                 if status["state"] != "configured"}
        peers.update(c.instance for c in registry.network_configs())
        if any(_saved_source(registry, other) != SOURCE for other in peers):
            raise ValueError("Cannot delegate removal on a mixed or unverified host; "
                             "inspect shared PF and Bastille state before changing it")
    command = ["/bin/sh", str(path), *(["--plain"] if plain else []), "remove", name]
    if args.purge_data:
        command.append("--purge-data")
    capture = getattr(args, "capture_backup", None)
    if capture is not None:
        command.append("--backup" if capture else "--no-backup")
    if getattr(args, "backup_output", None) is not None:
        command.extend(("--backup-output", str(args.backup_output)))
    os.execv(command[0], command)


def require_local_removal(registry, name):
    """Admit the current remover, rechecked under the caller's operation lock."""
    from .management import RECEIPT, installed_guard

    source = _saved_source(registry, name)
    state = registry.instance_path(name)
    if source != SOURCE and os.path.lexists(state / RECEIPT):
        if installed_guard(registry, registry.load(name)) is not None:
            return
    if ((source is None and os.path.lexists(state / "complete"))
            or (source is not None and source != source_digest())):
        raise ValueError("Removal requires a compatible completed install or the matching original installer and retained source evidence")
