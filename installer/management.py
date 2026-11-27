"""Receipt for completed native-v1 installations, not a provisioning input."""

import hashlib
import os
import re

from .host import read_private
from .state import atomic_json, config_digest, private_json


RECEIPT = "management.json"
CONTRACT = 1


def _binding(registry, config):
    source = read_private(registry.evidence_path(config.instance, "source.sha256")).strip()
    if not re.fullmatch(r"[a-f0-9]{64}", source):
        raise ValueError("Invalid original installer source evidence")
    return {"contract": CONTRACT, "config_sha256": config_digest(config), "source_sha256": source}


def record_completed_install(deployment):
    """Bind the same guard bytes published by boot activation, before Ready."""
    from .network import storage_guard

    config = deployment.config
    path = deployment.state / RECEIPT
    value = _binding(deployment.registry, config)
    text = storage_guard(config, deployment.storage, deployment.registry.root)
    value["storage_guard_sha256"] = hashlib.sha256(text.encode()).hexdigest()
    if os.path.lexists(path):
        if private_json(path) != value:
            raise ValueError("Completed-install management receipt changed")
    else:
        atomic_json(path, value)


def installed_guard(registry, config):
    """Return the original guard digest for a supported completed instance only."""
    from .deploy import COMPLETE_MESSAGE

    state = registry.instance_path(config.instance)
    path = state / RECEIPT
    if (not os.path.lexists(path) or registry.lifecycle_enabled()
            or registry.status(config.instance)["state"] not in ("ready", "removing", "removed")):
        return None
    record = private_json(path)
    binding = _binding(registry, config)
    journal = private_json(state / "deployment.json")
    if (not config.has_native_services or not isinstance(record, dict)
            or type(record.get("contract")) is not int
            or set(record) != set(binding) | {"storage_guard_sha256"}
            or any(record[key] != value for key, value in binding.items())
            or not re.fullmatch(r"[a-f0-9]{64}", str(record["storage_guard_sha256"]))
            or read_private(state / "complete") != COMPLETE_MESSAGE
            or journal.get("schema_version") != config.schema_version
            or journal.get("config_sha256") != binding["config_sha256"]
            or any(journal.get("steps", {}).get(step, {}).get("state") != "complete"
                   for step in ("readiness checks", "boot activation"))):
        raise ValueError("Unsupported or unbound completed-install management receipt")
    return record["storage_guard_sha256"]
