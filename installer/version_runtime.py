"""Pure public worker payloads derived from an already resolved version plan.

Compatibility and package selection belong to the host resolver. These helpers
only validate the wire format and bind each worker's lock to that immutable plan.
"""

import hashlib
import json
import re


_NUMBER = r"[0-9]+(?:\.[0-9]+)+"
_TRIPLE = r"[0-9]+\.[0-9]+\.[0-9]+"
_NAME = r"[A-Za-z0-9][A-Za-z0-9_+.-]*"
_PACKAGE_VERSION = r"[A-Za-z0-9._+][A-Za-z0-9.+_,~:\-]*"
_ORIGIN = rf"{_NAME}/{_NAME}"
_CHECKSUM = r"(?:[0-9]+\$[A-Za-z0-9]+|[0-9A-Fa-f]{64})"
_VERSION_FIELDS = {
    "nextcloud": _TRIPLE,
    "onlyoffice": _TRIPLE,
    "connector": _TRIPLE,
    "php": _NUMBER,
    "database": _NUMBER,
    "freebsd_release": r"[0-9]+\.[0-9]+-RELEASE",
    "architecture": r"[a-z][a-z0-9_]*",
    "php_package": r"php[0-9]+",
    "plan_sha256": r"[a-f0-9]{64}",
    "packages_sha256": r"[a-f0-9]{64}",
    "dependencies_sha256": r"[a-f0-9]{64}",
    "connector_sha256": r"[a-f0-9]{64}",
}
_NC_VERSION_FIELDS = {key: value for key, value in _VERSION_FIELDS.items()
                      if key not in ("onlyoffice", "connector", "connector_sha256")}
_NC_VERSION_FIELDS["office_backend"] = r"none"
_VM_VERSION_FIELDS = {key: value for key, value in _NC_VERSION_FIELDS.items() if key != 'office_backend'}
_VM_VERSION_FIELDS.update(office_backend=r"(?:eurooffice|collabora)", connector=_TRIPLE,
                          connector_app=r"(?:eurooffice|richdocuments)", connector_sha256=r"[a-f0-9]{64}")
_LOCK_LIMIT = 1024 * 1024
_SERVICE_VERSION_FIELDS = {
    "service_profile": r"native-v1",
    "services_sha256": r"[a-f0-9]{64}",
    "talk_selected": r"(?:yes|no)",
}


def _safe(value, pattern, limit=256):
    return isinstance(value, str) and len(value) <= limit and re.fullmatch(pattern, value) is not None


def validate_runtime_versions(value):
    """Require exactly the public scalar fields; never accept shell fragments."""
    backend = value.get('office_backend') if isinstance(value, dict) else None
    fields = _VM_VERSION_FIELDS if backend in ('eurooffice', 'collabora') else _NC_VERSION_FIELDS if backend == "none" else _VERSION_FIELDS
    if isinstance(value, dict) and "app_installation" in value:
        fields = {key: pattern for key, pattern in fields.items() if key not in ("connector", "connector_sha256", "connector_app")}
        fields.update(app_installation=r"occ", office_backend=r"(?:onlyoffice|none|eurooffice|collabora)")
    if isinstance(value, dict) and "service_profile" in value:
        fields = dict(fields, **_SERVICE_VERSION_FIELDS)
    if isinstance(value, dict) and "package_installation" in value:
        fields = {key: pattern for key, pattern in fields.items()
                  if key not in ("packages_sha256", "dependencies_sha256")}
        fields.update(package_installation=r"pkg", requirements_sha256=r"[a-f0-9]{64}")
        fields.update({key: "(?:" + _PACKAGE_VERSION + ")?" for key in ("php", "database", "onlyoffice") if key in fields})
        if value.get("app_installation") == "occ":
            fields["freebsd_release"] = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-(?:RELEASE|STABLE|CURRENT)"
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError("The runtime requires an exact public versions object")
    if any(not _safe(value[key], pattern, 128) for key, pattern in fields.items()):
        raise ValueError("Invalid public version, release, package name or digest")
    if int(value["freebsd_release"].split(".", 1)[0]) < 15:
        raise ValueError("Runtime requires FreeBSD 15 or higher")
    # Wire validation also runs in the minimal staged Talk package. Keep it
    # independent of resource/path loading: authenticated policy admission is
    # performed separately by the worker before package/volatile-state actions.
    if value.get("package_installation") == "pkg" and value["architecture"] != "amd64":
        raise ValueError("Fresh runtime requires amd64")
    if backend in ('eurooffice', 'collabora') and "app_installation" not in value and value['connector_app'] != {'eurooffice':'eurooffice','collabora':'richdocuments'}[backend]:
        raise ValueError("Runtime connector ID does not match office backend")
    return dict(value)


def _validate_package_text(text):
    if (not isinstance(text, str) or not text or len(text.encode("utf-8")) > _LOCK_LIMIT
            or not text.endswith("\n")):
        raise ValueError("The package lock must be bounded, nonempty UTF-8 text")
    names = set()
    lines = text[:-1].split("\n")
    if lines != sorted(lines):
        raise ValueError("The package lock must be sorted")
    for line in lines:
        fields = line.split("|")
        if (len(fields) != 4 or any(not _safe(field, pattern) for field, pattern in
                                  zip(fields, (_NAME, _PACKAGE_VERSION, _ORIGIN, _CHECKSUM)))
                or fields[0] in names):
            raise ValueError("Invalid or duplicate package lock row")
        names.add(fields[0])
    return text


def package_text(plan, group):
    """Serialize the complete selected group, without resolving new packages."""
    if group == "talk":
        from .resolution import _plan_inventory
        _plan_inventory(plan)
        if not plan.get("services", {}).get("talk"):
            raise ValueError("Talk package lock requires an explicit selected services extension")
    elif group not in ("host", "nextcloud", "onlyoffice"):
        raise ValueError("Unknown package lock group")
    try:
        packages = plan["packages"][group]
        if not isinstance(packages, dict) or not packages:
            raise ValueError("A selected package group must be nonempty")
        lines = []
        for name, record in packages.items():
            if (not isinstance(record, dict) or record.get("name") != name
                    or not _safe(name, _NAME) or not _safe(record.get("version"), _PACKAGE_VERSION)
                    or not _safe(record.get("origin"), _ORIGIN) or not _safe(record.get("checksum"), _CHECKSUM)):
                raise ValueError("Invalid selected package record")
            lines.append(f'{name}|{record["version"]}|{record["origin"]}|{record["checksum"]}\n')
        return _validate_package_text("".join(sorted(lines)))
    except (KeyError, TypeError):
        raise ValueError("Incomplete selected package group") from None


def _upstream(value):
    if not isinstance(value, str):
        raise ValueError("A selected upstream version is required")
    match = re.fullmatch(rf"({_NUMBER})(?:_[0-9]+)?(?:,[0-9]+)?", value)
    if match is None:
        raise ValueError("Expected a numeric upstream package version")
    return match[1]


def _validate_dependency_text(text, packages):
    if (not isinstance(text, str) or len(text.encode("utf-8")) > _LOCK_LIMIT
            or (text and not text.endswith("\n"))):
        raise ValueError("The dependency lock must be bounded UTF-8 text")
    identities = {name: (version, origin) for name, version, origin, _ in
                  (line.split("|") for line in packages.splitlines())}
    lines = text[:-1].split("\n") if text else []
    if lines != sorted(lines):
        raise ValueError("The dependency lock must be sorted")
    seen = set()
    for line in lines:
        fields = line.split("|")
        if (len(fields) != 4 or any(not _safe(field, pattern) for field, pattern in
                                  zip(fields, (_NAME, _NAME, _PACKAGE_VERSION, _ORIGIN)))):
            raise ValueError("Invalid dependency lock row")
        owner, name, version, origin = fields
        if (owner not in identities or identities.get(name) != (version, origin)
                or (owner, name) in seen):
            raise ValueError("Dependency lock does not match the complete selected package closure")
        seen.add((owner, name))
    return text


def dependency_text(plan, group):
    """Serialize exact dependency edges, including an empty dependency graph."""
    packages = package_text(plan, group)
    lines = []
    for owner, record in plan["packages"][group].items():
        dependencies = record.get("dependencies")
        if not isinstance(dependencies, dict):
            raise ValueError("A complete dependency map is required")
        for name, dependency in dependencies.items():
            if (not _safe(name, _NAME) or not isinstance(dependency, dict)
                    or set(dependency) != {"version", "origin"}
                    or not _safe(dependency["version"], _PACKAGE_VERSION)
                    or not _safe(dependency["origin"], _ORIGIN)):
                raise ValueError("Invalid selected dependency record")
            lines.append(f'{owner}|{name}|{dependency["version"]}|{dependency["origin"]}\n')
    return _validate_dependency_text("".join(sorted(lines)), packages)


def connector_text(plan):
    """Exact selected signed record, never a mutable app-store 'latest' alias."""
    from .compatibility import connector_record
    if isinstance(plan, dict) and plan.get('schema_version') == 3:
        from .resolution import _plan_inventory
        _plan_inventory(plan)
    try:
        record = connector_record(plan["connector"], plan['connector_app'] if plan.get('schema_version') == 3 else 'onlyoffice')
        return json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    except (KeyError, TypeError):
        raise ValueError("A complete signed connector record is required") from None


def services_text(plan):
    """Stage as private services.json alongside the per-worker package locks."""
    from .resolution import _plan_inventory
    _plan_inventory(plan)
    if "services" not in plan:
        raise ValueError("No explicitly selected native services identity")
    return json.dumps(plan["services"], sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"


def runtime_versions(plan, package_text, dependency_text, *, group=None):
    """Bind public versions to this group's requirements or retained exact locks."""
    from .package_policy import repository_current
    current = repository_current(plan)
    if current:
        from .package_policy import requirements_text
        if package_text != "" or dependency_text != "" or group not in ("host", "nextcloud", "onlyoffice", "talk"):
            raise ValueError("Repository-current runtime requires an explicit group and no package locks")
        text = requirements_text(plan, group)
    else:
        text = _validate_package_text(package_text)
        dependencies = _validate_dependency_text(dependency_text, text)
    none = isinstance(plan, dict) and plan.get("schema_version") == 2
    vm = isinstance(plan, dict) and plan.get("schema_version") == 3
    fresh = isinstance(plan, dict) and "app_installation" in plan
    if none or vm or (isinstance(plan, dict) and "services" in plan):
        from .resolution import _plan_inventory
        _plan_inventory(plan)
    try:
        php_package = plan["roles"]["php"]
        packages = plan["packages"]["nextcloud"]
        result = {
            "nextcloud": plan["applications"]["nextcloud"],
            **({"app_installation": "occ", "office_backend": plan.get("office_backend", "onlyoffice"),
                **({"onlyoffice": plan["applications"]["onlyoffice"] if current else _upstream(plan["applications"]["onlyoffice"])} if not none and not vm else {})} if fresh else {"office_backend": "none"} if none else {
                'office_backend': plan['office_backend'], 'connector_app': plan['connector_app'],
                'connector': plan['applications']['connector']} if vm else {
                "onlyoffice": plan["applications"]["onlyoffice"] if current else _upstream(plan["applications"]["onlyoffice"]),
                "connector": plan["applications"]["connector"]}),
            "php": packages.get(php_package, {}).get("version", "") if current else _upstream(packages[php_package]["version"]),
            "database": packages.get(plan["roles"]["database"], {}).get("version", "") if current else _upstream(packages[plan["roles"]["database"]]["version"]),
            "freebsd_release": plan["target"]["release"],
            "architecture": plan["target"]["architecture"],
            "php_package": php_package,
            "plan_sha256": hashlib.sha256(json.dumps(
                plan, sort_keys=True, separators=(",", ":"),
                allow_nan=False).encode("utf-8")).hexdigest(),
            **({"package_installation": "pkg",
                "requirements_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()} if current else {
                "packages_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                "dependencies_sha256": hashlib.sha256(dependencies.encode("utf-8")).hexdigest()}),
            **({} if none or fresh else {"connector_sha256": hashlib.sha256(connector_text(plan).encode("utf-8")).hexdigest()}),
            **({"service_profile": "native-v1",
                "services_sha256": hashlib.sha256(services_text(plan).encode("utf-8")).hexdigest(),
                "talk_selected": "yes" if plan["services"]["talk"] else "no"} if "services" in plan else {}),
        }
    except (KeyError, TypeError):
        raise ValueError("Incomplete resolved version plan") from None
    return validate_runtime_versions(result)
