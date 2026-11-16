"""Pure root requirements for native pkg; catalog observations are not locks.

The discriminator is deliberately independent of app installation. Its absence
always means the retained exact-package contract, including for older occ plans.
"""

from copy import deepcopy
import json
from pathlib import Path
import re

from .versions import NAME, ORIGIN, TRIPLE, object_fields, text, validate_families


INSTALLATION = {"method": "pkg", "policy": "repository-current"}
GROUPS = ("host", "nextcloud", "onlyoffice", "talk")


def repository_current(plan):
    """Validate an explicit discriminator; never infer or retrofit one."""
    if not isinstance(plan, dict):
        raise ValueError("Package policy requires an object")
    if "package_installation" not in plan:
        return False
    if plan["package_installation"] != INSTALLATION:
        raise ValueError("Unsupported package_installation; expected method=pkg, policy=repository-current")
    return True


def _recipe_profiles(config, policy):
    """Select original recipes before their package-name aliases are replaced."""
    from .versions import VM_BACKENDS, office_backend, target
    backend = office_backend(config)
    release = getattr(config, "freebsd_release", "") or policy["defaults"]["freebsd_release"]
    architecture = getattr(config, "architecture", "") or policy["defaults"]["architecture"]
    if getattr(config, "_legacy_target", None):
        release, architecture = config._legacy_target.split("/")
    identity = target(policy, release, architecture)["release"] + "/" + architecture
    profiles = [profile for profile in policy["profiles"]
                if profile.get("office_backend", "onlyoffice") == backend and identity in profile["targets"]]
    if not profiles:
        label = "No reviewed version policy" if backend in VM_BACKENDS else "No reviewed compatibility profiles"
        raise ValueError(f"{label} for office_backend={backend!r} on {identity}")
    return profiles


def _normalize_families(families, profiles):
    """Bind only recipe-name aliases to roles; preserve canonical role inputs."""
    roles = ("php", "database", "database_client")
    aliases = {profile["roles"][role]["package"]: role for profile in profiles for role in roles}
    aliases.update({role: role for role in roles})
    normalized = {}
    for name, family in validate_families(families).items():
        if name == "nextcloud":
            normalized[name] = family
            continue
        if name not in aliases:
            raise ValueError(f"version_families.{name} is unsupported with repository-current packages; only Nextcloud and selected PHP/database package flavors are supported")
        text(family, r"[1-9][0-9]*\.(?:0|[1-9][0-9]*)", "PHP/MariaDB package flavour (major.minor)")
        role = aliases[name]
        if role in normalized and normalized[role] != family:
            raise ValueError("Contradictory PHP/database package flavour requests")
        normalized[role] = family
    if ("database" in normalized and "database_client" in normalized
            and normalized["database"] != normalized["database_client"]):
        raise ValueError("Contradictory PHP/database package flavour requests")
    return normalized


def normalize_plan_constraints(config, effective, policy):
    """Normalize fresh/comparison constraints, never mutate configs or saved plans."""
    result = deepcopy(effective)
    if "version_families" in result:
        result["version_families"] = _normalize_families(result["version_families"], _recipe_profiles(config, policy))
    return result


def validate_constraints(config, policy=None):
    """Copy the backend recipe with the requested numeric package flavours.

    Tested defaults are not an eligibility list or a compatibility guarantee.
    """
    from .versions import load_policy
    if (getattr(config, "external_storage_smb", False) or getattr(config, "external_storage_ftp", False)) and not getattr(config, "external_storage", False):
        raise ValueError("External storage SMB/FTP support requires external_storage")
    if getattr(config, "external_storage", False) and getattr(config, "service_profile", "") != "native-v1":
        raise ValueError("external_storage requires service_profile=native-v1")
    if "files_external" in getattr(config, "selected_nextcloud_apps", ()) and not getattr(config, "external_storage", False):
        raise ValueError("Repository-current files_external requires explicit external_storage selection")
    for field in ("onlyoffice_min", "onlyoffice_exact"):
        if getattr(config, field, ""):
            raise ValueError(f"{field} is unsupported with repository-current packages; native pkg selects the repository version")
    policy = load_policy() if policy is None else policy
    profiles = _recipe_profiles(config, policy)
    families = _normalize_families(getattr(config, "version_families", {}), profiles)
    requested_roles = {"database" if role == "database_client" else role: family
                       for role, family in families.items() if role != "nextcloud"}
    selected = []
    for original in profiles:
        profile = deepcopy(original)
        for role, family in requested_roles.items():
            suffix = family.replace(".", "")
            if role == "php":
                profile["php_suffix"] = suffix
                profile["roles"][role].update(package="php" + suffix, origin="lang/php" + suffix)
            else:
                for db_role, ending in (("database", "server"), ("database_client", "client")):
                    name = "mariadb" + suffix + "-" + ending
                    profile["roles"][db_role].update(package=name, origin="databases/" + name)
        # These are client extensions only. Native pkg resolves their libraries;
        # no Samba server root or service is selected by this feature.
        for enabled, name, origin in (
                (getattr(config, "external_storage_ftp", False), "php{suffix}-ftp", "ftp/php{suffix}-ftp"),
                (getattr(config, "external_storage_smb", False), "php{suffix}-pecl-smbclient", "net/pecl-smbclient")):
            if enabled:
                profile["php_extensions"].append(name)
                profile.setdefault("extension_origins", {})[name] = origin.replace("{suffix}", profile["php_suffix"])
        selected.append(profile)
    return selected


def validate_tested_versions(value):
    """Validate individual observations and optional tuples, never eligibility."""
    object_fields(value, ("schema_version", "tested_versions"), ("tested_combinations",), label="tested versions")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValueError("Unsupported tested-versions schema")
    keys = ("nextcloud", "php", "database")
    def numeric(key, item):
        pattern = TRIPLE if key == "nextcloud" else r"[1-9][0-9]*\.(?:0|[1-9][0-9]*)"
        text(item, pattern, "tested " + key)
        if len(item) > 64:
            raise ValueError("Tested numeric value is too long")
    individual = object_fields(value["tested_versions"], keys, label="individually tested versions")
    for key, items in individual.items():
        if not isinstance(items, list) or len(items) > 4096:
            raise ValueError("Individually tested versions must be bounded lists")
        for item in items:
            numeric(key, item)
        if len(items) != len(set(items)):
            raise ValueError("Duplicate individually tested version")
    rows = value.get("tested_combinations", [])
    if not isinstance(rows, list) or len(rows) > 4096:
        raise ValueError("Tested combinations must be a bounded list")
    seen = set()
    for row in rows:
        object_fields(row, keys, label="tested combination")
        for key in keys:
            numeric(key, row[key])
        identity = tuple(row[key] for key in keys)
        if identity in seen:
            raise ValueError("Duplicate tested combination")
        seen.add(identity)
    return deepcopy(dict(value, tested_combinations=rows))


def load_tested_versions(path=None):
    """Read editable advisory data on demand, with bounded strict JSON syntax."""
    if path is None:
        from .paths import RESOURCES
        path = RESOURCES / "tested-versions.json"
    else:
        path = Path(path)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate tested-versions field")
            result[key] = value
        return result
    try:
        with path.open("rb") as stream:
            content = stream.read(1048577)
        if len(content) > 1048576:
            raise ValueError("Tested-versions file exceeds 1 MiB")
        return validate_tested_versions(json.loads(content, object_pairs_hook=unique))
    except (OSError, ValueError) as error:
        raise ValueError(f"Cannot load tested-versions JSON: {error}") from error


def selection_status(config, policy=None, *, nextcloud=None, tested=None):
    """Return combination/individual/unrecorded status and unknown component labels.

    Family requests without a resolved release are conservatively unverified.
    This catalogue never changes selection or probes availability/compatibility.
    """
    from .versions import load_policy
    policy = load_policy() if policy is None else policy
    profiles = validate_constraints(config, policy)
    families = validate_families(getattr(config, "version_families", {}))
    nc = getattr(config, "nextcloud_exact", "") if nextcloud is None else nextcloud
    if nc:
        text(nc, TRIPLE, "selected Nextcloud release")
    catalogue = load_tested_versions() if tested is None else validate_tested_versions(tested)
    explicit = {"php" if name.startswith("php") else "database": family
                for name, family in families.items() if name != "nextcloud"}
    def matches_component(profile, key, value):
        if key == "nextcloud":
            return bool(nc) and value == nc
        if key in explicit and explicit[key] != value:
            return False
        roles = profile["roles"]
        suffix = value.replace(".", "")
        if key == "php":
            return roles["php"]["package"] == "php" + suffix
        return (roles["database"]["package"] == "mariadb" + suffix + "-server"
                and roles["database_client"]["package"] == "mariadb" + suffix + "-client")
    combinations = catalogue["tested_combinations"]
    verified = all(any(all(matches_component(profile, key, value) for key, value in row.items())
                       for row in combinations) for profile in profiles)
    # A recorded combination is also evidence that its individual components
    # worked. Separate lists need not duplicate every optional combination row.
    known = {key: set(values) | {row[key] for row in combinations}
             for key, values in catalogue["tested_versions"].items()}
    unknown = []
    for profile in profiles:
        labels = {"nextcloud": "Nextcloud " + (nc or "(release not yet resolved)"),
                  "php": "PHP " + explicit.get("php", profile["roles"]["php"]["package"]),
                  "database": "MariaDB " + explicit.get("database", profile["roles"]["database"]["package"])}
        for key, label in labels.items():
            if not any(matches_component(profile, key, value) for value in known[key]) and label not in unknown:
                unknown.append(label)
    return {"status": "combination" if verified else "unrecorded" if unknown else "individual", "unknown": unknown}


def selection_warnings(config, policy=None, *, nextcloud=None, tested=None):
    """Advisory only: missing evidence never changes the requested installation."""
    status = selection_status(config, policy, nextcloud=nextcloud, tested=tested)
    if status["status"] != "unrecorded":
        return []
    return ["Versions not recorded in resources/tested-versions.json: " + ", ".join(status["unknown"]) + ". "
            "The existing installation recipe will be attempted without compatibility validation; "
            "packages or upstream commands may fail. Arbitrary combinations are not guaranteed to work."]


def selection_note(config, policy=None, *, nextcloud=None, tested=None):
    """Informational version evidence, never acceptance of an installation/backend."""
    status = selection_status(config, policy, nextcloud=nextcloud, tested=tested)["status"]
    if status == "individual":
        return ("Selected versions are recorded individually; this exact combination is not recorded. "
                "Normal installation will be attempted.")
    if status == "combination":
        return ("The selected Nextcloud release and PHP/MariaDB flavours are recorded as a tested combination. "
                "This does not establish acceptance of this installation or office backend.")
    return ""


def validate_requirements(value):
    """Validate root requests; schema 2 also permits unobserved names/origins.

    An empty origin is absence of observation, never a manufactured identity.
    Explicit role origins and any observed origins remain binding.
    """
    object_fields(value, ("schema_version", "repository", "abi", "group", "roots"), label="package requirements")
    if type(value["schema_version"]) is not int or value["schema_version"] not in (1, 2):
        raise ValueError("Unsupported package requirements schema")
    if value["repository"] not in ("latest", "quarterly") or value["group"] not in GROUPS:
        raise ValueError("Invalid package requirements repository/group")
    if value["abi"] != "FreeBSD:15:amd64":
        raise ValueError("Repository-current requirements need the reviewed FreeBSD:15:amd64 ABI")
    roots = value["roots"]
    if not isinstance(roots, dict) or not roots or len(roots) > 1024:
        raise ValueError("Package requirements need nonempty bounded roots")
    for name, origin in roots.items():
        text(name, NAME + ("|" + ORIGIN if value["schema_version"] == 2 else ""), "package requirement name")
        if origin != "" or value["schema_version"] == 1:
            text(origin, ORIGIN, "package requirement origin")
        if "/" in name and origin != name:
            raise ValueError("Origin-only package request must retain its origin")
        if re.fullmatch(r"php[0-9]+", name) and origin != "lang/" + name:
            raise ValueError("PHP runtime must retain its selected origin")
        if re.fullmatch(r"mariadb[0-9]+-(?:server|client)", name) and origin != "databases/" + name:
            raise ValueError("MariaDB must retain its selected origin")
    return deepcopy(value)


def requirements(plan, group):
    """Freeze selected root names/origins only, never package versions."""
    if not repository_current(plan):
        raise ValueError("Package requirements require explicit repository-current policy")
    if group not in GROUPS or group not in plan.get("roots", {}):
        raise ValueError("Package requirements group is not selected")
    names = plan["roots"][group]
    if not isinstance(names, list) or not names or len(names) != len(set(map(str, names))):
        raise ValueError("Missing or ambiguous package roots")
    roles = plan.get("roles", {})
    if not isinstance(roles, dict):
        raise ValueError("Package requirements need explicit role identities")
    php = roles.get("php")
    if php is not None:
        text(php, NAME, "selected PHP package name")
    roots = {}
    for name in names:
        text(name, NAME + "|" + ORIGIN, "normalized package root")
        if re.fullmatch(r"php[0-9]+(?:-.+)?", name) and (group != "nextcloud" or not php or (name != php and not name.startswith(php + "-"))):
            raise ValueError("PHP root must match the selected package flavor")
        record = plan.get("packages", {}).get(group, {}).get(name)
        if "root_origins" in plan:
            if not isinstance(plan["root_origins"], dict):
                raise ValueError("Package root origins must be grouped objects")
            origins = plan["root_origins"].get(group, {})
            if not isinstance(origins, dict) or set(origins) != set(names):
                raise ValueError("Package root origins do not match selected roots")
            roots[name] = origins[name]
            if record is not None and (record.get("name") != name or (roots[name] and record.get("origin") != roots[name])):
                raise ValueError("Package root observation differs from requested identity: " + name)
            continue
        if not isinstance(record, dict) or record.get("name") != name:
            raise ValueError("Package root is missing from the catalog preview: " + name)
        roots[name] = record["origin"]
    return validate_requirements({"schema_version": 2 if "root_origins" in plan else 1, "repository": plan["repository"],
                                  "abi": plan["target"]["abi"], "group": group, "roots": roots})


def requirements_text(plan, group):
    return json.dumps(requirements(plan, group), sort_keys=True, separators=(",", ":")) + "\n"
