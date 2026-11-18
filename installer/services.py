"""Pure optional native service policy composition; no package manager or probes.

An absent discriminator is historical semantics, not an implicit opt-in. App
signatures still require native verification; the separate ELF hash is an
integrity identity, not a publisher-signature assertion.
"""

from copy import deepcopy
from dataclasses import asdict
import hashlib
import json

from . import versions


PROFILE = "native-v1"
TALK_ROLES = ("talk_signaling", "talk_nats", "talk_janus", "talk_turn", "talk_python")


def app_selection(config):
    """Fresh app IDs only; occ owns release selection and signature checking."""
    apps = set(getattr(config, "selected_nextcloud_apps", ()))
    backend = versions.office_backend(config)
    if backend != "none":
        apps.add({"onlyoffice": "onlyoffice", "eurooffice": "eurooffice", "collabora": "richdocuments"}[backend])
    if enabled(config):
        apps.add("notify_push")
    return {"method": "occ", "apps": sorted(apps)}


def native_occ(value):
    return isinstance(value, dict) and "app_installation" in value


def enabled(config):
    profile = getattr(config, "service_profile", "")
    if not isinstance(profile, str) or profile not in ("", PROFILE):
        raise ValueError("Unknown native service profile")
    return profile == PROFILE


def talk_selected(config):
    return enabled(config) and "spreed" in config.selected_nextcloud_apps


def validate_policy(policy):
    versions.object_fields(policy, ("schema_version", "profile", "target", "nextcloud", "php", "push", "talk"), ("repository_current_targets", "repository_current_platform"), label="native services policy")
    versions.repository_current_platform(policy)
    if type(policy["schema_version"]) is not int or policy["schema_version"] != 1 or policy["profile"] != PROFILE:
        raise ValueError("Unsupported native services policy")
    if policy["target"] != {"release": "15.1-RELEASE", "architecture": "amd64"}:
        raise ValueError("Unreviewed native services target")
    if ("repository_current_targets" in policy and policy["repository_current_targets"] not in (
            [{"release": "15.2-STABLE", "architecture": "amd64"}],
            [{"release": "15.2-STABLE", "architecture": "amd64"},
             {"release": "16.0-CURRENT", "architecture": "amd64"}])):
        raise ValueError("Unreviewed development native services target")
    for application in ("nextcloud", "php"):
        versions.object_fields(policy[application], ("family",), label="native services application family")
        versions.text(policy[application]["family"], versions.FAMILY, "native services application family")
    push = versions.object_fields(policy["push"], ("app", "native"), label="Push policy")
    app = versions.object_fields(push["app"], ("version", "download", "sha256", "size", "platformVersionSpec", "phpVersionSpec"), label="Push app policy")
    versions.text(app["version"], versions.TRIPLE, "Push version")
    versions.text(app["download"], r"https://github\.com/nextcloud-releases/notify_push/releases/download/v[0-9.]+/notify_push-v[0-9.]+\.tar\.gz", "Push app URL")
    versions.text(app["sha256"], r"[a-f0-9]{64}", "Push app SHA256")
    if type(app["size"]) is not int or not 0 < app["size"] <= 64 * 1024 * 1024:
        raise ValueError("Invalid Push app size")
    from .client_push import REVIEWED_ARTIFACT
    if push["native"] != asdict(REVIEWED_ARTIFACT) or app["version"] != REVIEWED_ARTIFACT.version:
        raise ValueError("Unreviewed native Push artifact")
    if app["platformVersionSpec"] != ">=30.0.0 <36.0.0" or app["phpVersionSpec"] != "*":
        raise ValueError("Unreviewed Push requirements")
    versions.object_fields(policy["talk"], ("roles",), label="Talk policy")
    roles = versions.object_fields(policy["talk"]["roles"], TALK_ROLES, label="Talk roles")
    expected = (("nextcloud-spreed-signaling", "net-im/nextcloud-spreed-signaling"),
                ("nats-server", "net/nats-server"), ("janus", "www/janus"),
                ("turnserver", "net/turnserver"), ("python3", "lang/python3"))
    for role, identity in zip(TALK_ROLES, expected):
        rule = roles[role]
        versions.object_fields(rule, ("package", "origin") + (("range",) if role == "talk_python" else ()), label=role)
        if (rule["package"], rule["origin"]) != identity:
            raise ValueError("Wrong native Talk role identity")
        if role == "talk_python":
            if rule["range"] != {"family": "3"}:
                raise ValueError("Unreviewed Talk Python family")
    return policy


def load_policy():
    from .paths import RESOURCES
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate native services policy field")
            result[key] = value
        return result
    try:
        return validate_policy(json.loads((RESOURCES / "native-services.json").read_text(), object_pairs_hook=unique))
    except (OSError, ValueError) as error:
        raise ValueError(f"Cannot load resources/native-services.json: {error}") from error


def policy_hash(policy):
    validate_policy(policy)
    return hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def role_rules(config, policy=None):
    if not talk_selected(config):
        return {}
    policy = load_policy() if policy is None else validate_policy(policy)
    return deepcopy(policy["talk"]["roles"])


def add_roots(config, roots):
    rules = role_rules(config)
    if rules:
        roots["talk"] = sorted(rule["package"] for rule in rules.values())
    return roots


def extension(config, records=None, policy=None):
    """Fresh deferred Push policy, or an explicitly supplied legacy signed lock."""
    if not enabled(config):
        raise ValueError("Native service extension requires explicit selection")
    policy = load_policy() if policy is None else validate_policy(policy)
    if records is None:
        return validate_extension({"profile": PROFILE, "policy_sha256": policy_hash(policy),
                                   "talk": talk_selected(config), "push": {"app": "occ", "native": "deferred"}},
                                  config=config, policy=policy)
    app = policy["push"]["app"]
    matches = [record for record in records if isinstance(record, dict) and record.get("version") == app["version"]]
    if len(matches) != 1:
        raise ValueError("No unique obtainable signed notify_push release")
    result = {"profile": PROFILE, "policy_sha256": policy_hash(policy), "talk": talk_selected(config),
              "push": {"app": {"release": deepcopy(matches[0]), "sha256": app["sha256"], "size": app["size"]},
                       "native": deepcopy(policy["push"]["native"])}}
    return validate_extension(result, config=config, policy=policy)


def validate_extension(value, *, config=None, policy=None):
    policy = load_policy() if policy is None else validate_policy(policy)
    versions.object_fields(value, ("profile", "policy_sha256", "talk", "push"), label="services extension")
    if (value["profile"] != PROFILE or value["policy_sha256"] != policy_hash(policy)
            or type(value["talk"]) is not bool):
        raise ValueError("Native services policy identity changed; retain the original artifact/policy")
    if config is not None and (not enabled(config) or value["talk"] != talk_selected(config)):
        raise ValueError("Native services selection does not match configuration")
    push = versions.object_fields(value["push"], ("app", "native"), label="Push identity")
    if push == {"app": "occ", "native": "deferred"}:
        return deepcopy(value)
    app = versions.object_fields(push["app"], ("release", "sha256", "size"), label="Push app identity")
    record = versions.object_fields(app["release"], ("version", "phpVersionSpec", "platformVersionSpec", "isNightly", "signatureDigest", "download", "signature", "certificate"), label="signed Push app release")
    expected = policy["push"]["app"]
    if (any(record[key] != expected[key] for key in ("version", "download", "phpVersionSpec", "platformVersionSpec"))
            or record["isNightly"] is not False or record["signatureDigest"] != "sha512"
            or type(app["size"]) is not int or any(app[key] != expected[key] for key in ("size", "sha256"))
            or push["native"] != policy["push"]["native"]):
        raise ValueError("Push app/native artifact differs from reviewed identity")
    for key in ("signature", "certificate"):
        if not isinstance(record[key], str) or not record[key].strip() or len(record[key]) > 65536 or "\0" in record[key]:
            raise ValueError("Missing Push app signature/certificate; native verification remains required")
    return deepcopy(value)


def validate_context(extension, target, nextcloud, php, packages, *, repository_current=False):
    """Validate service integration context, not a live pkg execution snapshot.

    Only the caller's validated package discriminator opts into current catalog
    observations. Older occ/service records keep their numeric package contract.
    Python >=3.11 is a worker interpreter requirement, never a python3 metapackage
    version: native pkg owns the metapackage's actual interpreter dependencies.
    """
    if type(repository_current) is not bool:
        raise ValueError("Service repository_current context must be explicit boolean")
    policy = load_policy()
    validate_extension(extension, policy=policy)
    if repository_current and extension["push"] != {"app": "occ", "native": "deferred"}:
        raise ValueError("Repository-current services require the fresh native occ contract")
    targets = [policy["target"]] + (policy.get("repository_current_targets", []) if repository_current else [])
    if repository_current and versions.repository_current_platform(policy) is not None:
        expected = versions.repository_current_target({**policy, "targets": []}, target["release"], target["architecture"])
        matches_target = target["abi"] == expected["abi"]
    else:
        matches_target = any(all(target[key] == expected for key, expected in item.items()) for item in targets)
    if (not matches_target
            or (not repository_current and not versions.in_range(nextcloud, policy["nextcloud"]))
            or (not repository_current and not versions.in_range(php, policy["php"]))):
        raise ValueError("Native services context differs from the selected target/Nextcloud/PHP policy")
    rules = policy["talk"]["roles"] if extension["talk"] else {}
    for role, rule in rules.items():
        record = packages.get(rule["package"])
        if repository_current and record is None:
            continue
        if (record is None or record["origin"] != rule["origin"]
                or (not repository_current and "range" in rule and not versions.in_range(record["version"], rule["range"]))):
            raise ValueError(f"Missing/wrong-origin/incompatible native service package: {role}")
        if repository_current:
            from .compatibility import inventory
            # Validate preview shape/origin/ABI, never compare versions or hashes
            # with an earlier catalog. Actual dependency solving belongs to pkg.
            inventory({rule["package"]: record}, target["abi"])
        else:
            versions.package_version(record["version"])
    return {role: {key: deepcopy(value) for key, value in rule.items()
                   if not repository_current or key not in ("range", "version_exact")}
            for role, rule in rules.items()}
