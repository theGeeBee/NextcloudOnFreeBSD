"""Validated, offline regional choices; importing this module reads no data."""

import json
import re
import unicodedata

from .paths import PROJECT_ROOT


def _error(kind: str, reason: str) -> ValueError:
    return ValueError(
        f"Bundled resources/{kind}.json {reason}; restore this file from the "
        "same installer artifact."
    )


def _unique_object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _load(kind: str) -> list:
    try:
        data = json.loads(
            (PROJECT_ROOT / "resources" / f"{kind}.json").read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
        )
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise _error(kind, "is missing, unreadable or invalid JSON") from None
    if (not isinstance(data, dict) or set(data) != {"schema_version", "metadata", kind}
            or type(data["schema_version"]) is not int or data["schema_version"] != 1):
        raise _error(kind, "has an unsupported schema (expected schema_version 1)")
    metadata, entries = data["metadata"], data[kind]
    if (not isinstance(metadata, dict)
            or not {"source", "version", "license", "count"} <= metadata.keys()
            or any(not key.isprintable()
                   or (key != "count" and (not isinstance(value, str) or not value.strip()
                                          or not value.isprintable()))
                   for key, value in metadata.items())
            or type(metadata.get("count")) is not int
            or not isinstance(entries, list) or not entries
            or metadata["count"] != len(entries)):
        raise _error(kind, "has invalid provenance or an incomplete entry list")
    return entries


def _name_key(name: str) -> str:
    # Stable English alphabetical ordering, without depending on the host locale.
    return "".join(char for char in unicodedata.normalize("NFKD", name.casefold())
                   if not unicodedata.combining(char))


def country_choices() -> tuple[tuple[str, str], ...]:
    """Return immutable (ISO alpha-2 code, IANA English name) pairs by name."""
    result = []
    codes = set()
    names = set()
    for entry in _load("countries"):
        if not isinstance(entry, list) or len(entry) != 2:
            raise _error("countries", "contains a malformed country pair")
        code, name = entry
        if (not isinstance(code, str) or re.fullmatch(r"[A-Z]{2}", code) is None
                or code in codes):
            raise _error("countries", "contains a duplicate or noncanonical ISO alpha-2 code")
        if (not isinstance(name, str) or not 1 <= len(name) <= 120
                or name != name.strip() or "  " in name
                or not any(char.isalpha() for char in name)
                or any(unicodedata.category(char)[0] not in "LMN"
                       and char not in " &'’().,-" for char in name)
                or _name_key(name) in names):
            raise _error("countries", "contains a duplicate or unsafe country name")
        codes.add(code)
        names.add(_name_key(name))
        result.append((code, name))
    return tuple(sorted(result, key=lambda pair: (_name_key(pair[1]), pair[0])))


def timezone_choices() -> tuple[str, ...]:
    """Return immutable, sorted PHP ALL timezone identifiers, including UTC."""
    result = []
    seen = set()
    for identifier in _load("timezones"):
        if (not isinstance(identifier, str) or len(identifier) > 120
                or re.fullmatch(r"(?:UTC|[A-Za-z][A-Za-z0-9_+-]*(?:/[A-Za-z][A-Za-z0-9_+-]*)+)",
                                identifier) is None
                or identifier in seen):
            raise _error("timezones", "contains a duplicate or unsafe timezone identifier")
        seen.add(identifier)
        result.append(identifier)
    if "UTC" not in seen:
        raise _error("timezones", "is missing UTC")
    return tuple(sorted(result))
