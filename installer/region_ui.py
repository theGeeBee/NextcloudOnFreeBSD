"""Small native menus over bundled regional data; no host discovery or writes."""

import unicodedata

from .regions import country_choices, timezone_choices


def country_label(code):
    if not code:
        return "Not set"
    return f"{dict(country_choices())[code]} ({code})"


def select_country(current="", *, ui):
    countries = country_choices()
    groups = {}
    for code, name in countries:
        letter = unicodedata.normalize("NFKD", name)[0].upper()
        groups.setdefault(letter, []).append((code, name))
    current_group = next((letter for letter, rows in groups.items()
                          if any(code == current for code, _ in rows)), "unset")
    while True:
        group = ui.menu("Country — first letter",
                        [("unset", "Not set (use international phone numbers)")] +
                        [(letter, letter) for letter in sorted(groups)], current_group,
                        text="Choose the first letter of your country's name.",
                        help_text="Sets the default region for profile phone numbers, not your timezone.")
        if group == "unset":
            return ""
        rows = groups[group]
        choices = [(code, f"{name} ({code})") for code, name in rows] + [("back", "Back to letters")]
        default = current if any(code == current for code, _ in rows) else rows[0][0]
        selected = ui.menu("Choose your country", choices, default,
                           text="Used for phone numbers without an international country code.")
        if selected != "back":
            return selected
        current_group = group


def select_timezone(current="UTC", *, ui):
    zones = timezone_choices()
    groups = sorted({zone.split("/", 1)[0] for zone in zones if "/" in zone})
    choices = [("UTC", "UTC — Coordinated Universal Time")] + [(group, group) for group in groups]
    # Keep a retained alias visible without silently substituting a canonical zone.
    if current not in zones:
        choices.insert(0, ("keep", f"Keep current timezone: {current}"))
    default = current.split("/", 1)[0] if current in zones else "keep"
    while True:
        group = ui.menu("Timezone — region", choices, default,
                        text="Choose a region, then a city. Country and timezone are independent.")
        if group == "keep":
            return current
        if group == "UTC":
            return "UTC"
        rows = [(zone, zone.split("/", 1)[1].replace("_", " "))
                for zone in zones if zone.startswith(group + "/")]
        selected = ui.menu("Timezone — location", rows + [("back", "Back to regions")],
                           current if any(zone == current for zone, _ in rows) else rows[0][0],
                           text=f"{group}: choose the location for your timezone.")
        if selected != "back":
            return selected
        default = group
