"""Small terminal UI using FreeBSD's base bsddialog, with a plain fallback.

Dialogs inherit stdin/stdout (the foreground terminal). Only their documented
response descriptor, stderr, is captured. Secrets never enter a subprocess.
"""

import builtins
import getpass
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
import warnings


# Hand-refined from assets/branding/NextcloudOnFreeBSD.png; no image at runtime.
_BANNER = r"""                 ,/                \.
                / (   .------.    ) \
               (   `-'        `--'   )       ^  ^  ^
                `-.   .--.  .--.  .-'        |  |  |
                  /  /  o| /  o|   \         |  |  |
                 |   \___/ \___/    |        \__|__/
                 |           _      |           |
                  \    `----'      /         .--|.
       .---->      `-.          .-'         /  _| )
     .'  .-'     .---'----------'---.    .--'  / |/
    /  .'       /    .----.          `--'   .-'  |
   (  (        (___ / / / /) .------------'      |
    \  `--.        `-'-'-' .--------.            |
     `----.\   .----.   .'          '.   .----. |
             .' .--. `./    .----.    \.' .--. '.
            (  (    )     /      \      (    )  )
             '. '--' .'   \      /    '. '--' .'
               '----'  '.  '----'  .'   '----'
                 .-------`--------'-------.
                 '---NextcloudOnFreeBSD----'"""
_BANNER_COMPACT = r"\^/ (o)-O-(o) NextcloudOnFreeBSD"
# Only package a theme generated and round-trip verified by the target binary.
_THEME = Path(__file__).resolve().parents[1] / "resources/ui/brand.theme"


def _banner_view(columns, rows, accent=None):
    """Static ASCII with one shared margin; never wrap or sanitize its spacing."""
    art = _BANNER if columns >= 60 and rows >= 35 else _BANNER_COMPACT
    if columns < len(_BANNER_COMPACT):
        art = 'NextcloudOnFreeBSD'
    lines = art.splitlines()
    margin = ' ' * max(0, (columns - max(map(len, lines))) // 2)
    result = []
    for line in lines:
        if accent:
            # Keep the contiguous rendered wordmark readable in the user's
            # foreground, with only FreeBSD in the supplied brand green.
            line = line.replace('NextcloudOnFreeBSD', '\033[0mNextcloudOn' + f'\033[{accent}mFreeBSD')
        result.append(margin + _emphasis(line, accent, bool(accent)))
    return '\n' + '\n'.join(result) + '\n'


def _interactive(stream):
    return (sys.stdin.isatty() and sys.stdout.isatty() and stream.isatty()
            and os.environ.get("TERM", "") not in ("", "dumb", "unknown"))


def _safe(text):
    """Escape terminal controls in display text, never in input/returned values."""
    return "".join(char if char == "\n" or not unicodedata.category(char).startswith("C")
                   else repr(char)[1:-1] for char in str(text)).expandtabs(4)


def _cells(text):
    return sum(0 if unicodedata.combining(char) else
               2 if unicodedata.east_asian_width(char) in ("W", "F") else 1 for char in text)


def _wrapped(text, width):
    """Wrap existing lines at spaces/cell boundaries without dropping long values."""
    lines = []
    for line in _safe(text).split("\n"):
        indent = line[:len(line) - len(line.lstrip())]
        indent = indent if len(indent) < width // 2 else ""
        while _cells(line) > width:
            used, cut = 0, 0
            for char in line:
                size = _cells(char)
                if used + size > width:
                    break
                used += size
                cut += 1
            space = line.rfind(" ", len(indent) + 1, cut + 1)
            cut = space if space > 0 else max(1, cut)
            lines.append(line[:cut].rstrip())
            line = indent + line[cut:].lstrip()
        lines.append(line)
    return lines


def _emphasis(text, code, color):
    return f"\033[{code}m{text}\033[0m" if color else text


def _menu_view(title, choices, default, columns, color):
    """One ordered choice source for every width; no input or selection state."""
    width = max(4, min(96, columns - 4)) if columns >= 60 else max(4, columns)
    framed = columns >= 60
    inner = width - 4 if framed else width
    rows = []
    for number, (key, label) in enumerate(choices, 1):
        text = f"  {number}. {label}" + (" (default)" if key == default else "")
        rows.extend((line, key == default) for line in _wrapped(text, inner))
    rows.extend((line, False) for line in _wrapped("  0. Cancel", inner))
    margin = " " * ((columns - width) // 2) if framed else ""
    if not framed:
        return "\n" + "\n".join([*_wrapped(title, inner), *(line for line, _ in rows)])
    border = margin + "+" + "-" * (width - 2) + "+"
    result = ["", _emphasis(border, "36", color)]
    for line in _wrapped(title, inner):
        result.append(margin + "| " + _emphasis(line, "1;36", color) + " " * (inner - _cells(line)) + " |")
    result.append(border)
    for line, selected in rows:
        result.append(margin + "| " + _emphasis(line, "1;36", color and selected) + " " * (inner - _cells(line)) + " |")
    result.append(_emphasis(border, "36", color))
    return "\n".join(result)


def _text_view(text, columns, color):
    """Reflow only already-emitted human text; headless callers bypass this."""
    width = max(4, min(96, columns - 4)) if columns >= 60 else max(4, columns)
    margin = " " * ((columns - width) // 2) if columns >= 60 else ""
    lines = _wrapped(text, width)
    heading = str(text).startswith("\n") or (len(lines) > 1 and lines[0].endswith(":"))
    first = next((index for index, line in enumerate(lines) if line), None)
    # Only emphasize facts already printed by the caller; never infer a stage
    # outcome from its number, elapsed time or absence of an error.
    public = _safe(text).lstrip()
    tone = "1;36" if heading or re.match(r"\[[0-9]+/[0-9]+\]", public) else None
    if public.startswith(("Error:", "Invalid value:", "Preflight failed:")):
        tone = "31"
    elif public.startswith(("Stopped.", "NOTICE:", "ATTENTION:", "Configuration needs correction:")):
        tone = "33"
    elif public.startswith("Installer checks passed."):
        tone = "32"
    result = []
    for index, line in enumerate(lines):
        result.append(margin + _emphasis(line, tone, color and tone is not None and index == first) if line else "")
        if heading and index == first and len(lines) <= 2:
            result.append(margin + "-" * min(width, _cells(line)))
    return "\n".join(result)


class TerminalUI:
    def __init__(self, plain=False):
        self.dialog = None
        if plain or os.environ.get("CLOUD_INSTALLER_PLAIN") == "1":
            return
        term = os.environ.get("TERM", "")
        if not term or term in ("dumb", "unknown") or not (sys.stdin.isatty() and sys.stdout.isatty()):
            return
        executable = shutil.which("bsddialog")
        if not executable:
            return
        try:
            import curses
            curses.setupterm(term=term, fd=sys.stdout.fileno())
            size = shutil.get_terminal_size((80, 24))
            if size.columns < 76 or size.lines < 22:
                return
        except (ImportError, OSError, ValueError):
            return
        except curses.error:
            return
        self.dialog = executable

    @staticmethod
    def welcome():
        """Decorate only the interactive welcome; redirected/CLI bytes stay put."""
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            return
        accent = None
        if _interactive(sys.stdout) and not os.environ.get('NO_COLOR'):
            if os.environ.get('COLORTERM', '').lower() in ('truecolor', '24bit') or os.environ.get('TERM', '').endswith('-direct'):
                accent = '38;2;186;214;96'  # #BAD660
            elif '256color' in os.environ.get('TERM', ''):
                accent = '38;5;149'
            else:
                accent = '32'
        size = shutil.get_terminal_size((80, 24))
        print(_banner_view(size.columns, size.lines, accent), flush=True)

    def _dialog(self, title, arguments, *, negative=False, raw=False):
        if not self.dialog:
            return None
        # Recheck every screen; curses itself handles resize during a widget.
        size = shutil.get_terminal_size((80, 24))
        if size.columns < 76 or size.lines < 22:
            return None
        # Oversized explanations cannot scroll inside ordinary widgets. Fall
        # back for this screen only, retaining every warning and input value;
        # do not discover predictable geometry errors by invoking curses (which
        # would disable native rendering for the rest of this session).
        widgets = {"--menu", "--form", "--checklist", "--textbox", "--yesno", "--inputbox"}
        widget_index = next((index for index, argument in enumerate(arguments[:-1])
                             if argument in widgets and arguments[index + 1] == "--"), None)
        if widget_index is not None:
            body_index = widget_index + 2
            widget = arguments[widget_index]
            if widget != "--textbox" and self._body_space(arguments[body_index]) < 1:
                return None
        if _cells(_safe(title)) > self._width() - 6:
            return None
        appearance = []
        if os.environ.get("CLOUD_INSTALLER_ASCII_LINES") == "1":
            appearance += ["--ascii-lines"]
        if os.environ.get("NO_COLOR"):
            appearance += ["--theme", "blackwhite"]
        elif _THEME.is_file():
            appearance += ["--load-theme", str(_THEME)]
        command = [self.dialog, "--alternate-screen", "--text-unchanged", *appearance,
                   "--backtitle", _BANNER_COMPACT, "--title", _safe(title),
                   "--output-fd", "2", "--ok-exit-code", "0", "--cancel-exit-code", "1",
                   "--esc-exit-code", "5", "--error-exit-code", "255", *arguments]
        try:
            # Capturing stdout would hide the curses display. bsddialog(1)
            # documents stderr as its response channel, made explicit above.
            result = subprocess.run(command, stderr=subprocess.PIPE, text=True, check=False, shell=False)
            if result.returncode == 255 and "--load-theme" in appearance:
                # Optional branding must not make input unavailable. Retry only
                # the explicit error status, never a cancellation or approval.
                index = command.index("--load-theme")
                fallback_command = command[:index] + command[index + 2:]
                result = subprocess.run(fallback_command, stderr=subprocess.PIPE, text=True, check=False, shell=False)
        except OSError:
            result = None
        if result is not None:
            if result.returncode == 0:
                return result.stderr if raw else result.stderr.rstrip("\n")
            if result.returncode == 1 and negative:
                return False
            if result.returncode in (1, 5, 130, -2):
                raise KeyboardInterrupt
        self.dialog = None
        self.message("Dialog unavailable; continuing with numbered terminal prompts.")
        return None

    @staticmethod
    def _read(prompt):
        try:
            value = builtins.input(prompt)
        except EOFError:
            raise KeyboardInterrupt from None
        if value == "\x1b":
            raise KeyboardInterrupt
        return value

    @staticmethod
    def _width():
        return max(4, min(96, shutil.get_terminal_size((80, 24)).columns - 4))

    @staticmethod
    def _help(help_text):
        return ["--hmsg", _safe(help_text)] if help_text else []

    def _body_space(self, text):
        """Rows left after complete explanatory text and native chrome."""
        lines = len(_wrapped(text, max(4, self._width() - 6))) if text else 0
        return shutil.get_terminal_size((80, 24)).lines - lines - 10

    def _visible_rows(self, text, count):
        # Reserve backtitle, frame, text/list separation and buttons. Native
        # widgets scroll the remaining rows rather than growing off-screen.
        # Zero is never sent when the body cannot fit: _dialog performs the
        # same check just before invocation and chooses a screen-local fallback.
        return str(max(0, min(count, self._body_space(text))))

    def menu(self, title, choices, default=None, text="", help_text=""):
        choices = [(str(key), str(label)) for key, label in choices]
        keys = [key for key, _ in choices]
        if not keys or len(set(keys)) != len(keys) or any(not key or key == "0" for key in keys):
            raise ValueError("A menu needs distinct nonempty keys other than 0")
        if default is not None and default not in keys:
            raise ValueError("Menu default is not a choice")
        arguments = ["--default-item", default] if default is not None else []
        arguments += self._help(help_text)
        arguments += ["--menu", "--", _safe(text), "0", str(self._width()), self._visible_rows(text, len(choices))]
        arguments += [part for key, label in choices for part in (key, _safe(label))]
        response = self._dialog(title, arguments)
        if response is not None:
            if response not in keys:
                raise ValueError("Dialog returned an unknown menu choice")
            return response
        if _interactive(sys.stdout):
            print(_menu_view(title, choices, default, shutil.get_terminal_size((80, 24)).columns,
                             not os.environ.get("NO_COLOR")), flush=True)
        else:
            self.message("\n" + str(title))
            for number, (key, label) in enumerate(choices, 1):
                marker = " (default)" if key == default else ""
                self.message(f"  {number}. {label}{marker}")
            self.message("  0. Cancel")
        if text:
            self.message(_safe(text))
        if help_text:
            self.message(_safe(help_text))
        while True:
            response = self._read("Selection: ").strip()
            if response == "0":
                raise KeyboardInterrupt
            if not response and default is not None:
                return default
            if response.isdecimal() and 1 <= int(response) <= len(keys):
                return keys[int(response) - 1]
            if response in keys:
                return response
            self.message("Enter a listed number or choice; 0 cancels.")

    def form(self, title, fields, *, text="", help_text=""):
        """Collect public strings; callers own conversion and draft redisplay.

        Native fields are prefilled and an erased field stays empty. In plain
        mode Enter keeps the displayed default. A lone '-' explicitly clears a
        field in either mode. No trimming or display sanitization alters values.
        Read-only context belongs in text, never in the returned field list.
        """
        fields = [(str(key), str(label), str(value)) for key, label, value in fields]
        keys = [key for key, _, _ in fields]
        if not keys or len(set(keys)) != len(keys) or any(not key for key in keys):
            raise ValueError("A form needs distinct nonempty field keys")
        width = self._width()
        label_width = max(4, min(max(_cells(_safe(label)) for _, label, _ in fields), width // 2 - 4))
        field_width = max(8, width - label_width - 8)
        instructions = "Enter keeps prefilled values; - clears a field."
        body = "\n\n".join(part for part in (text, instructions) if part)
        args = [*self._help(help_text), "--ok-label", "Continue", "--form", "--", _safe(body),
                "0", str(width), self._visible_rows(body, len(fields))]
        for row, (_, label, value) in enumerate(fields):
            # Labels may wrap separately from fields; never truncate input.
            display_label = _safe(label)
            if (_cells(display_label) > label_width and self.dialog and width >= 72
                    and shutil.get_terminal_size((80, 24)).lines >= 22):
                # Two-row fields retain complete labels without overlapping input.
                return self._stacked_form(title, fields, text=text, help_text=help_text)
            display_value = _safe(value).replace("\n", "\\n")
            args += [display_label, str(row), "0", display_value, str(row), str(label_width + 2),
                     str(field_width), str(max(4096, len(display_value)))]
        response = self._dialog(title, args, raw=True)
        if response is not None:
            # bsddialog terminates EACH editable field with one newline. Remove
            # that terminator only, preserving empty last fields and all spaces.
            values = response[:-1].split("\n") if response.endswith("\n") else []
            if len(values) != len(keys):
                raise ValueError("Dialog returned a malformed form field count")
            return {key: "" if value == "-" else original if value == _safe(original).replace("\n", "\\n") else value
                    for (key, _, original), value in zip(fields, values)}
        self.message(_safe(title))
        if text:
            self.message(_safe(text))
        self.message("Enter keeps the displayed value; - clears a field.")
        if help_text:
            self.message(_safe(help_text))
        values = {}
        for key, label, default in fields:
            suffix = f" [{_safe(default)}]" if default else ""
            value = self._read(f"{_safe(label)}{suffix}: ")
            values[key] = "" if value == "-" else value if value else default
        return values

    def _stacked_form(self, title, fields, *, text, help_text):
        # Avoid a second layout engine: full labels remain visible in context;
        # short numbered labels map unambiguously to their original keys.
        context = "\n".join(f"{index}. {label}" for index, (_, label, _) in enumerate(fields, 1))
        return self.form(title, [(key, str(index), value) for index, (key, _, value) in enumerate(fields, 1)],
                         text="\n\n".join(part for part in (text, context) if part), help_text=help_text)

    def checklist(self, title, choices, selected=(), *, text="", help_text=""):
        choices = [(str(key), str(label)) for key, label in choices]
        keys = [key for key, _ in choices]
        selected = set(selected)
        if (not keys or len(set(keys)) != len(keys) or
                any(not key or key == "0" or "\n" in key for key in keys) or not selected <= set(keys)):
            raise ValueError("A checklist needs distinct keys and known selections")
        args = [*self._help(help_text), "--separate-output", "--ok-label", "Continue", "--checklist", "--",
                _safe(text), "0", str(self._width()), self._visible_rows(text, len(choices))]
        args += [part for key, label in choices for part in (key, _safe(label), "on" if key in selected else "off")]
        response = self._dialog(title, args, raw=True)
        if response is not None:
            values = response.splitlines()
            if len(set(values)) != len(values) or not set(values) <= set(keys):
                raise ValueError("Dialog returned unknown or duplicate checklist choices")
            return [key for key in keys if key in values]
        self.message(_safe(title))
        if text:
            self.message(_safe(text))
        if help_text:
            self.message(_safe(help_text))
        while True:
            for number, (key, label) in enumerate(choices, 1):
                self.message(f"  {number}. [{'x' if key in selected else ' '}] {_safe(label)}")
            answer = self._read("Toggle number/key; Enter continues; none clears; 0 cancels: ").strip()
            if answer == "0":
                raise KeyboardInterrupt
            if not answer:
                return [key for key in keys if key in selected]
            if answer == "none":
                selected.clear()
                continue
            key = keys[int(answer) - 1] if answer.isdecimal() and 1 <= int(answer) <= len(keys) else answer
            if key in keys:
                selected.symmetric_difference_update((key,))
            else:
                self.message("Enter a listed number or key.")

    def details(self, title, text):
        """Scrollable public information; no configuration or secret storage."""
        if self.dialog:
            with tempfile.TemporaryDirectory(prefix="cloud-installer-ui-") as directory:
                path = Path(directory) / "details.txt"
                path.write_text(_safe(text), encoding="utf-8")
                response = self._dialog(title, ["--textbox", "--", str(path), "0", str(self._width())])
            if response is not None:
                return
        self.message(_safe(title))
        self.message(_safe(text))

    def authorize_apply(self, text):
        """Explicit APPLY button; errors/fallback never imply authorization."""
        response = self._dialog("Apply installation", ["--default-no", "--yes-label", "APPLY",
                                "--no-label", "Cancel", "--yesno", "--", _safe(text), "0", str(self._width())],
                                negative=True)
        if response is not None:
            return response is not False
        self.message(_safe(text))
        return self._read("Type APPLY to proceed: ") == "APPLY"

    def input(self, label, default=""):
        default = str(default)
        response = self._dialog(label, ["--inputbox", "--", _safe(label), "0", "0", default])
        if response is not None:
            return response.strip()
        suffix = f" [{default}]" if default else ""
        return self._read(f"{label}{suffix}: ").strip() or default

    def confirm(self, message):
        response = self._dialog("Confirmation", ["--default-no", "--yesno", "--", _safe(message), "0", "0"], negative=True)
        if response is not None:
            return response is not False
        while True:
            answer = self._read(str(message) + " [y/N]: ").strip().lower()
            if answer in ("y", "yes"):
                return True
            if answer in ("", "n", "no"):
                return False
            self.message("Enter yes or no; Ctrl-C cancels.")

    def secret(self, label):
        # Treat getpass's echoing fallback as an error, rather than exposing a
        # password when a controlling terminal cannot be opened.
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            try:
                return getpass.getpass(str(label) + ": ")
            except EOFError:
                raise KeyboardInterrupt from None
            except getpass.GetPassWarning:
                raise ValueError("A terminal with hidden input is required for passwords") from None

    @staticmethod
    def message(text, *, file=None):
        stream = sys.stdout if file is None else file
        if _interactive(stream):
            text = _text_view(text, shutil.get_terminal_size((80, 24)).columns, not os.environ.get("NO_COLOR"))
        if file is None:
            print(text, flush=True)
        else:
            print(text, file=file)

    def progress(self, current, total, label):
        """Present existing step counts, not completion claims or percentages."""
        total = max(0, int(total))
        current = min(total, max(0, int(current)))
        if _interactive(sys.stdout):
            self.message(f"NextcloudOnFreeBSD\nStep {current} of {total} — {label}")
        else:
            self.message(f"[{current}/{total}] {label}")
