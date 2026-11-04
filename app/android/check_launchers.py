#!/usr/bin/env python3
"""Checks the launcher entries of a built Android manifest (ADR-0022, review IC2-1).

Exactly five <activity-alias> launcher entries (Veil and the four disguises), only Veil's
enabled at install, and no LAUNCHER filter anywhere else, so the app has exactly one icon
on the home screen. `aapt2 dump badging` ignores aliases, so this reads the manifest XML that
the Gradle build merges. Usage: check_launchers.py <AndroidManifest.xml>...
"""
import sys
import xml.etree.ElementTree as ET

A = "{http://schemas.android.com/apk/res/android}"
LAUNCHER = "android.intent.category.LAUNCHER"
WANT = {"LaunchVeil", "LaunchCalculator", "LaunchNotes", "LaunchWeather", "LaunchClock"}


def launcher(el):
    return any(c.get(A + "name") == LAUNCHER for c in el.iter("category"))


def check(path):
    root = ET.parse(path).getroot()
    # Gradle's merger writes full names; the source manifest has relative ones (review IC3-3).
    pkg = root.get("package") or "org.veil.app"

    def fq(n):
        return pkg + n if n.startswith(".") else n

    app = root.find("application")
    if app is None:
        return "no <application>"
    aliases = {}
    for el in app:
        name = fq(el.get(A + "name") or "")
        if el.tag == "activity-alias":
            if not launcher(el):
                return f"alias {name} has no LAUNCHER filter"
            if fq(el.get(A + "targetActivity") or "") != pkg + ".MainActivity":
                return f"alias {name} does not target MainActivity"
            aliases[name] = el.get(A + "enabled", "true") != "false"
        elif launcher(el):
            return f"<{el.tag}> {name} also has a LAUNCHER filter"
    want = {f"{pkg}.{n}" for n in WANT}
    if set(aliases) != want:
        return f"aliases {sorted(aliases)}, expected {sorted(want)}"
    enabled = [n for n, on in aliases.items() if on]
    if enabled != [f"{pkg}.LaunchVeil"]:
        return f"enabled at install: {enabled}, expected only LaunchVeil"
    return None


paths = sys.argv[1:]
if not paths:
    sys.exit("check_launchers: no manifest given")
for p in paths:
    err = check(p)
    if err:
        sys.exit(f"check_launchers: {p}: {err}")
    print(f"check_launchers: {p}: one launcher entry (LaunchVeil), four disguises disabled")
