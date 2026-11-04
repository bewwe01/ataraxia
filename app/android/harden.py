#!/usr/bin/env python3
"""Hardens the Android project that `tauri android init` generates (review P4-4, P4-8).

* No backups: `android:allowBackup="false"`, and backup/transfer rules that exclude every
  domain, so the vault header, the database and the device secret never leave the phone
  through Auto Backup (cloud) or device-to-device transfer (Android 12+).
* FLAG_SECURE on the activity: no screenshots, screen recording or plaintext snapshot in
  the recents screen.
* The camera permission (asked for at first use), for scanning QR codes.
* Launcher icons: Veil's own and the disguises (ADR-0022), one `<activity-alias>` each, with
  only Veil's enabled until the user picks another in Settings.

Fails loudly if the generated project does not look as expected, so a template change in
a Tauri upgrade cannot silently drop these protections.
Usage: harden.py <src-tauri/gen/android>
"""
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
main = root / "app" / "src" / "main"
manifest = main / "AndroidManifest.xml"
text = manifest.read_text()

DOMAINS = ["root", "file", "database", "sharedpref", "external"]
excludes = "\n".join(f'    <exclude domain="{d}" path="." />' for d in DOMAINS)
xml_dir = main / "res" / "xml"
xml_dir.mkdir(parents=True, exist_ok=True)
(xml_dir / "veil_backup_rules.xml").write_text(
    f'<?xml version="1.0" encoding="utf-8"?>\n<full-backup-content>\n{excludes}\n</full-backup-content>\n'
)
(xml_dir / "veil_data_extraction_rules.xml").write_text(
    '<?xml version="1.0" encoding="utf-8"?>\n<data-extraction-rules>\n'
    f"  <cloud-backup>\n{excludes}\n  </cloud-backup>\n"
    f"  <device-transfer>\n{excludes}\n  </device-transfer>\n"
    "</data-extraction-rules>\n"
)

m = re.search(r"<application\b[^>]*>", text)
if not m:
    sys.exit("harden: no <application> element in AndroidManifest.xml")
tag = m.group(0)
for attr in ("allowBackup", "fullBackupContent", "dataExtractionRules"):
    tag = re.sub(rf'\s*android:{attr}="[^"]*"', "", tag)
tag = tag.replace(
    "<application",
    '<application android:allowBackup="false"'
    ' android:fullBackupContent="@xml/veil_backup_rules"'
    ' android:dataExtractionRules="@xml/veil_data_extraction_rules"',
    1,
)
text = text[: m.start()] + tag + text[m.end() :]

# The camera, for scanning invite and safety codes (milestone 2). Frames are decoded in the
# webview and never leave the phone. Not required: Veil installs on phones without one.
PERMS = [
    '<uses-permission android:name="android.permission.CAMERA" />',
    # The microphone, for voice notes (milestone 3), asked for at first use.
    '<uses-permission android:name="android.permission.RECORD_AUDIO" />',
    '<uses-permission android:name="android.permission.MODIFY_AUDIO_SETTINGS" />',
    '<uses-feature android:name="android.hardware.microphone" android:required="false" />',
    # Content-free notifications and the opt-in background connection (milestone 4).
    '<uses-permission android:name="android.permission.POST_NOTIFICATIONS" />',
    '<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />',
    '<uses-permission android:name="android.permission.FOREGROUND_SERVICE_REMOTE_MESSAGING" />',
    '<uses-feature android:name="android.hardware.camera" android:required="false" />',
]
for line in PERMS:
    if line not in text:
        text = text.replace("<application", f"{line}\n    <application", 1)
# The background-connection service (only started if the user turns it on).
SERVICE = '<service android:name=".VeilService" android:exported="false" android:foregroundServiceType="remoteMessaging" />'
if SERVICE not in text:
    if "</application>" not in text:
        sys.exit("harden: no </application> in AndroidManifest.xml")
    text = text.replace("</application>", f"    {SERVICE}\n    </application>", 1)

# Disguised launcher icons (ADR-0022). The launcher entry moves from MainActivity to one
# activity-alias per icon; the plugin (VeilIcons) enables exactly one of them. Original,
# generic glyphs on a 108 dp adaptive-icon canvas, inside the 66 dp safe zone.
DISGUISES = {
    # name: (label, background, [(fill, path, even_odd)])
    "calculator": ("Calculator", "#FF455A64", [("#FFFFFFFF",
        "M40,28h28a4,4 0 0 1 4,4v44a4,4 0 0 1 -4,4h-28a4,4 0 0 1 -4,-4v-44a4,4 0 0 1 4,-4z"
        " M41,33h26v9h-26z"
        " M41,47h7v7h-7z M50.5,47h7v7h-7z M60,47h7v7h-7z"
        " M41,57h7v7h-7z M50.5,57h7v7h-7z M60,57h7v7h-7z"
        " M41,67h7v7h-7z M50.5,67h7v7h-7z M60,67h7v7h-7z", True)]),
    "notes": ("Notes", "#FFF9A825", [("#FFFFFFFF",
        "M40,28h28a4,4 0 0 1 4,4v44a4,4 0 0 1 -4,4h-28a4,4 0 0 1 -4,-4v-44a4,4 0 0 1 4,-4z"
        " M43,38h22v3h-22z M43,47h22v3h-22z M43,56h22v3h-22z M43,65h14v3h-14z", True)]),
    "weather": ("Weather", "#FF1E88E5", [
        ("#FFFFD54F", "M34,46a10,10 0 1 0 20,0a10,10 0 1 0 -20,0z", False),
        ("#FFFFFFFF",
         "M37,64a9,9 0 1 0 18,0a9,9 0 1 0 -18,0z M49,60a11,11 0 1 0 22,0a11,11 0 1 0 -22,0z"
         " M61,68a7,7 0 1 0 14,0a7,7 0 1 0 -14,0z M42,66h26v9h-26z", False)]),
    "clock": ("Clock", "#FF37474F", [("#FFFFFFFF",
        "M30,54a24,24 0 1 0 48,0a24,24 0 1 0 -48,0z M34,54a20,20 0 1 0 40,0a20,20 0 1 0 -40,0z", True),
        ("#FFFFFFFF", "M52,40h4v16h-4z M54,52h11v4h-11z", False)]),
}

res = main / "res"
for d in ("drawable", "mipmap-anydpi", "mipmap-anydpi-v26", "values"):
    (res / d).mkdir(parents=True, exist_ok=True)


def vector(paths, mono=False):
    body = "".join(
        f'  <path android:fillColor="{"#FFFFFFFF" if mono else fill}"'
        + (' android:fillType="evenOdd"' if even else "")
        + f' android:pathData="{path}"/>\n'
        for fill, path, even in paths
    )
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<vector xmlns:android="http://schemas.android.com/apk/res/android" android:width="108dp" '
        'android:height="108dp" android:viewportWidth="108" android:viewportHeight="108">\n'
        f"{body}</vector>\n"
    )


colors = []
strings = []
for name, (label, bg, paths) in DISGUISES.items():
    (res / "drawable" / f"veil_disguise_{name}_fg.xml").write_text(vector(paths))
    (res / "drawable" / f"veil_disguise_{name}_mono.xml").write_text(vector(paths, mono=True))
    colors.append(f'  <color name="veil_disguise_{name}_bg">{bg}</color>')
    strings.append(f'  <string name="veil_disguise_{name}">{label}</string>')
    # Android 8+: an adaptive icon (and a themed one on Android 13+).
    (res / "mipmap-anydpi-v26" / f"veil_disguise_{name}.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">\n'
        f'  <background android:drawable="@color/veil_disguise_{name}_bg"/>\n'
        f'  <foreground android:drawable="@drawable/veil_disguise_{name}_fg"/>\n'
        f'  <monochrome android:drawable="@drawable/veil_disguise_{name}_mono"/>\n'
        "</adaptive-icon>\n"
    )
    # Older Android: the glyph on a round background.
    (res / "mipmap-anydpi" / f"veil_disguise_{name}.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<layer-list xmlns:android="http://schemas.android.com/apk/res/android">\n'
        f'  <item><shape android:shape="oval"><solid android:color="@color/veil_disguise_{name}_bg"/></shape></item>\n'
        f'  <item android:drawable="@drawable/veil_disguise_{name}_fg"/>\n'
        "</layer-list>\n"
    )
(res / "values" / "veil_disguise.xml").write_text(
    '<?xml version="1.0" encoding="utf-8"?>\n<resources>\n'
    + "\n".join(colors + strings)
    + "\n</resources>\n"
)

act_m = re.search(r'<activity\b[^>]*android:name="\.MainActivity"[^>]*>.*?</activity>', text, re.S)
if not act_m:
    sys.exit("harden: no MainActivity <activity> in AndroidManifest.xml")
act_xml = act_m.group(0)
launcher = re.search(r"<intent-filter\b[^>]*>(?:(?!</intent-filter>).)*android\.intent\.category\.LAUNCHER.*?</intent-filter>", act_xml, re.S)
if not launcher:
    sys.exit("harden: MainActivity has no LAUNCHER intent-filter")
app_tag = re.search(r"<application\b[^>]*>", text)
icon = re.search(r'android:icon="([^"]+)"', app_tag.group(0)) if app_tag else None
if not icon:
    sys.exit("harden: <application> has no android:icon")
round_icon = re.search(r'android:roundIcon="([^"]+)"', app_tag.group(0))
FILTER = (
    "<intent-filter>"
    '<action android:name="android.intent.action.MAIN" />'
    '<category android:name="android.intent.category.LAUNCHER" />'
    "</intent-filter>"
)


def alias(name, enabled, icon_ref, round_ref, label_ref):
    rnd = f' android:roundIcon="{round_ref}"' if round_ref else ""
    return (
        f'\n        <activity-alias android:name=".Launch{name.capitalize()}" android:targetActivity=".MainActivity"'
        f' android:enabled="{"true" if enabled else "false"}" android:exported="true"'
        f' android:icon="{icon_ref}"{rnd} android:label="{label_ref}">{FILTER}</activity-alias>'
    )


aliases = alias("veil", True, icon.group(1), round_icon.group(1) if round_icon else None, "@string/app_name")
for name in DISGUISES:
    ref = f"@mipmap/veil_disguise_{name}"
    aliases += alias(name, False, ref, ref, f"@string/veil_disguise_{name}")
new_act = act_xml.replace(launcher.group(0), "", 1)
text = text.replace(act_xml, new_act + aliases, 1)
if text.count("android.intent.category.LAUNCHER") != 1 + len(DISGUISES):
    sys.exit("harden: unexpected LAUNCHER entries after adding the icon aliases")
if 'name="app_name"' not in "".join(p.read_text() for p in (res / "values").glob("*.xml")):
    sys.exit("harden: no @string/app_name in res/values")
manifest.write_text(text)

# Monochrome status-bar icon for notifications.
drawable = main / "res" / "drawable"
drawable.mkdir(parents=True, exist_ok=True)
# A plain dot for notifications while a disguise is on.
(drawable / "ic_stat_dot.xml").write_text(
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<vector xmlns:android="http://schemas.android.com/apk/res/android" android:width="24dp" '
    'android:height="24dp" android:viewportWidth="24" android:viewportHeight="24">\n'
    '  <path android:fillColor="#FFFFFFFF" android:pathData="M6,12a6,6 0 1 0 12,0a6,6 0 1 0 -12,0z"/>\n'
    "</vector>\n"
)
(drawable / "ic_stat_veil.xml").write_text(
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<vector xmlns:android="http://schemas.android.com/apk/res/android" android:width="24dp" '
    'android:height="24dp" android:viewportWidth="24" android:viewportHeight="24">\n'
    '  <path android:fillColor="#FFFFFFFF" android:pathData="M12,2L4,5v6c0,5 3.4,9.7 8,11 '
    '4.6,-1.3 8,-6 8,-11V5L12,2zM12,7a2.5,2.5 0,1 1,0 5a2.5,2.5 0,1 1,0 -5z"/>\n'
    "</vector>\n"
)

acts = list(main.rglob("MainActivity.kt"))
if len(acts) != 1:
    sys.exit(f"harden: expected one MainActivity.kt, found {len(acts)}")
act = acts[0]
src = act.read_text()
pkg = re.search(r"^package\s+([\w.]+)", src, re.M)
if not pkg or "TauriActivity()" not in src:
    sys.exit("harden: MainActivity.kt does not look like the Tauri template")
pkg = pkg.group(1)
# app/src-tauri/src/lib.rs registers the plugin under this package (ANDROID_PACKAGE).
if pkg != "org.veil.app":
    sys.exit(f"harden: unexpected Android package {pkg}; update ANDROID_PACKAGE in lib.rs")
edge = "enableEdgeToEdge" in src
# The app draws edge to edge (Android 15+ enforces it), but the webview gets no reliable CSS
# safe-area insets, so pad the content view by the system bars, the display cutout and the
# keyboard. The page then always sits inside the visible area, and the composer stays above
# the keyboard.
act.write_text(
    f"package {pkg}\n\n"
    "import android.os.Bundle\n"
    "import android.view.View\n"
    "import android.view.WindowManager\n"
    + ("import androidx.activity.enableEdgeToEdge\n" if edge else "")
    + "import androidx.core.view.ViewCompat\n"
    "import androidx.core.view.WindowInsetsCompat\n"
    "\n// Generated by app/android/harden.py: FLAG_SECURE (lifted only if the user allows\n"
    "// screenshots in Settings) and system-bar/keyboard padding.\n"
    "class MainActivity : TauriActivity() {\n"
    "  override fun onCreate(savedInstanceState: Bundle?) {\n"
    "    window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)\n"
    + ("    enableEdgeToEdge()\n" if edge else "")
    + "    super.onCreate(savedInstanceState)\n"
    "    window.decorView.setBackgroundColor(0xFF0B0D22.toInt())\n"
    "    val root = findViewById<View>(android.R.id.content)\n"
    "    ViewCompat.setOnApplyWindowInsetsListener(root) { v, insets ->\n"
    "      val b = insets.getInsets(\n"
    "        WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout() or WindowInsetsCompat.Type.ime()\n"
    "      )\n"
    "      v.setPadding(b.left, b.top, b.right, b.bottom)\n"
    "      WindowInsetsCompat.CONSUMED\n"
    "    }\n"
    "  }\n"
    "}\n"
)

# The native plugin (biometrics, screenshot setting, bar colours), in the app's own package.
plugin_src = pathlib.Path(__file__).with_name("VeilNativePlugin.kt").read_text()
(act.parent / "VeilNativePlugin.kt").write_text(plugin_src.replace("__PACKAGE__", pkg))

gradle = root / "app" / "build.gradle.kts"
g = gradle.read_text()
dep = 'implementation("androidx.biometric:biometric:1.1.0")'
if dep not in g:
    m = re.search(r"^dependencies\s*\{", g, re.M)
    if not m:
        sys.exit("harden: no dependencies block in app/build.gradle.kts")
    g = g[: m.end()] + "\n    " + dep + g[m.end() :]
    gradle.write_text(g)

print(f"harden: manifest patched; {act.relative_to(root)}: FLAG_SECURE + insets (edge-to-edge kept: {edge}); plugin + biometric dependency added")
