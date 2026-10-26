#!/usr/bin/env python3
"""Hardens the Android project that `tauri android init` generates (review P4-4, P4-8).

* No backups: `android:allowBackup="false"`, and backup/transfer rules that exclude every
  domain, so the vault header, the database and the device secret never leave the phone
  through Auto Backup (cloud) or device-to-device transfer (Android 12+).
* FLAG_SECURE on the activity: no screenshots, screen recording or plaintext snapshot in
  the recents screen.
* The camera permission (asked for at first use), for scanning QR codes.

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
manifest.write_text(text)

# Monochrome status-bar icon for notifications.
drawable = main / "res" / "drawable"
drawable.mkdir(parents=True, exist_ok=True)
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
