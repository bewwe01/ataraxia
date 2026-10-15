"""Build labelled overview sheets from design/screenshots (dev-only helper)."""
import json, os, sys
from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SHOTS = os.path.join(ROOT, "screenshots")
OUT = os.path.join(SHOTS, "overview")
FONT = "/usr/share/fonts/opentype/inter/Inter-SemiBold.otf"
os.makedirs(OUT, exist_ok=True)
manifest = json.load(open(os.path.join(SHOTS, "manifest.json")))

def sheet(style, layout, mode, cols, scale, name, routes=None):
    items = [m for m in manifest if m["style"] == style and m["layout"] == layout and m["mode"] == mode and (routes is None or m["route"] in routes)]
    ims = [Image.open(os.path.join(ROOT, m["file"])).convert("RGB") for m in items]
    w, h = ims[0].size
    tw, th = int(w * scale), int(h * scale)
    lab, pad = 30, 14
    rows = (len(ims) + cols - 1) // cols
    bg = (14, 15, 30) if mode == "dark" else (226, 228, 238)
    fg = (230, 232, 255) if mode == "dark" else (20, 22, 43)
    S = Image.new("RGB", (pad + cols * (tw + pad), pad + rows * (th + lab + pad)), bg)
    d = ImageDraw.Draw(S)
    f = ImageFont.truetype(FONT, 17)
    for i, (im, m) in enumerate(zip(ims, items)):
        x, y = pad + (i % cols) * (tw + pad), pad + (i // cols) * (th + lab + pad)
        d.text((x, y + 4), m["title"], fill=fg, font=f)
        S.paste(im.resize((tw, th), Image.LANCZOS), (x, y + lab))
    S.save(os.path.join(OUT, name + ".png"), optimize=True)
    print(name, len(ims))

for style in ("aurora", "ink"):
    for mode in ("dark", "light"):
        sheet(style, "mobile", mode, 6, 0.5, f"{style}-mobile-{mode}")
        sheet(style, "desktop", mode, 4, 0.3, f"{style}-desktop-{mode}")
        sheet(style, "tablet", mode, 5, 0.32, f"{style}-tablet-{mode}")
