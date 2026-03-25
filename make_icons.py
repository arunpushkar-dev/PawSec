"""
Generate PawSec PNG icons at 16/32/48/128px from a hand-drawn paw print.
Matches the SVG dashboard logo: white fluffy silhouette + pink (#F2AABD) fill,
on a white rounded-square background so it is visible in the browser toolbar.
Uses only Pillow — no external dependencies beyond pip install pillow.
"""

from pathlib import Path
from PIL import Image, ImageDraw, ImageFilter

# ─── Colours ────────────────────────────────────────────────────────────────
BG      = (255, 255, 255, 255)   # white card background (matches dashboard)
BORDER  = (240, 214, 228, 255)   # subtle rose border (#f0d6e4) so it reads on gray toolbar
PINK    = (242, 170, 189, 255)   # #F2AABD — exact match to SVG toe/pad fill
WHITE   = (255, 255, 255, 255)   # white silhouette layer (mimics SVG fluffy halo)

def draw_paw(size: int) -> Image.Image:
    """Draw the SVG-style paw on a white rounded-square card."""
    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    s    = size

    # ── White rounded-square background with rose border ────────────────────
    radius = max(2, round(s * 0.20))
    draw.rounded_rectangle(
        [0, 0, s - 1, s - 1],
        radius=radius,
        fill=BG,
        outline=BORDER,
        width=max(1, round(s * 0.04)),
    )

    def circle(cx, cy, r, fill):
        draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=fill)

    # SVG viewBox is 0–100; scale to `size`.
    def sc(v): return v / 100 * s

    # ── White silhouette layer (slightly enlarged — mimics fluffy halo) ──────
    halo = round(s * 0.025)   # expand each shape by this many px
    def hcircle(cx, cy, r):
        circle(sc(cx), sc(cy), sc(r) + halo, WHITE)
    def hellipse(cx, cy, rx, ry):
        x, y = sc(cx), sc(cy)
        draw.ellipse([x - sc(rx) - halo, y - sc(ry) - halo,
                      x + sc(rx) + halo, y + sc(ry) + halo], fill=WHITE)

    hellipse(50, 68, 34, 28)        # main palm
    hcircle(19, 47, 10.5)           # outer-left toe
    hcircle(36, 31, 12.5)           # inner-left toe
    hcircle(64, 31, 12.5)           # inner-right toe
    hcircle(81, 47, 10.5)           # outer-right toe

    # ── Pink pad fill (three-lobe trefoil matching SVG) ─────────────────────
    circle(sc(43), sc(72), sc(10), PINK)
    circle(sc(57), sc(72), sc(10), PINK)
    circle(sc(50), sc(64), sc(10), PINK)

    # ── Pink toe beans ───────────────────────────────────────────────────────
    circle(sc(19), sc(47), sc(7),   PINK)
    circle(sc(36), sc(31), sc(8.5), PINK)
    circle(sc(64), sc(31), sc(8.5), PINK)
    circle(sc(81), sc(47), sc(7),   PINK)

    return img


def save_icons(out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    for size in (16, 32, 48, 128, 256):
        img  = draw_paw(size)
        name = out_dir / f"icon{size}.png"
        img.save(name, "PNG")
        print(f"  Saved {name}")


if __name__ == "__main__":
    icons_dir = Path(__file__).parent / "pawsec-extension" / "icons"
    print("Generating PawSec icons…")
    save_icons(icons_dir)
    print("Done.")
