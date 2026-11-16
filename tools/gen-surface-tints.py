"""Generate accent-tinted surface ramps for Kestrel.

The default (blue) accent keeps a pure neutral ramp: black, white and grey only.
Every other accent tints the surface layers toward itself by a few percent, so a
rose vault feels warm and a violet vault feels violet without hurting legibility.

Mixing happens in linear light (not sRGB) so the perceived lightness of each
layer stays put and only the hue moves.

Usage:
    python tools/gen-surface-tints.py --css src/styles/tokens.css \
        --out src/styles/tints.css
"""
import argparse
import colorsys
import re
import sys

# Neutral ramps (equal RGB channels): the blue default.
NEUTRAL = {
    "light": {
        "--ground": "#f6f6f6",
        "--surface": "#ffffff",
        "--sidebar": "#efefef",
        "--list": "#f8f8f8",
        "--sunken": "#e9e9e9",
        "--input": "#ffffff",
        "--hover": "#eeeeee",
        "--selected": "#e7e7e7",
        "--line": "#e4e4e4",
        "--line-strong": "#cdcdcd",
    },
    "dark": {
        "--ground": "#000000",
        "--surface": "#101010",
        "--sidebar": "#080808",
        "--list": "#0a0a0a",
        "--sunken": "#161616",
        "--input": "#121212",
        "--hover": "#181818",
        "--selected": "#1e1e1e",
        "--line": "#222222",
        "--line-strong": "#303030",
    },
}

# How much of the accent's saturation each layer keeps. The hue is taken from
# the accent and the lightness is taken from the neutral ramp, so a layer can
# never lose contrast or drift lighter/darker — only its temperature moves.
TINT = {
    "light": {
        "--ground": 0.16,
        "--surface": 0.09,
        "--sidebar": 0.22,
        "--list": 0.18,
        "--sunken": 0.26,
        "--input": 0.08,
        "--hover": 0.26,
        "--selected": 0.34,
        "--line": 0.30,
        "--line-strong": 0.38,
    },
    "dark": {
        # Pure-black ground never takes a hue (an OLED pixel must stay off);
        # raised layers carry a muted trace of the accent instead.
        "--ground": 0.0,
        "--surface": 0.05,
        "--sidebar": 0.08,
        "--list": 0.06,
        "--sunken": 0.09,
        "--input": 0.04,
        "--hover": 0.09,
        "--selected": 0.12,
        "--line": 0.09,
        "--line-strong": 0.14,
    },
}

ACCENTS = ["teal", "green", "amber", "rose", "violet"]  # blue = neutral


def parse_blocks(css: str):
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    blocks = []
    for match in re.finditer(r"([^{}]+)\{([^{}]*)\}", css):
        selector = " ".join(match.group(1).split())
        decls = {}
        for decl in match.group(2).split(";"):
            if ":" not in decl:
                continue
            name, value = decl.split(":", 1)
            name = name.strip()
            if name.startswith("--"):
                decls[name] = value.strip()
        if decls:
            blocks.append((selector, decls))
    return blocks


def accent_colour(blocks, theme, accent):
    """Resolve --accent for one (theme, accent) pair using cascade order."""
    value = None
    for selector, decls in blocks:
        if ":root" not in selector:
            continue
        want_theme = re.search(r'data-theme=["\'](light|dark)["\']', selector)
        want_accent = re.search(r'data-accent=["\']([a-z-]+)["\']', selector)
        if want_theme and want_theme.group(1) != theme:
            continue
        if want_accent and want_accent.group(1) != accent:
            continue
        if "--accent" in decls:
            value = decls["--accent"]
    if value is None:
        raise SystemExit(f"no --accent for {theme}/{accent}")
    return value


def hex_to_rgb(value):
    h = value.strip().lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    return tuple(int(h[i : i + 2], 16) for i in (0, 2, 4))


def rgb_to_hex(rgb):
    return "#" + "".join(f"{c:02x}" for c in rgb)


def to_linear(c):
    c = c / 255
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def to_srgb(c):
    v = 12.92 * c if c <= 0.0031308 else 1.055 * c ** (1 / 2.4) - 0.055
    return max(0, min(255, round(v * 255)))


def tint(neutral_hex, accent_hex, factor):
    """Keep the neutral layer's lightness, borrow the accent's hue, and take a
    fraction of its saturation. Contrast therefore stays put while temperature
    changes — exactly what a subtle surface tint should do."""
    _, lightness, _ = colorsys.rgb_to_hls(*(c / 255 for c in hex_to_rgb(neutral_hex)))
    accent_hue, _, accent_sat = colorsys.rgb_to_hls(*(c / 255 for c in hex_to_rgb(accent_hex)))
    r, g, b = colorsys.hls_to_rgb(accent_hue, lightness, accent_sat * factor)
    return rgb_to_hex((round(r * 255), round(g * 255), round(b * 255)))


def luminance(rgb):
    r, g, b = (to_linear(c) for c in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a_hex, b_hex):
    la, lb = luminance(hex_to_rgb(a_hex)), luminance(hex_to_rgb(b_hex))
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--css", default="src/styles/tokens.css")
    parser.add_argument("--out", default="src/styles/tints.css")
    args = parser.parse_args()

    blocks = parse_blocks(open(args.css, encoding="utf-8").read())
    lines = [
        "/* Generated by tools/gen-surface-tints.py — do not edit by hand.",
        "   Blue (the default accent) is the pure neutral ramp in tokens.css.",
        "   Other accents tint the surface stack in linear light so only hue",
        "   moves; lightness stays where the neutral ramp put it. */",
        "",
    ]

    report = []
    for theme in ("light", "dark"):
        for accent in ACCENTS:
            accent_hex = accent_colour(blocks, theme, accent)
            tinted = {}
            for token, neutral in NEUTRAL[theme].items():
                tinted[token] = tint(neutral, accent_hex, TINT[theme][token])
            # Keep accent-on-ground legible even after the ground takes a hue.
            factor = TINT[theme]["--ground"]
            while contrast(accent_hex, tinted["--ground"]) < 4.6 and factor > 0.0:
                factor -= 0.02
                tinted["--ground"] = tint(NEUTRAL[theme]["--ground"], accent_hex, max(factor, 0.0))
            report.append((theme, accent, contrast(accent_hex, tinted["--ground"])))

            selector = f':root[data-theme="{theme}"][data-accent="{accent}"]'
            lines.append(f"{selector} {{")
            for token, value in tinted.items():
                lines.append(f"  {token}: {value};")
            lines.append("}")
            lines.append("")

    with open(args.out, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines))

    for theme, accent, ratio in report:
        print(f"{theme:6} {accent:8} accent/ground {ratio:5.2f}:1")
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    sys.exit(main())
