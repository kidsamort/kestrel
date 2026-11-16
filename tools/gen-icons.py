"""Render the Kestrel app icons: an eight-point star on the brand-blue tile.

The mark is four round-capped strokes through the centre (stroke 19/100), the
same geometry as src/ui/BrandMark.tsx. Output is written into src-tauri/icons.

Usage: python tools/gen-icons.py
"""
import math
import os
import struct
import zlib

TILE_TOP = (37, 99, 235)   # #2563eb
TILE_BOT = (29, 78, 216)   # #1d4ed8
MARK = (255, 255, 255)
ARMS = [(0.0,), (45.0,), (90.0,), (135.0,)]  # angles, each drawn through the centre
SS = 3                                        # supersampling factor


def rounded(x, y, s, r):
    cx, cy = x - s / 2 + 0.5, y - s / 2 + 0.5
    ax, ay = abs(cx), abs(cy)
    lim = s / 2 - r
    dx, dy = max(ax - lim, 0), max(ay - lim, 0)
    return dx * dx + dy * dy <= r * r


def on_mark(px, py, s):
    cx = cy = s / 2
    half_width = s * 0.095
    inner, outer = s * 0.15, s * 0.85
    for (deg,) in ARMS:
        a = math.radians(deg)
        ux, uy = math.cos(a), math.sin(a)
        # the arm spans the centre, so project onto [-outer, outer]
        t = max(-outer, min(outer, (px - cx) * ux + (py - cy) * uy))
        ex, ey = cx + ux * t, cy + uy * t
        if math.hypot(px - ex, py - ey) <= half_width:
            return True
    return False


def render(s):
    raw = bytearray()
    for y in range(s):
        raw.append(0)
        for x in range(s):
            acc = [0, 0, 0, 0]
            for sy in range(SS):
                for sx in range(SS):
                    fx, fy = x + (sx + 0.5) / SS, y + (sy + 0.5) / SS
                    if not rounded(fx, fy, s, s * 0.22):
                        continue
                    t = fy / s
                    base = tuple(
                        TILE_TOP[i] + (TILE_BOT[i] - TILE_TOP[i]) * t for i in range(3)
                    )
                    if on_mark(fx, fy, s):
                        base = MARK
                    acc[0] += base[0]
                    acc[1] += base[1]
                    acc[2] += base[2]
                    acc[3] += 255
            n = SS * SS
            if acc[3] == 0:
                raw.extend((0, 0, 0, 0))
            else:
                covered = acc[3] / 255
                raw.extend(
                    (
                        round(acc[0] / covered),
                        round(acc[1] / covered),
                        round(acc[2] / covered),
                        round(acc[3] / n),
                    )
                )
    return bytes(raw)


def png(path, size):
    raw = render(size)

    def chunk(tag, data):
        body = struct.pack(">I", len(data)) + tag + data
        return body + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    blob = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )
    open(path, "wb").write(blob)
    return blob


def main():
    out = os.path.join(os.path.dirname(__file__), "..", "src-tauri", "icons")
    os.makedirs(out, exist_ok=True)
    sizes = {s: png(os.path.join(out, f"{s}x{s}.png"), s) for s in (32, 128, 256, 512)}
    png(os.path.join(out, "icon.png"), 512)
    image = sizes[256]
    open(os.path.join(out, "icon.ico"), "wb").write(
        struct.pack("<HHH", 0, 1, 1)
        + struct.pack("<BBBBHHII", 0, 0, 0, 0, 1, 32, len(image), 6 + 16)
        + image
    )
    print("icons written:", sorted(os.listdir(out)))


if __name__ == "__main__":
    main()
