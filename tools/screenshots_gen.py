#!/usr/bin/env python3
"""Render the project's actual --help output as a terminal screenshot."""

from pathlib import Path
import subprocess

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "Screenshots" / "home.png"


def main() -> None:
    result = subprocess.run(
        ["cargo", "run", "--quiet", "--", "--help"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    text = result.stdout.rstrip()
    font = ImageFont.load_default()
    lines = text.splitlines()
    width = max(font.getlength(line) for line in lines) + 48
    height = len(lines) * 18 + 40
    image = Image.new("RGB", (int(width), height), "#14151a")
    draw = ImageDraw.Draw(image)
    draw.multiline_text((24, 20), text, fill="#f2f3f5", font=font, spacing=4)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    image.save(OUTPUT)
    print(OUTPUT)


if __name__ == "__main__":
    main()
