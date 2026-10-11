#!/usr/bin/env python3
"""Create the large 2×2 UI1 reference/production comparison board."""

from __future__ import annotations

import base64
import hashlib
import argparse
import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT.parent / "bifrost-docs"
EVIDENCE = DOCS / "evidence"
DEFAULT_ACTUAL = ROOT / "artifacts" / "ui-acceptance" / "ui1-obsidian-20260816" / "bifrost-windows-dark-protected-test-actual.png"


def font(size: int, bold: bool = False):
    candidates = [r"C:\Windows\Fonts\msyhbd.ttc" if bold else r"C:\Windows\Fonts\msyh.ttc", r"C:\Windows\Fonts\segoeuib.ttf" if bold else r"C:\Windows\Fonts\segoeui.ttf"]
    for candidate in candidates:
        try:
            return ImageFont.truetype(candidate, size)
        except OSError:
            pass
    return ImageFont.load_default()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, default=EVIDENCE)
    parser.add_argument("--output-dir", type=Path, default=EVIDENCE)
    parser.add_argument("--actual", type=Path, default=DEFAULT_ACTUAL)
    args = parser.parse_args(argv)
    input_dir = args.input_dir.resolve(); output_dir = args.output_dir.resolve(); output_dir.mkdir(parents=True, exist_ok=True)
    out_png = output_dir / "UI1-obsidian-comparison-board-1440x900.png"
    out_html = output_dir / "UI1-obsidian-comparison-board.html"
    pixel = json.loads((input_dir / "ui1-pixel-acceptance.json").read_text(encoding="utf-8"))
    images = [
        ("参考图 · Protected 定稿", input_dir / "reference-normalized-1440x810.png", "owner authority · normalized 1440×810"),
        ("Windows · dark protected-test", args.actual.resolve(), "production WPF · TEST-ONLY fixture"),
        ("50% alpha overlay", input_dir / "ui1-windows-protected-overlay-1440x810.png", "reference + actual · structure visible"),
        ("glyph-only mask", input_dir / "ui1-pixel-glyph-mask-1440x810.png", "magenta glyph pixels · no structure masking"),
    ]
    board = Image.new("RGB", (1440, 900), (7, 8, 9))
    draw = ImageDraw.Draw(board)
    draw.rectangle((0, 0, 1439, 93), fill=(17, 18, 22), outline=(43, 44, 49), width=1)
    draw.text((26, 17), "Bifrost Obsidian UI1 · ATTEMPT 7 Protected 像素对照板", fill=(240, 238, 233), font=font(22, True))
    draw.text((26, 51), "reference × WPF production × overlay × glyph-only mask；右侧 inspector divider 参与结构比较", fill=(170, 167, 161), font=font(12))
    meta = f"MASK {pixel['maskArtifacts']['coveragePercent']:.3f}% / 10% MAX\nEdge {pixel['metrics']['edgeSsim']:.4f} · Luminance {pixel['metrics']['luminanceSsim']:.4f}\nDial ΔW {pixel['dialGeometry']['widthDeltaRelative'] * 100:.2f}% · ΔH {pixel['dialGeometry']['heightDeltaRelative'] * 100:.2f}% · 结构遮罩 {pixel['maskArtifacts']['structurePixelsMasked']} px"
    draw.multiline_text((1120, 18), meta, anchor="ra", align="right", fill=(244, 180, 91), font=font(11), spacing=3)

    card_w, card_h, gap = 692, 390, 14
    for i, (label, image_path, status) in enumerate(images):
        col, row = i % 2, i // 2
        x, y = 18 + col * (card_w + gap), 106 + row * (card_h + gap)
        draw.rounded_rectangle((x, y, x + card_w, y + card_h), radius=12, fill=(20, 21, 24), outline=(48, 49, 54), width=1)
        draw.text((x + 14, y + 10), label, fill=(240, 238, 233), font=font(15, True))
        draw.text((x + 14, y + 35), status, fill=(170, 167, 161), font=font(11))
        preview = Image.open(image_path).convert("RGB")
        preview.thumbnail((668, 334), Image.Resampling.LANCZOS)
        px = x + (card_w - preview.width) // 2
        py = y + 62 + (334 - preview.height) // 2
        draw.rounded_rectangle((x + 11, y + 58, x + card_w - 11, y + 58 + 334), radius=8, fill=(13, 14, 16), outline=(58, 59, 64), width=1)
        board.paste(preview, (px, py))
        draw.text((x + 14, y + 365), "结构比较不遮 shell / 三栏 / 机械盘 / 上下 segmented / 右卡片 / 分隔线", fill=(196, 194, 189), font=font(11))
    board.save(out_png, format="PNG", optimize=False, compress_level=9)

    html_images = []
    for label, image_path, status in images:
        data = base64.b64encode(image_path.read_bytes()).decode("ascii")
        html_images.append(f'<section class="card"><h2>{label}</h2><div class="status">{status}</div><div class="preview"><img src="data:image/png;base64,{data}" alt="{label}" /></div><div class="notes">结构比较不遮 shell/三栏/机械盘/上下 segmented/右卡片/分隔线</div></section>')
    html = f'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>Bifrost Obsidian UI1 ATTEMPT 7 对照板</title><style>:root{{color-scheme:dark;font-family:"Segoe UI","Microsoft YaHei",sans-serif;background:#070809;color:#f0eee9}}*{{box-sizing:border-box}}body{{margin:0;width:1440px;height:900px;background:#070809;overflow:hidden}}header{{height:94px;padding:18px 26px 10px;border-bottom:1px solid #2b2c31;background:#111216;position:relative}}h1{{font-size:22px;margin:0 0 5px}}header p{{font-size:12px;color:#aaa7a1;margin:0}}.meta{{position:absolute;right:26px;top:18px;font-size:11px;color:#aaa7a1;text-align:right;line-height:1.55}}.meta b{{color:#f0b45b}}main{{height:806px;padding:12px 18px 18px;display:grid;grid-template-columns:repeat(2,1fr);grid-template-rows:repeat(2,1fr);gap:14px}}.card{{min-width:0;border:1px solid #303136;border-radius:12px;background:#141518;display:flex;flex-direction:column;overflow:hidden;box-shadow:0 18px 36px #0003}}.card h2{{font-size:15px;margin:0;padding:10px 14px 3px}}.status{{font-size:11px;padding:0 14px 7px;min-height:24px;color:#aaa7a1}}.preview{{height:334px;margin:0 11px;border:1px solid #3a3b40;border-radius:8px;background:#0d0e10;display:flex;align-items:center;justify-content:center;overflow:hidden}}.preview img{{max-width:100%;max-height:100%;object-fit:contain;display:block}}.notes{{border-top:1px solid #2a2b2f;margin-top:7px;padding:6px 14px 7px;font-size:11px;line-height:1.4;color:#c4c2bd;min-height:26px}}</style></head><body><header><h1>Bifrost Obsidian UI1 · ATTEMPT 7 Protected 像素对照板</h1><p>reference × WPF production × overlay × glyph-only mask；右侧 inspector divider 参与结构比较</p><div class="meta"><b>MASK {pixel['maskArtifacts']['coveragePercent']:.3f}% / 10% MAX</b><br>Edge {pixel['metrics']['edgeSsim']:.4f} · Luminance {pixel['metrics']['luminanceSsim']:.4f}<br>Dial ΔW {pixel['dialGeometry']['widthDeltaRelative'] * 100:.2f}% · ΔH {pixel['dialGeometry']['heightDeltaRelative'] * 100:.2f}% · 结构遮罩 {pixel['maskArtifacts']['structurePixelsMasked']} px</div></header><main>{''.join(html_images)}</main></body></html>'''
    out_html.write_text(html, encoding="utf-8")
    print(f"PNG {out_png} sha256={hashlib.sha256(out_png.read_bytes()).hexdigest()}")
    print(f"HTML {out_html} sha256={hashlib.sha256(out_html.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
