#!/usr/bin/env python3
"""Derive Direction A references and the Windows-matched Android launcher.

The checked-in Direction A source remains the QA/reference artwork input. This script performs
deterministic background extraction, high-quality raster resizing, Windows
brand-preview PNG generation, Android notification/reference resources, and a
non-product contact sheet for human inspection.  The Windows product icon is
preserved byte-for-byte. The Android product launcher is deterministically
derived from the exact 256x256 frame embedded in that Windows product ICO, so
the two platforms use the same artwork. It never reads a Codex cache path at
runtime.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFont
from scipy.ndimage import binary_fill_holes, gaussian_filter


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "assets" / "brand" / "bifrost-direction-a-brand-source.png"
WINDOWS_ASSETS = ROOT / "windows-app" / "Assets"
WINDOWS_BRAND = WINDOWS_ASSETS / "Brand"
ANDROID_RES = ROOT / "android-app" / "src" / "main" / "res"
ANDROID_LEGACY_LAUNCHER = ANDROID_RES / "mipmap-anydpi" / "ic_launcher_original.xml"
ANDROID_ADAPTIVE_LAUNCHER = ANDROID_RES / "mipmap-anydpi-v26" / "ic_launcher_original.xml"
ANDROID_WINDOWS_BITMAP = ANDROID_RES / "drawable-nodpi" / "bifrost_windows_launcher.png"
ARTIFACT = ROOT / "artifacts" / "icon-acceptance" / "ui1-icon-direction-a-20260817"
SOURCE_SHA256 = "0798377182330324b85652b868fa0a8d427f10d04d03446950b3665efe2ab9a3"
ORIGINAL_WINDOWS_ICO_SHA256 = "9f2fa5238e49fa484ca3bb115404c69f21ea618e6d4044f295ec1bca622d0677"
SOURCE_SIZE = (1254, 1254)
ANDROID_WINDOWS_FRAME_SIZE = (256, 256)
WARM_WHITE = (250, 247, 239)
ANDROID_DENSITIES = {"mdpi": 1, "hdpi": 3 / 2, "xhdpi": 2, "xxhdpi": 3, "xxxhdpi": 4}
ICO_SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)
ORIGINAL_WINDOWS_ICO_SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)
PIXEL_SPECIALIZED_SIZES = (16, 20, 24, 32, 40)


class IconIntegrityError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_source() -> Image.Image:
    if not SOURCE.is_file():
        raise IconIntegrityError(f"missing checked-in Direction A source: {SOURCE}")
    actual = sha256(SOURCE)
    if actual != SOURCE_SHA256:
        raise IconIntegrityError(f"Direction A source hash mismatch: expected {SOURCE_SHA256}, got {actual}")
    image = Image.open(SOURCE).convert("RGB")
    if image.size != SOURCE_SIZE:
        raise IconIntegrityError(f"Direction A source dimensions are {image.size}, expected {SOURCE_SIZE}")
    return image


def validate_original_windows_icon(path: Path) -> None:
    """Fail closed if the canonical Windows 2.2.62 product icon was replaced."""
    if not path.is_file():
        raise IconIntegrityError(f"missing canonical Windows 2.2.62 icon: {path}")
    actual = sha256(path)
    if actual != ORIGINAL_WINDOWS_ICO_SHA256:
        raise IconIntegrityError(
            "canonical Windows 2.2.62 icon hash mismatch: "
            f"expected {ORIGINAL_WINDOWS_ICO_SHA256}, got {actual}"
        )
    with Image.open(path) as icon:
        sizes = tuple(sorted(size[0] for size in icon.ico.sizes()))
    if sizes != ORIGINAL_WINDOWS_ICO_SIZES:
        raise IconIntegrityError(
            f"canonical Windows 2.2.62 icon sizes are {sizes}, expected {ORIGINAL_WINDOWS_ICO_SIZES}"
        )


def generate_windows_android_launcher(ico_path: Path) -> Path:
    """Copy the Windows product icon's 256px frame into Android as PNG."""
    validate_original_windows_icon(ico_path)
    with Image.open(ico_path) as icon:
        frame = icon.ico.getimage(ANDROID_WINDOWS_FRAME_SIZE).convert("RGBA")
    if frame.size != ANDROID_WINDOWS_FRAME_SIZE or frame.getchannel("A").getbbox() is None:
        raise IconIntegrityError("canonical Windows 2.2.62 256px icon frame is invalid")
    save_png(frame, ANDROID_WINDOWS_BITMAP)
    return ANDROID_WINDOWS_BITMAP


def validate_windows_android_launcher(ico_path: Path) -> None:
    """Fail closed unless Android launcher resources use the Windows product icon."""
    required = (ico_path, ANDROID_WINDOWS_BITMAP, ANDROID_LEGACY_LAUNCHER, ANDROID_ADAPTIVE_LAUNCHER)
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise IconIntegrityError(f"missing owner-approved Android launcher resource(s): {missing}")

    legacy = ANDROID_LEGACY_LAUNCHER.read_text(encoding="utf-8")
    adaptive = ANDROID_ADAPTIVE_LAUNCHER.read_text(encoding="utf-8")
    for name, xml in (("legacy", legacy), ("v26", adaptive)):
        if "<bitmap" not in xml or "@drawable/bifrost_windows_launcher" not in xml:
            raise IconIntegrityError(f"Windows-matched Android {name} launcher reference changed")
        if "bifrost_user_launcher" in xml or "bifrost_direction_a_" in xml or "ic_bifrost_bridge" in xml:
            raise IconIntegrityError(f"unapproved Android {name} launcher artwork is active")
    with Image.open(ico_path) as icon:
        windows_frame = icon.ico.getimage(ANDROID_WINDOWS_FRAME_SIZE).convert("RGBA")
    with Image.open(ANDROID_WINDOWS_BITMAP) as bitmap:
        android_frame = bitmap.convert("RGBA")
    if android_frame.size != ANDROID_WINDOWS_FRAME_SIZE or android_frame.tobytes() != windows_frame.tobytes():
        raise IconIntegrityError("Android launcher no longer matches the Windows 256px icon frame")


def soft_mask(mask: np.ndarray, sigma: float = 0.75) -> np.ndarray:
    alpha = gaussian_filter(mask.astype(np.float32), sigma=sigma)
    alpha /= max(float(alpha.max()), 1.0)
    return np.clip(np.round(alpha * 255), 0, 255).astype(np.uint8)


def derive_materials(image: Image.Image) -> tuple[Image.Image, Image.Image]:
    rgb = np.asarray(image, dtype=np.uint8)
    luminance = np.dot(rgb.astype(np.float32), [0.2126, 0.7152, 0.0722])
    # The warm-white tile is the only large bright connected region. Filling
    # its enclosed dark artwork leaves the rounded tile while excluding the
    # black corners of the original RGB candidate.
    tile = binary_fill_holes(luminance > 180)
    tile_alpha = soft_mask(tile, sigma=0.75)
    base_rgb = rgb.copy()
    # Pixels introduced by the antialias blur outside the tile must carry the
    # warm-white matte, never the candidate's black outer background.  This
    # prevents a one-pixel dark fringe on transparent Windows/legacy icons.
    base_rgb[~tile] = WARM_WHITE
    base_rgb[tile_alpha == 0] = WARM_WHITE
    legacy = Image.fromarray(np.dstack((base_rgb, tile_alpha)), "RGBA")

    artwork = tile & (luminance < 180)
    if not artwork.any():
        raise IconIntegrityError("Direction A artwork extraction found no dark/blue mark")
    art_alpha = soft_mask(artwork, sigma=0.55)
    art_rgb = np.zeros_like(rgb)
    art_rgb[:, :, :] = rgb
    art_rgb[art_alpha == 0] = (0, 0, 0)
    foreground = Image.fromarray(np.dstack((art_rgb, art_alpha)), "RGBA")
    bbox = foreground.getchannel("A").getbbox()
    if bbox is None:
        raise IconIntegrityError("Direction A foreground has no alpha bounds")
    return legacy, foreground.crop(bbox)


def resize_rgba(image: Image.Image, size: int) -> Image.Image:
    return image.resize((size, size), Image.Resampling.LANCZOS)


def _diamond_points(cx: int, cy: int, radius: int) -> list[tuple[int, int]]:
    return [(cx, cy - radius), (cx + radius, cy), (cx, cy + radius), (cx - radius, cy)]


def _ring_mask(size: int, cx: int, cy: int, radius: int, thickness: int) -> Image.Image:
    """Draw one pixel-grid aligned diamond ring without antialias blur."""
    mask = Image.new("L", (size, size), 0)
    draw = ImageDraw.Draw(mask)
    draw.polygon(_diamond_points(cx, cy, radius), fill=255)
    inner = max(1, radius - thickness)
    draw.polygon(_diamond_points(cx, cy, inner), fill=0)
    return mask


def pixel_specialized_icon(size: int) -> Image.Image:
    """Return an optically tuned, hard pixel-grid icon for 16–40px frames.

    These frames intentionally do not resize the 1254px source.  Two compact
    diamond rings are aligned to integer coordinates and the blue anchor is
    kept as a deliberate one/two-pixel mark at the center.
    """
    if size not in PIXEL_SPECIALIZED_SIZES:
        raise ValueError(f"pixel specialization is only defined for {PIXEL_SPECIALIZED_SIZES}")
    icon = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(icon)
    radius = max(3, round(size * 0.28))
    thickness = max(1, round(size * 0.095))
    cy = (size - 1) // 2
    left_cx = round(size * 0.405)
    right_cx = round(size * 0.595)
    tile_radius = max(2, round(size * 0.22))
    draw.rounded_rectangle((0, 0, size - 1, size - 1), radius=tile_radius, fill=WARM_WHITE + (255,))
    for cx in (left_cx, right_cx):
        ring = _ring_mask(size, cx, cy, radius, thickness)
        icon.paste(Image.new("RGBA", (size, size), (15, 16, 18, 255)), (0, 0), ring)
    # The anchor is deliberately drawn last so it remains visible at tiny
    # sizes even where the two rings overlap.
    anchor_radius = 1 if size <= 24 else 2
    anchor_cx = size // 2
    anchor_cy = size // 2
    if size <= 20:
        draw.rectangle((anchor_cx, anchor_cy, anchor_cx, anchor_cy), fill=(40, 111, 246, 255))
    else:
        draw.polygon(_diamond_points(anchor_cx, anchor_cy, anchor_radius), fill=(40, 111, 246, 255))
    return icon


def frame_for_size(legacy: Image.Image, size: int) -> Image.Image:
    return pixel_specialized_icon(size) if size in PIXEL_SPECIALIZED_SIZES else resize_rgba(legacy, size)


def repo_relative(path: Path) -> str:
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(ROOT.resolve())
    except ValueError as error:
        raise IconIntegrityError(f"generated path escapes clients repository: {resolved}") from error
    if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
        raise IconIntegrityError(f"generated path is not a clean relative path: {relative}")
    return relative.as_posix()


def validate_manifest_paths(manifest: dict) -> None:
    """Fail closed if a manifest ever emits absolute/escape paths."""
    path_values: list[str] = []
    source = manifest.get("source", {})
    path_values.append(source.get("checkedInPath", ""))
    windows = manifest.get("windows", {})
    path_values.append(windows.get("ico", "")); path_values.extend(windows.get("pngs", []))
    android = manifest.get("android", {})
    for key in ("legacyLauncher", "adaptiveLauncher", "launcherSource", "launcherBitmap"):
        value = android.get(key)
        if value:
            path_values.append(value)
    path_values.extend(android.get("adaptiveForeground", [])); path_values.extend(android.get("monochrome", []))
    path_values.append(manifest.get("contactSheet", ""))
    path_values.extend(manifest.get("outputsSha256", {}).keys())
    for value in path_values:
        if not isinstance(value, str) or not value or "\\" in value:
            raise IconIntegrityError(f"manifest path is not POSIX-relative: {value!r}")
        candidate = Path(value)
        if candidate.is_absolute() or any(part in ("", ".", "..") for part in candidate.parts):
            raise IconIntegrityError(f"manifest path is absolute or escapes repository: {value!r}")
        external_tokens = ("c:/users/", "c:/windows/" + "temp/", "." + "codex", "generated" + "_images")
        if value.lower().startswith(external_tokens[:2]) or any(token in value.lower() for token in external_tokens[2:]):
            raise IconIntegrityError(f"manifest path references an external cache: {value!r}")


def safe_canvas(artwork: Image.Image, size: int, max_extent: int = 64, fill=(0, 0, 0, 0)) -> Image.Image:
    scale = min(max_extent / artwork.width, max_extent / artwork.height)
    width = max(1, round(artwork.width * scale))
    height = max(1, round(artwork.height * scale))
    resized = artwork.resize((width, height), Image.Resampling.LANCZOS)
    canvas = Image.new("RGBA", (size, size), fill)
    canvas.alpha_composite(resized, ((size - width) // 2, (size - height) // 2))
    return canvas


def save_png(image: Image.Image, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(path, format="PNG", optimize=False)


def font(size: int, bold: bool = False):
    candidates = [
        r"C:\Windows\Fonts\msyhbd.ttc" if bold else r"C:\Windows\Fonts\msyh.ttc",
        r"C:\Windows\Fonts\segoeuib.ttf" if bold else r"C:\Windows\Fonts\segoeui.ttf",
    ]
    for candidate in candidates:
        try:
            return ImageFont.truetype(candidate, size)
        except OSError:
            pass
    return ImageFont.load_default()


def write_ico(frames: dict[int, Image.Image], path: Path) -> None:
    """Write PNG-compressed ICO entries without resampling any frame."""
    import io
    import struct

    payloads: list[tuple[int, bytes]] = []
    for size in sorted(frames):
        stream = io.BytesIO()
        frames[size].save(stream, format="PNG", optimize=False)
        payloads.append((size, stream.getvalue()))
    header_size = 6 + len(payloads) * 16
    offset = header_size
    directory = bytearray(struct.pack("<HHH", 0, 1, len(payloads)))
    body = bytearray()
    for size, payload in payloads:
        dimension = 0 if size == 256 else size
        directory.extend(struct.pack("<BBBBHHII", dimension, dimension, 0, 0, 1, 32, len(payload), offset))
        body.extend(payload)
        offset += len(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(directory) + bytes(body))


def _background_tile(frame: Image.Image, size: int, color: tuple[int, int, int], nearest: bool = False) -> Image.Image:
    tile = Image.new("RGB", (112, 112), color)
    if nearest:
        scale = max(1, min(6, 96 // max(size, 1)))
        shown = frame.resize((size * scale, size * scale), Image.Resampling.NEAREST)
    else:
        shown = frame
    tile.paste(shown, ((112 - shown.width) // 2, (112 - shown.height) // 2), shown)
    return tile


def make_contact_sheet(frames: dict[int, Image.Image], foreground: Image.Image, path: Path) -> None:
    """Show 1:1 and nearest-neighbour checks on light and dark backgrounds."""
    labels = [16, 24, 32, 40, 48, 64, 128, 256]
    cell_w, cell_h = 270, 300
    sheet = Image.new("RGB", (cell_w * 4, cell_h * 3), (28, 29, 32))
    draw = ImageDraw.Draw(sheet)
    light = (238, 237, 232)
    dark = (24, 25, 29)
    for index, size in enumerate(labels):
        x = (index % 4) * cell_w
        y = (index // 4) * cell_h
        draw.text((x + 14, y + 8), f"Win {size}px · 1:1 + NN", fill=(241, 239, 233), font=font(13, True))
        frame = frames[size]
        blocks = [
            ("浅色 1:1", _background_tile(frame, size, light, False)),
            ("深色 1:1", _background_tile(frame, size, dark, False)),
            ("浅色 NN", _background_tile(frame, size, light, True)),
            ("深色 NN", _background_tile(frame, size, dark, True)),
        ]
        for block_index, (label, block) in enumerate(blocks):
            bx = x + 12 + (block_index % 2) * 126
            by = y + 34 + (block_index // 2) * 132
            sheet.paste(block, (bx, by))
            draw.text((bx + 4, by + 114), label, fill=(226, 224, 219), font=font(10))

    # Adaptive mask checks occupy a separate third row of the same board.
    adaptive = Image.new("RGBA", (108, 108), WARM_WHITE + (255,))
    adaptive.alpha_composite(safe_canvas(foreground, 108, 64))
    masks = (("circle", 0), ("squircle", 29), ("rounded-square", 17))
    for index, (label, radius) in enumerate(masks):
        m = Image.new("L", (108, 108), 0)
        md = ImageDraw.Draw(m)
        if label == "circle":
            md.ellipse((0, 0, 107, 107), fill=255)
        else:
            md.rounded_rectangle((0, 0, 107, 107), radius=radius, fill=255)
        masked = Image.new("RGBA", (108, 108), (0, 0, 0, 0))
        masked.paste(adaptive, (0, 0), m)
        block = Image.new("RGB", (112, 112), light)
        block.paste(masked, (2, 2), masked)
        bx = 12 + index * 136
        by = cell_h * 2 + 34
        sheet.paste(block, (bx, by))
        draw.text((bx + 4, by + 114), f"Adaptive {label}", fill=(226, 224, 219), font=font(10))
    draw.text((12, cell_h * 2 + 8), "Adaptive 安全区：circle / squircle / rounded-square", fill=(241, 239, 233), font=font(13, True))
    path.parent.mkdir(parents=True, exist_ok=True)
    sheet.save(path, format="PNG", optimize=False)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", type=Path, default=ARTIFACT)
    args = parser.parse_args()
    artifact = args.artifact_dir.resolve()
    artifact.mkdir(parents=True, exist_ok=True)
    image = validate_source()
    legacy, foreground = derive_materials(image)

    # Windows: preserve the owner-approved native application/installer icon.
    # Direction A remains available only as explicit preview/QA PNG assets;
    # running this generator must never replace the shipped Windows icon again.
    WINDOWS_BRAND.mkdir(parents=True, exist_ok=True)
    frames = {size: frame_for_size(legacy, size) for size in ICO_SIZES}
    ico_path = WINDOWS_ASSETS / "bifrost.ico"
    validate_original_windows_icon(ico_path)
    android_launcher_bitmap = generate_windows_android_launcher(ico_path)
    validate_windows_android_launcher(ico_path)
    windows_pngs: list[Path] = []
    for size in ICO_SIZES:
        path = WINDOWS_BRAND / f"bifrost-direction-a-{size}.png"
        save_png(frames[size], path)
        windows_pngs.append(path)

    # Direction A remains available only for non-launcher system surfaces and
    # QA/reference use. Product launcher bytes come only from the owner-approved
    # Windows product ICO above, keeping Windows and Android visually identical.
    android_outputs: list[Path] = []
    android_foreground_paths: list[Path] = []
    android_monochrome_paths: list[Path] = []
    for density, factor in ANDROID_DENSITIES.items():
        adaptive_size = round(108 * factor)
        fg_path = ANDROID_RES / f"drawable-{density}" / "bifrost_direction_a_foreground.png"
        mono_path = ANDROID_RES / f"drawable-{density}" / "bifrost_direction_a_monochrome.png"
        save_png(safe_canvas(foreground, adaptive_size, round(64 * factor)), fg_path)
        mono = Image.new("RGBA", foreground.size, (0, 0, 0, 0))
        mono.paste(Image.new("RGBA", foreground.size, (0, 0, 0, 255)), mask=foreground.getchannel("A"))
        save_png(safe_canvas(mono, adaptive_size, round(64 * factor)), mono_path)
        android_outputs.extend((fg_path, mono_path))
        android_foreground_paths.append(fg_path)
        android_monochrome_paths.append(mono_path)

    contact_sheet = artifact / "bifrost-direction-a-icon-contact-sheet.png"
    make_contact_sheet(frames, foreground, contact_sheet)
    manifest = {
        "schemaVersion": 1,
        "contract": "BIFROST-ICON-DIRECTION-A-20260817",
        "semantic": "暖白底、黑色交叠菱形、中心小蓝色锚点",
        "source": {
            "checkedInPath": repo_relative(SOURCE),
            "sha256": SOURCE_SHA256,
            "dimensions": "1254x1254 RGB",
            "ownerDecision": "方向 A｜黑白品牌印记",
            "provenance": "Owner-selected candidate; supplied via built-in image generation; copied byte-for-byte before derivation.",
        },
        "derivation": {
            "outsideTile": "removed by filled warm-white connected tile mask with antialiased alpha; no artwork repaint",
            "adaptiveSafeExtent": "64/108 viewport units maximum; foreground and monochrome share identical bounds",
            "pixelSpecializedSizes": list(PIXEL_SPECIALIZED_SIZES),
            "pixelSpecialization": "integer-coordinate diamond rings, direct blue anchor pixel, no mechanical resize for 16/20/24/32/40",
            "backgroundColor": "#FAF7EF",
            "monochrome": "same extracted black/blue mark rendered as one black silhouette",
        },
        "windows": {
            "ico": repo_relative(ico_path),
            "sizes": list(ORIGINAL_WINDOWS_ICO_SIZES),
            "sha256": ORIGINAL_WINDOWS_ICO_SHA256,
            "preservedOriginal": True,
            "pngs": [repo_relative(p) for p in windows_pngs],
        },
        "android": {
            "launcherMode": "windows-ico-256-frame",
            "legacyLauncher": repo_relative(ANDROID_LEGACY_LAUNCHER),
            "adaptiveLauncher": repo_relative(ANDROID_ADAPTIVE_LAUNCHER),
            "launcherSource": repo_relative(ico_path),
            "launcherSourceSha256": ORIGINAL_WINDOWS_ICO_SHA256,
            "launcherBitmap": repo_relative(android_launcher_bitmap),
            "adaptiveForeground": [repo_relative(p) for p in android_foreground_paths],
            "monochrome": [repo_relative(p) for p in android_monochrome_paths],
        },
        "contactSheet": repo_relative(contact_sheet),
    }
    manifest["outputsSha256"] = {repo_relative(path): sha256(path) for path in [ico_path, android_launcher_bitmap, *windows_pngs, *android_outputs, contact_sheet]}
    validate_manifest_paths(manifest)
    manifest_path = artifact / "bifrost-direction-a-icon-manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "PASS", "sourceSha256": SOURCE_SHA256, "ico": repo_relative(ico_path), "icoMode": "preserved-original", "icoSizes": list(ORIGINAL_WINDOWS_ICO_SIZES), "pixelSpecializedSizes": list(PIXEL_SPECIALIZED_SIZES), "androidOutputs": len(android_outputs), "contactSheet": repo_relative(contact_sheet), "manifest": repo_relative(manifest_path)}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except IconIntegrityError as error:
        print(f"ICON_INTEGRITY_ERROR: {error}")
        raise SystemExit(2)
