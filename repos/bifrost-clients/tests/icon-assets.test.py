#!/usr/bin/env python3
"""Fail-closed integrity and portability gates for Bifrost icon assets."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import numpy as np
from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "assets/brand/bifrost-direction-a-brand-source.png"
SOURCE_SHA = "0798377182330324b85652b868fa0a8d427f10d04d03446950b3665efe2ab9a3"
ANDROID_WINDOWS_BITMAP = ROOT / "android-app/src/main/res/drawable-nodpi/bifrost_windows_launcher.png"
WINDOWS_ICO_SHA = "9f2fa5238e49fa484ca3bb115404c69f21ea618e6d4044f295ec1bca622d0677"
ARTIFACT = ROOT / "artifacts/icon-acceptance/ui1-icon-direction-a-20260817"
GENERATOR = ROOT / "tools/generate-bifrost-icon-assets.py"
ICO_SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)
ORIGINAL_WINDOWS_ICO_SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)
PIXEL_SPECIALIZED = (16, 20, 24, 32, 40)
DENSITIES = {"mdpi": (108, 48, 1), "hdpi": (162, 72, 1.5), "xhdpi": (216, 96, 2), "xxhdpi": (324, 144, 3), "xxxhdpi": (432, 192, 4)}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def load_generator():
    spec = importlib.util.spec_from_file_location("bifrost_icon_generator", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def corner_is_clean(pixel: tuple[int, int, int, int]) -> bool:
    return pixel[3] == 0 or (pixel[3] <= 8 and min(pixel[:3]) >= 180)


def check_pixel_topology(image: Image.Image, size: int) -> None:
    rgba = np.asarray(image.convert("RGBA"), dtype=np.uint8)
    rgb = rgba[:, :, :3]
    alpha = rgba[:, :, 3]
    black = (alpha >= 220) & (rgb.max(axis=2) <= 80)
    blue = (alpha >= 150) & (rgb[:, :, 2] >= 150) & (rgb[:, :, 2] > rgb[:, :, 0] + 60) & (rgb[:, :, 2] > rgb[:, :, 1] + 30)
    require(int(blue.sum()) >= 1, f"{size}px blue anchor is missing")
    ys, xs = np.where(blue)
    require(abs(float(xs.mean()) - size / 2) <= 1.5 and abs(float(ys.mean()) - size / 2) <= 1.5, f"{size}px blue anchor is not centered")
    require(int(black.sum()) >= max(12, size), f"{size}px black structure is too sparse")
    radius = max(3, round(size * 0.28))
    cy = (size - 1) // 2
    centers = (round(size * 0.405), round(size * 0.595))
    for cx in centers:
        # Each ring must expose its top/bottom and outside lateral vertices;
        # this rejects a single merged eye/blob even at 16px.
        for px, py in ((cx, cy - radius), (cx, cy + radius), (cx - radius, cy), (cx + radius, cy)):
            x0, x1 = max(0, px - 1), min(size, px + 2)
            y0, y1 = max(0, py - 1), min(size, py + 2)
            require(bool(black[y0:y1, x0:x1].any()), f"{size}px diamond vertex topology is missing near {(px, py)}")
    require(corner_is_clean(tuple(int(value) for value in rgba[0, 0])), f"{size}px transparent corner is dirty")
    # White gaps must survive inside both rings, proving that the two
    # outlines are not a single filled black blob.
    interior_radius = max(1, radius - max(1, round(size * 0.095)) - 1)
    for cx in centers:
        interior = []
        for y in range(size):
            for x in range(size):
                if abs(x - cx) + abs(y - cy) <= interior_radius and not black[y, x]:
                    interior.append((x, y))
        require(len(interior) >= 2, f"{size}px diamond interior gap collapsed")


def resolve_repo_relative(value: str, root: Path = ROOT) -> Path:
    require(isinstance(value, str) and value, f"manifest path must be a string: {value!r}")
    require("\\" not in value, f"manifest path must use POSIX separators: {value!r}")
    candidate = Path(value)
    require(not candidate.is_absolute(), f"manifest path must not be absolute: {value!r}")
    require(".." not in candidate.parts and "." not in candidate.parts, f"manifest path must not escape: {value!r}")
    root = root.resolve()
    resolved = (root / candidate).resolve()
    require(resolved.is_relative_to(root), f"manifest path escaped root: {value!r}")
    return resolved


def copy_minimal_clients_repo(destination: Path) -> None:
    files = (
        "tools/generate-bifrost-icon-assets.py",
        "tests/icon-assets.test.py",
        "assets/brand/bifrost-direction-a-brand-source.png",
        "windows-app/Assets/bifrost.ico",
        "android-app/src/main/AndroidManifest.xml",
        "android-app/src/main/res/mipmap-anydpi/ic_launcher_original.xml",
        "android-app/src/main/res/mipmap-anydpi-v26/ic_launcher_original.xml",
        "android-app/src/main/res/values/colors.xml",
    )
    for relative in files:
        source = ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def run_portability_checks() -> None:
    with tempfile.TemporaryDirectory(prefix="bifrost-icon-portable-") as temp:
        portable = Path(temp) / "bifrost-clients"
        portable.mkdir()
        copy_minimal_clients_repo(portable)
        sibling_docs_name = "bifrost-" + "docs"
        require(not (portable.parent / sibling_docs_name).exists(), "portable fixture must not have sibling docs")
        generated = subprocess.run(["python", "tools/generate-bifrost-icon-assets.py"], cwd=portable, text=True, capture_output=True)
        require(generated.returncode == 0, f"portable generator failed: {generated.stdout}{generated.stderr}")
        manifest_path = portable / "artifacts/icon-acceptance/ui1-icon-direction-a-20260817/bifrost-direction-a-icon-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        require(sibling_docs_name not in json.dumps(manifest), "portable manifest must not mention sibling docs")
        for path_text, expected in manifest["outputsSha256"].items():
            path = resolve_repo_relative(path_text, portable)
            require(path.is_file() and digest(path) == expected, f"portable manifest output: {path_text}")
        child_env = os.environ.copy()
        child_env["BIFROST_ICON_SKIP_PORTABILITY"] = "1"
        child = subprocess.run(["python", "tests/icon-assets.test.py"], cwd=portable, env=child_env, text=True, capture_output=True)
        require(child.returncode == 0, f"portable icon test failed: {child.stdout}{child.stderr}")

        tampered = Path(temp) / "bifrost-clients-tampered"
        tampered.mkdir()
        copy_minimal_clients_repo(tampered)
        source_bytes = bytearray((tampered / "assets/brand/bifrost-direction-a-brand-source.png").read_bytes())
        source_bytes[-1] ^= 1
        (tampered / "assets/brand/bifrost-direction-a-brand-source.png").write_bytes(source_bytes)
        rejected = subprocess.run(["python", "tools/generate-bifrost-icon-assets.py"], cwd=tampered, text=True, capture_output=True)
        require(rejected.returncode != 0 and "hash mismatch" in (rejected.stdout + rejected.stderr).lower(), "tampered source must fail closed")

    generator = load_generator()
    manifest = json.loads((ARTIFACT / "bifrost-direction-a-icon-manifest.json").read_text(encoding="utf-8"))
    bad_absolute = json.loads(json.dumps(manifest)); bad_absolute["windows"]["ico"] = str(ROOT / "windows-app/Assets/bifrost.ico")
    try:
        generator.validate_manifest_paths(bad_absolute)
    except generator.IconIntegrityError:
        pass
    else:
        raise AssertionError("absolute manifest path did not fail closed")
    bad_escape = json.loads(json.dumps(manifest)); bad_escape["outputsSha256"] = {"../outside.png": "0" * 64}
    try:
        generator.validate_manifest_paths(bad_escape)
    except generator.IconIntegrityError:
        pass
    else:
        raise AssertionError("escape manifest path did not fail closed")


def main() -> None:
    require(SOURCE.is_file(), "clients source copy exists")
    require(digest(SOURCE) == SOURCE_SHA, "clients source hash is owner-approved")
    with Image.open(SOURCE) as source:
        require(source.size == (1254, 1254) and source.mode == "RGB", "source dimensions and mode")
    generator = load_generator()
    icon = ROOT / "windows-app/Assets/bifrost.ico"
    require(icon.is_file(), "Windows ICO exists")
    require(digest(icon) == WINDOWS_ICO_SHA, "Windows ICO matches the canonical 2.2.62 release icon")
    with Image.open(icon) as ico:
        require(set(ico.ico.sizes()) == {(size, size) for size in ORIGINAL_WINDOWS_ICO_SIZES}, f"original ICO sizes are complete: {ico.ico.sizes()}")
        for size in ORIGINAL_WINDOWS_ICO_SIZES:
            frame = ico.ico.getimage((size, size)).convert("RGBA")
            require(frame.size == (size, size), f"original ICO {size}px dimensions")
            require(frame.getchannel("A").getbbox() is not None, f"original ICO {size}px has visible artwork")

    # Direction A Windows PNGs remain QA/reference assets, but they are no
    # longer allowed to replace the owner-approved native product ICO.
    specialized_hashes: dict[int, str] = {}
    for size in ICO_SIZES:
        png_path = ROOT / f"windows-app/Assets/Brand/bifrost-direction-a-{size}.png"
        with Image.open(png_path) as png:
            frame = png.convert("RGBA")
            require(frame.size == (size, size), f"Direction A PNG {size}px dimensions")
            require(frame.getchannel("A").getbbox() is not None, f"Direction A PNG {size}px has visible artwork")
            if size in PIXEL_SPECIALIZED:
                mechanical = generator.resize_rgba(generator.derive_materials(Image.open(SOURCE).convert("RGB"))[0], size)
                require(frame.tobytes() != mechanical.convert("RGBA").tobytes(), f"{size}px reverted to mechanical resize")
                check_pixel_topology(frame, size)
                specialized_hashes[size] = hashlib.sha256(frame.tobytes()).hexdigest()
    require(len(set(specialized_hashes.values())) == len(PIXEL_SPECIALIZED), "small Direction A PNG frames must have independent hashes")

    manifest_xml = (ROOT / "android-app/src/main/res/mipmap-anydpi-v26/ic_launcher_original.xml").read_text(encoding="utf-8")
    legacy_xml = (ROOT / "android-app/src/main/res/mipmap-anydpi/ic_launcher_original.xml").read_text(encoding="utf-8")
    require("<bitmap" in manifest_xml and "@drawable/bifrost_windows_launcher" in manifest_xml, "Android v26 launcher references the Windows icon")
    require("<bitmap" in legacy_xml and "@drawable/bifrost_windows_launcher" in legacy_xml, "Android legacy launcher references the Windows icon")
    require("bifrost_user_launcher" not in manifest_xml + legacy_xml and "bifrost_direction_a_" not in manifest_xml + legacy_xml and "ic_bifrost_bridge" not in manifest_xml + legacy_xml, "no superseded launcher artwork is active")
    generator.validate_windows_android_launcher(icon)
    require(ANDROID_WINDOWS_BITMAP.is_file(), "generated Windows-matched Android launcher exists")
    with Image.open(icon) as ico:
        windows_frame = ico.ico.getimage((256, 256)).convert("RGBA")
    with Image.open(ANDROID_WINDOWS_BITMAP) as launcher:
        android_frame = launcher.convert("RGBA")
        require(android_frame.size == (256, 256), "generated Android launcher keeps Windows 256px dimensions")
        require(android_frame.tobytes() == windows_frame.tobytes(), "generated Android launcher exactly matches Windows 256px pixels")
    android_manifest = (ROOT / "android-app/src/main/AndroidManifest.xml").read_text(encoding="utf-8")
    require('android:icon="@mipmap/ic_launcher_original"' in android_manifest and 'android:roundIcon="@mipmap/ic_launcher_original"' in android_manifest, "Android manifest pins the preserved original launcher resource")

    for density, (adaptive_size, _legacy_size, factor) in DENSITIES.items():
        for stem in ("foreground", "monochrome"):
            path = ROOT / f"android-app/src/main/res/drawable-{density}/bifrost_direction_a_{stem}.png"
            with Image.open(path) as image:
                require(image.size == (adaptive_size, adaptive_size), f"Android {density} {stem} size")
                bbox = image.getchannel("A").getbbox()
                require(bbox is not None, f"Android {density} {stem} artwork")
                max_extent = round(64 * factor) + 2
                require(bbox[2] - bbox[0] <= max_extent and bbox[3] - bbox[1] <= max_extent, f"Android {density} {stem} safe extent")
                center_x = (bbox[0] + bbox[2]) / 2
                center_y = (bbox[1] + bbox[3]) / 2
                require(abs(center_x - adaptive_size / 2) <= 2 and abs(center_y - adaptive_size / 2) <= 2, f"Android {density} {stem} optical center")

    script = GENERATOR.read_text(encoding="utf-8")
    require(("bifrost-" + "docs") not in script and "ROOT.parent" not in script and ('C:' + '\\Users\\whb') not in script, "clients generator has no sibling/default external dependency")
    manifest = json.loads((ARTIFACT / "bifrost-direction-a-icon-manifest.json").read_text(encoding="utf-8"))
    require(manifest["source"]["sha256"] == SOURCE_SHA, "manifest source hash")
    require(manifest["source"]["checkedInPath"] == "assets/brand/bifrost-direction-a-brand-source.png", "manifest source path is repository-relative")
    generator.validate_manifest_paths(manifest)
    for path_text, expected in manifest["outputsSha256"].items():
        path = resolve_repo_relative(path_text)
        require(path.is_file() and digest(path) == expected, f"manifest output hash: {path_text}")
    with Image.open(ARTIFACT / "bifrost-direction-a-icon-contact-sheet.png") as sheet:
        require(sheet.size == (1080, 900), "contact sheet includes light/dark 1:1 and NN rows")
    if not os.environ.get("BIFROST_ICON_SKIP_PORTABILITY"):
        run_portability_checks()
    print("BIFROST_ICON_ASSETS_PASS source=1 windows-ico=1 windows-png=1 pixel-specialized=1 topology=1 anchor=1 frame-identity=1 android-windows-launcher=1 android-adaptive-reference=1 android-monochrome=1 safe-area=1 provenance=1 relative-manifest=1 clean-room-portability=1 tampered-source-negative=1 manifest-negative=1")


if __name__ == "__main__":
    main()
