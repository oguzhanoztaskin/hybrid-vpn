#!/usr/bin/env python3
"""Generates the third-party notices for everything linked into the app.

    scripts/openvpn3-deps.sh        # native sources must be present
    python3 scripts/gen-notices.py

Writes THIRD_PARTY_NOTICES.md (summary), app/src/main/assets/third_party_licenses.txt (full
licence texts) and a copy of LICENSE as app/src/main/assets/gpl-3.0.txt; the app shows both under
Settings -> About -> Open-source licences. Sources:

- Go: modules linked into libhybridvpn_go.so (android/arm64, tag openvpn3), with the licence
  files shipped in each module, plus the Go standard library.
- Native: OpenVPN 3 Core, OpenSSL, asio, LZ4 from third_party/src.
- Android/JVM: the release runtime classpath, with licences from each artifact's POM.

Re-run after changing any dependency, and review the diff.
"""
import os
import re
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "third_party" / "src"
GRADLE_CACHE = Path.home() / ".gradle" / "caches" / "modules-2" / "files-2.1"

LICENSE_FILE = re.compile(r"^(LICEN[CS]E|COPYING|NOTICE|PATENTS)([._-][\w.-]*)?(\.txt|\.md)?$", re.I)
SOURCE_FILE = re.compile(r"\.(go|c|h|cc|cpp|hpp|py|sh|s)$", re.I)


def classify(text):
    """Best-effort SPDX id(s) of a licence text. Reviewed by hand in the generated summary."""
    found = []
    if "Apache License" in text and "Version 2.0" in text:
        found.append("Apache-2.0")
    if "Mozilla Public License" in text and "2.0" in text:
        found.append("MPL-2.0")
    if "Boost Software License" in text:
        found.append("BSL-1.0")
    if "Permission is hereby granted, free of charge, to any person obtaining" in text:
        found.append("MIT")
    if re.search(r"Permission to use, copy, modify, and(/or)? distribute this software for any", text):
        found.append("ISC")
    if "Redistribution and use in source and binary forms" in text:
        found.append("BSD-3-Clause" if re.search(r"Neither the name|names of (its|the) contributors", text) else "BSD-2-Clause")
    if "GNU AFFERO GENERAL PUBLIC LICENSE" in text:
        found.append("AGPL-3.0")
    if "Additional IP Rights Grant (Patents)" in text:
        found.append("patent grant")
    return " AND ".join(dict.fromkeys(found)) or "see text"


def license_files(directory, recursive=False):
    d = Path(directory)
    files = d.rglob("*") if recursive else d.iterdir()
    return sorted(p for p in files if p.is_file() and LICENSE_FILE.match(p.name) and not SOURCE_FILE.search(p.name))


def go_modules():
    env = dict(os.environ, GOOS="android", GOARCH="arm64", CGO_ENABLED="1")
    out = subprocess.run(
        ["go", "list", "-deps", "-tags", "openvpn3", "-f",
         "{{with .Module}}{{.Path}}\t{{.Version}}\t{{.Dir}}{{end}}", "./jni"],
        cwd=ROOT / "go", env=env, check=True, capture_output=True, text=True).stdout
    mods = {}
    for line in out.splitlines():
        path, version, directory = line.split("\t")
        if path != "hybridvpn/netcore":
            mods[path] = (version, directory)
    goroot = subprocess.run(["go", "env", "GOROOT"], cwd=ROOT / "go", check=True, capture_output=True, text=True).stdout.strip()
    goversion = subprocess.run(["go", "env", "GOVERSION"], cwd=ROOT / "go", check=True, capture_output=True, text=True).stdout.strip()
    comps = [("Go standard library and runtime", goversion, "https://go.dev", [Path(goroot) / "LICENSE", Path(goroot) / "PATENTS"])]
    for path, (version, directory) in sorted(mods.items()):
        files = license_files(directory)
        if not files:
            sys.exit(f"no licence file in {path} ({directory})")
        comps.append((path, version, "https://pkg.go.dev/" + path, files))
    return comps


def native():
    def need(p):
        if not p.exists():
            sys.exit(f"{p} missing: run scripts/openvpn3-deps.sh")
        return p
    o3 = SRC / "openvpn3"
    return [
        ("OpenVPN 3 Core (used under MPL-2.0)", "3.11.8", "https://github.com/OpenVPN/openvpn3",
         [need(o3 / "LICENSE.md"), need(o3 / "LICENSES" / "MPL-2.0.txt")]),
        ("OpenSSL", "3.5.9", "https://www.openssl.org", [need(SRC / "openssl" / "LICENSE.txt")]),
        ("asio (with OpenVPN's patches)", "1.24.0", "https://think-async.com/Asio/", [need(SRC / "asio" / "asio" / "LICENSE_1_0.txt")]),
        ("LZ4 library", "1.10.0", "https://github.com/lz4/lz4", [need(SRC / "lz4" / "lib" / "LICENSE")]),
    ]


def pom_licences(group, artifact, version, depth=0):
    """Licence names from a POM in the Gradle cache, following <parent> when it has none."""
    for pom in (GRADLE_CACHE / group / artifact / version).glob("*/*.pom"):
        root = ElementTree.parse(pom).getroot()
        ns = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
        names = [(lic.findtext(ns + "name") or "").strip() for lic in root.iterfind(f"{ns}licenses/{ns}license")]
        if names:
            return names
        parent = root.find(ns + "parent")
        if parent is not None and depth < 5:
            return pom_licences(parent.findtext(ns + "groupId"), parent.findtext(ns + "artifactId"),
                                parent.findtext(ns + "version"), depth + 1)
    return []


def maven():
    out = subprocess.run(["./gradlew", "-q", ":app:dependencies", "--configuration", "releaseRuntimeClasspath"],
                         cwd=ROOT, check=True, capture_output=True, text=True).stdout
    coords = set()
    for line in out.splitlines():
        m = re.search(r"([\w.-]+):([\w.-]+)(?::([\w.+-]+))?(?: -> ([\w.+-]+))?( \([cn*]\))?\s*$", line)
        if not m or "--- " not in line or (m.group(5) and m.group(5).strip() in ("(c)", "(n)")):
            continue
        group, artifact, version, resolved = m.group(1), m.group(2), m.group(3), m.group(4)
        version = resolved or version
        if version and not artifact.endswith("-bom"):
            coords.add((group, artifact, version))
    comps = []
    for group, artifact, version in sorted(coords):
        names = pom_licences(group, artifact, version)
        if not names:
            sys.exit(f"no licence in the POM of {group}:{artifact}:{version} (is it in the Gradle cache?)")
        spdx = "Apache-2.0" if all("Apache" in n and "2.0" in n for n in names) else " / ".join(names)
        comps.append((f"{group}:{artifact}", version, spdx))
    return comps


def main():
    go, nat, mvn = go_modules(), native(), maven()
    texts = []  # (title, text), deduplicated by text
    seen = {}

    def add_text(title, path):
        text = Path(path).read_text(errors="replace").strip()
        if text in seen:
            seen[text].append(title)
            return
        seen[text] = [title]
        texts.append(text)

    rows = []
    for section, comps in (("Native libraries (C/C++)", nat), ("Go modules", go)):
        rows.append(f"\n## {section}\n\n| Component | Version | Licence |\n| --- | --- | --- |")
        for name, version, url, files in comps:
            spdx = " AND ".join(dict.fromkeys(
                classify(Path(f).read_text(errors="replace")) for f in files if not Path(f).name.upper().startswith("NOTICE")))
            if name.startswith("OpenVPN 3 Core"):
                spdx = "MPL-2.0 (dual-licensed AGPL-3.0-only OR MPL-2.0)"
            rows.append(f"| [{name}]({url}) | {version} | {spdx} |")
            for f in files:
                add_text(f"{name} {version}: {Path(f).name}", f)
    rows.append("\n## Android and Kotlin libraries\n\n| Component | Version | Licence |\n| --- | --- | --- |")
    for name, version, spdx in mvn:
        rows.append(f"| {name} | {version} | {spdx} |")
    apache = SRC / "openssl" / "LICENSE.txt"  # the verbatim Apache License 2.0
    add_text("Android and Kotlin libraries listed in THIRD_PARTY_NOTICES.md (Apache-2.0)", apache)

    summary = f"""# Third-party notices

HybridVPN is licensed under the GNU General Public License v3.0 or later (see [LICENSE](LICENSE)).
It includes the components below, each under its own licence. The full licence texts ship in the
app (Settings → Open-source licences) and in
[`app/src/main/assets/third_party_licenses.txt`](app/src/main/assets/third_party_licenses.txt).

Generated by `scripts/gen-notices.py` from what the release build links: the Go modules in
`libhybridvpn_go.so`, the native libraries compiled into it, and the release runtime classpath.
Build and test tools (Gradle, the Android Gradle plugin, the NDK, JUnit, the OpenVPN 2 test server
in `scripts/ovpnlab/`) are not distributed and are not listed.

OpenVPN 3 Core is used under the Mozilla Public License 2.0. Its source, including OpenVPN's asio
patches, is available at the URL below; `scripts/openvpn3-deps.sh` fetches the exact version used.

Filter lists that the app downloads at the user's request (for example AdGuard DNS filter, hosts
files) are not part of the app; their own licences apply to them.
{chr(10).join(rows)}

## Trademarks

OpenVPN is a registered trademark of OpenVPN Inc. Tailscale is a trademark of Tailscale Inc.
AdGuard is a trademark of AdGuard Software Ltd. Android is a trademark of Google LLC. HybridVPN is
an independent project and is not affiliated with, endorsed by or sponsored by any of them.
"""
    (ROOT / "THIRD_PARTY_NOTICES.md").write_text(summary)

    out = ["HybridVPN — open-source licences",
           "",
           "HybridVPN is free software, licensed under the GNU General Public License v3.0 or later.",
           "Its complete source code is published in the project's public repository.",
           "It includes the components below, each under the licence that follows its name.",
           ""]
    for text in texts:
        titles = seen[text]
        out.append("=" * 78)
        out.extend(titles)
        out.append("=" * 78)
        out.append(text)
        out.append("")
    asset = ROOT / "app" / "src" / "main" / "assets" / "third_party_licenses.txt"
    asset.parent.mkdir(parents=True, exist_ok=True)
    asset.write_text("\n".join(out) + "\n")
    (asset.parent / "gpl-3.0.txt").write_text((ROOT / "LICENSE").read_text())
    print(f"{len(nat)} native, {len(go)} Go, {len(mvn)} Android/JVM components; {len(texts)} distinct licence texts; "
          f"{asset.stat().st_size // 1024} KiB")


if __name__ == "__main__":
    main()
