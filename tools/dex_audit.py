#!/usr/bin/env python3
# 火漆 · Sealing Wax — release dex audit.
#
# Guards against the two R8 failure classes we actually hit:
#   1. visibility inversion: a PUBLIC class extending a package-private
#      superclass across packages -> IllegalAccessError at first load
#      (crashed ProcessLifecycleInitializer startup in the first release
#      build);
#   2. silently dropping required classes (a mis-scoped optimization block
#      once stripped everything except -keep'ed classes).
#
# Usage: dex_audit.py <apk>
# Needs dexdump (from Android build-tools) in PATH or under ANDROID_HOME.
# Exit 0 = clean; exit 1 = problems found (printed).
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

PROBE_CLASSES = [
    "Lsealing/wax/MainActivity;",
    "Lsealing/wax/bridge/WaxNative;",
    "Lsealing/wax/store/Persistence;",
    "Lsealing/wax/ui/ChatScreenKt;",
    "Landroidx/lifecycle/ProcessLifecycleInitializer;",
    "Landroidx/startup/InitializationProvider;",
]
PROBE_PREFIXES = [
    ("Lcom/google/crypto/tink/", 100),
    ("Lcom/google/zxing/", 10),
]


def find_dexdump():
    cand = shutil.which("dexdump")
    if cand:
        return cand
    home = os.environ.get("ANDROID_HOME", "/opt/android-sdk")
    hits = sorted(glob.glob(f"{home}/build-tools/*/dexdump"))
    if hits:
        return hits[-1]
    sys.exit("error: dexdump not found (PATH or ANDROID_HOME/build-tools)")


def parse_dex(text):
    classes = {}
    cur = None
    for line in text.splitlines():
        m = re.match(r"\s*Class descriptor\s*:\s*'(\S+)'", line)
        if m:
            cur = m.group(1)
            classes[cur] = ("", "")
            continue
        if cur:
            m = re.match(r"\s*Access flags\s*:\s*(.*)", line)
            if m:
                access, sup = classes[cur]
                classes[cur] = (m.group(1).strip(), sup)
            m = re.match(r"\s*Superclass\s*:\s*'(\S+)'", line)
            if m:
                access, _ = classes[cur]
                classes[cur] = (access, m.group(1))
    return classes


def is_public(access):
    # dexdump prints e.g. "0x0401 (PUBLIC ABSTRACT)"; either representation
    # decides, and the hex bit (0x0001 = PUBLIC) is the authoritative one.
    m = re.match(r"0x([0-9a-fA-F]+)", access)
    if m:
        return int(m.group(1), 16) & 0x1 != 0
    return "PUBLIC" in access


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: dex_audit.py <apk>")
    apk = sys.argv[1]
    dexdump = find_dexdump()
    problems = []

    with tempfile.TemporaryDirectory() as tmp, zipfile.ZipFile(apk) as z:
        dexes = [n for n in z.namelist() if re.fullmatch(r"classes\d*\.dex", n)]
        if not dexes:
            sys.exit("error: no classes.dex in apk")
        z.extractall(tmp, members=dexes)
        classes = {}
        for name in dexes:
            out = subprocess.run(
                [dexdump, "-l", "plain", os.path.join(tmp, name)],
                capture_output=True, text=True, errors="replace",
            )
            if out.returncode != 0:
                sys.exit(f"error: dexdump failed on {name}")
            classes.update(parse_dex(out.stdout))

    print(f"classes: {len(classes)}")

    for desc, (access, sup) in classes.items():
        if not sup or sup in ("Ljava/lang/Object;", "-"):
            continue
        if sup not in classes:
            continue    # framework/library-external parent: not R8's doing
        sup_access = classes[sup][0]
        if is_public(access) and not is_public(sup_access):
            if desc.rsplit("/", 1)[0] != sup.rsplit("/", 1)[0]:
                problems.append(
                    f"visibility inversion: {desc} (public) extends "
                    f"{sup} (package-private, different package)"
                )

    for probe in PROBE_CLASSES:
        if probe not in classes:
            problems.append(f"missing required class: {probe}")
    for prefix, minimum in PROBE_PREFIXES:
        n = sum(1 for c in classes if c.startswith(prefix))
        print(f"{prefix}*: {n} classes")
        if n < minimum:
            problems.append(
                f"library stripped: {prefix}* has only {n} classes (<{minimum})"
            )

    if problems:
        print("\nDEX AUDIT FAILED:")
        for p in problems:
            print("  -", p)
        sys.exit(1)
    print("DEX AUDIT PASSED")


if __name__ == "__main__":
    main()
