#!/usr/bin/env python3
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
"""Test the real Java leaf patcher with ephemeral certificates, without Soong or a device.

Requires JDK 21 and an existing framework.jar containing the internal BC classes.
Only temporary Log/Build stubs and class files are written; production sources and
build outputs are never modified. All cryptographic keys stay in the test JVM.
"""

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = Path(__file__).resolve().parents[4]
CORE = ROOT / "frameworks/base/core/java/android/security/yasvara"
FRAMEWORK_JAR = ROOT / (
    "out/soong/.intermediates/frameworks/base/framework-minus-apex/"
    "android_common/jarjar/framework.jar"
)
STUBS = {
    "android/util/Log.java": """\
package android.util;
public final class Log {
    private Log() {}
    public static int w(String tag, String message) {
        System.err.println(tag + ": " + message);
        return 0;
    }
    public static int w(String tag, String message, Throwable error) {
        System.err.println(tag + ": " + message);
        error.printStackTrace(System.err);
        return 0;
    }
}
""",
    "android/os/Build.java": """\
package android.os;
public final class Build {
    private Build() {}
    public static final String BRAND = "host-build-brand";
    public static final String DEVICE = "host-build-device";
    public static final String PRODUCT = "host-build-product";
    public static final String MANUFACTURER = "host-build-manufacturer";
    public static final String MODEL = "host-build-model";
}
""",
}


def run(command, *, cwd, timeout):
    print("+", " ".join(map(str, command)), flush=True)
    subprocess.run(command, cwd=cwd, check=True, timeout=timeout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--java-home", type=Path, help="JDK 21 home (default: java/javac on PATH)")
    parser.add_argument("--framework-jar", type=Path, default=FRAMEWORK_JAR,
                        help="existing framework.jar with internal Bouncy Castle classes")
    args = parser.parse_args()
    framework = args.framework_jar.resolve()
    sources = [CORE / "YasvaraAttestation.java", CORE / "YasvaraLeafPatcher.java",
               HERE / "LeafPatcherHostTest.java"]
    for path in [framework, *sources]:
        if not path.is_file():
            parser.error(f"required existing input is missing: {path}; this runner never builds it")

    tools = {}
    for tool in ("javac", "java"):
        executable = (str(args.java_home.resolve() / "bin" / tool) if args.java_home
                      else shutil.which(tool))
        if not executable:
            parser.error(f"{tool} not found; provide --java-home pointing to JDK 21")
        version = subprocess.run([executable, "-version"], check=True, capture_output=True,
                                 text=True, timeout=10)
        text = (version.stdout + version.stderr).strip()
        if not re.search(r'\b21(?:[.+\-\s]|"|$)', text.splitlines()[0]):
            parser.error(f"JDK 21 required, got {text.splitlines()[0]}")
        tools[tool] = executable
        print(text.splitlines()[0], flush=True)

    # Never put generated sources/classes under the live Android build tree.
    with tempfile.TemporaryDirectory(prefix="yasvara-leaf-patcher-") as temporary:
        work = Path(temporary)
        stubs = work / "stubs"
        classes = work / "classes"
        classes.mkdir()
        stub_sources = []
        for relative, content in STUBS.items():
            source = stubs / relative
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(content, encoding="utf-8")
            stub_sources.append(source)
        run([tools["javac"], "--release", "17", "-encoding", "UTF-8", "-proc:none",
             "-implicit:none", "-classpath", str(framework), "-sourcepath", str(stubs),
             "-d", str(classes), *map(str, stub_sources), *map(str, sources)],
            cwd=work, timeout=60)
        # Fresh production classes and JNI-free stubs must take precedence over the jar.
        run([tools["java"], "-ea", "-XX:-UsePerfData", f"-Djava.io.tmpdir={work}",
             "-cp", os.pathsep.join((str(classes), str(framework))),
             "android.security.yasvara.LeafPatcherHostTest"], cwd=work, timeout=90)


if __name__ == "__main__":
    main()
