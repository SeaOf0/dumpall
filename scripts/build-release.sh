#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
RELEASE_DIR="${1:-$ROOT/../dumpall-release}"

cd "$ROOT"
STRICT_BUILD=1 sh scripts/build-matrix.sh build
mkdir -p "$RELEASE_DIR/bin"

# Keep the release bundle self-contained and reproducible.  The source tree is
# the authority for operator docs and platform installers.
cp README.md 使用手册.md NOTICE.txt "$RELEASE_DIR/"
cp scripts/install.sh scripts/install.ps1 "$RELEASE_DIR/"
chmod 0755 "$RELEASE_DIR/install.sh"
mkdir -p "$RELEASE_DIR/docs"
cp docs/ARCHITECTURE.md docs/CAPABILITY_MATRIX.md docs/TRIAGE_COVERAGE.md docs/dumpall_采集能力清单.xlsx "$RELEASE_DIR/docs/"
mkdir -p "$RELEASE_DIR/scripts/ir"
cp -R scripts/ir/. "$RELEASE_DIR/scripts/ir/"

ARTIFACTS="dumpall-linux-amd64-musl dumpall-linux-x86-musl dumpall-linux-arm64-musl dumpall-linux-arm32 dumpall-windows-amd64.exe dumpall-windows-x86.exe dumpall-windows-arm64.exe"
for artifact in $ARTIFACTS; do
    cp "dist/$artifact" "$RELEASE_DIR/bin/$artifact"
done

if command -v sha256sum >/dev/null 2>&1; then
    (cd "$RELEASE_DIR" && find . -type f ! -name SHA256SUMS.txt -print | LC_ALL=C sort | while IFS= read -r file; do sha256sum "$file"; done > SHA256SUMS.txt)
else
    (cd "$RELEASE_DIR" && find . -type f ! -name SHA256SUMS.txt -print | LC_ALL=C sort | while IFS= read -r file; do shasum -a 256 "$file"; done > SHA256SUMS.txt)
fi

printf "发布目录已生成: %s\n" "$RELEASE_DIR"
