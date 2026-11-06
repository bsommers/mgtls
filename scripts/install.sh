#!/usr/bin/env bash
# install.sh — Multi-target installer for mgtls (Local, Global, Custom Prefix, or GitHub Releases)
set -euo pipefail

TOOL_NAME="mgtls"
GITHUB_REPO="bsommers/mgtls"
VERSION="${MGTLS_VERSION:-v1.1.1}"

SCOPE="local"
CUSTOM_PREFIX="${PREFIX:-}"
COPY_MODE=1
DRY_RUN=0
UNINSTALL=0
FORCE=0
FROM_RELEASE=0

usage() {
  cat <<EOF
${TOOL_NAME} installer (${VERSION})

Usage:
  ./install.sh [options]

Scopes:
  --local          Install to \${XDG_BIN_HOME:-\$HOME/.local/bin} (default, unprivileged)
  --global         Install to /usr/local/bin (requires write access)
  --prefix DIR     Install to DIR/bin (custom prefix for CI, containers, or sandboxes)

Options:
  --copy           Copy binary into target directory (default)
  --from-release   Download prebuilt binary + SHA256SUMS from GitHub Releases (${GITHUB_REPO})
  --version TAG    Release tag to download when using --from-release (default: ${VERSION})
  --dry-run        Print actions without modifying the filesystem
  --uninstall      Remove managed ${TOOL_NAME} binary and data directory
  --force          Overwrite existing unmanaged binary at destination
  -h, --help       Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --local)
      SCOPE="local"
      shift
      ;;
    --global)
      SCOPE="global"
      COPY_MODE=1
      shift
      ;;
    --prefix)
      if [[ $# -lt 2 ]]; then
        echo "error: --prefix requires a directory argument" >&2
        exit 1
      fi
      SCOPE="prefix"
      CUSTOM_PREFIX="$2"
      shift 2
      ;;
    --prefix=*)
      SCOPE="prefix"
      CUSTOM_PREFIX="${1#*=}"
      shift
      ;;
    --copy)
      COPY_MODE=1
      shift
      ;;
    --from-release)
      FROM_RELEASE=1
      shift
      ;;
    --version)
      VERSION="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --uninstall)
      UNINSTALL=1
      shift
      ;;
    --force)
      FORCE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option '$1' (run './install.sh --help')" >&2
      exit 1
      ;;
  esac
done

# Resolve target bin and share directories
if [[ -n "$CUSTOM_PREFIX" && "$SCOPE" != "global" ]]; then
  SCOPE="prefix"
fi

case "$SCOPE" in
  local)
    BIN_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
    SHARE_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/${TOOL_NAME}"
    ;;
  global)
    BIN_DIR="/usr/local/bin"
    SHARE_DIR="/usr/local/share/${TOOL_NAME}"
    ;;
  prefix)
    mkdir -p "$CUSTOM_PREFIX" 2>/dev/null || true
    ABS_PREFIX="$(cd "$CUSTOM_PREFIX" 2>/dev/null && pwd || echo "$CUSTOM_PREFIX")"
    BIN_DIR="${ABS_PREFIX}/bin"
    SHARE_DIR="${ABS_PREFIX}/share/${TOOL_NAME}"
    ;;
esac

TARGET_BIN="${BIN_DIR}/${TOOL_NAME}"
MARKER_FILE="${SHARE_DIR}/.managed-by-mgtls-installer"

run_cmd() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] $*"
  else
    "$@"
  fi
}

if [[ "$UNINSTALL" -eq 1 ]]; then
  if [[ -e "$TARGET_BIN" ]]; then
    if [[ ! -f "$MARKER_FILE" && "$FORCE" -eq 0 ]]; then
      echo "error: ${TARGET_BIN} was not recorded as managed by install.sh (pass --force to remove anyway)" >&2
      exit 1
    fi
    run_cmd rm -f "$TARGET_BIN"
    echo "Removed ${TARGET_BIN}"
  else
    echo "Nothing to uninstall at ${TARGET_BIN}"
  fi
  if [[ -d "$SHARE_DIR" ]]; then
    run_cmd rm -rf "$SHARE_DIR"
    echo "Removed ${SHARE_DIR}"
  fi
  exit 0
fi

# Prevent clobbering an unmanaged binary unless --force is passed
if [[ -e "$TARGET_BIN" && ! -f "$MARKER_FILE" && "$FORCE" -eq 0 ]]; then
  echo "error: ${TARGET_BIN} already exists and is unmanaged (pass --force to overwrite)" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
TMP_BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_BUILD_DIR"' EXIT
BUILT_BIN="${TMP_BUILD_DIR}/${TOOL_NAME}"

detect_platform() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  case "$os" in
    linux) os="linux" ;;
    darwin) os="darwin" ;;
    *)
      echo "error: unsupported OS '${os}'" >&2
      exit 1
      ;;
  esac
  case "$arch" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *)
      echo "error: unsupported architecture '${arch}'" >&2
      exit 1
      ;;
  esac
  echo "${os}-${arch}"
}

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "[dry-run] mkdir -p ${BIN_DIR} ${SHARE_DIR}"
  echo "[dry-run] install ${TOOL_NAME} -> ${TARGET_BIN}"
  echo "[dry-run] record marker ${MARKER_FILE}"
  exit 0
fi

if [[ "$FROM_RELEASE" -eq 0 && -f "${SCRIPT_DIR}/go.mod" && -d "${SCRIPT_DIR}/src/cmd/mgtls" ]] && command -v go >/dev/null 2>&1; then
  echo "Building ${TOOL_NAME} from local source (${SCRIPT_DIR})..."
  (cd "$SCRIPT_DIR" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$BUILT_BIN" ./src/cmd/mgtls)
elif [[ "$FROM_RELEASE" -eq 0 && -f "${SCRIPT_DIR}/../go.mod" && -d "${SCRIPT_DIR}/../src/cmd/mgtls" ]] && command -v go >/dev/null 2>&1; then
  REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
  echo "Building ${TOOL_NAME} from local source (${REPO_ROOT})..."
  (cd "$REPO_ROOT" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$BUILT_BIN" ./src/cmd/mgtls)
else
  PLATFORM="$(detect_platform)"
  ASSET="mgtls-${PLATFORM}"
  BASE_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}"
  echo "Downloading ${ASSET} (${VERSION}) from ${BASE_URL}..."
  curl -fsSL "${BASE_URL}/${ASSET}" -o "${TMP_BUILD_DIR}/${ASSET}"
  curl -fsSL "${BASE_URL}/SHA256SUMS" -o "${TMP_BUILD_DIR}/SHA256SUMS"
  (
    cd "$TMP_BUILD_DIR"
    if command -v sha256sum >/dev/null 2>&1; then
      grep "  ${ASSET}\$" SHA256SUMS | sha256sum -c -
    elif command -v shasum >/dev/null 2>&1; then
      grep "  ${ASSET}\$" SHA256SUMS | shasum -a 256 -c -
    fi
  )
  mv "${TMP_BUILD_DIR}/${ASSET}" "$BUILT_BIN"
  chmod 0755 "$BUILT_BIN"
fi

mkdir -p "$BIN_DIR" "$SHARE_DIR"
cp -f "$BUILT_BIN" "$TARGET_BIN"
chmod 0755 "$TARGET_BIN"
printf "version=%s\ninstalled_at=%s\nscope=%s\n" "$VERSION" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$SCOPE" > "$MARKER_FILE"

echo "Installed ${TOOL_NAME} to ${TARGET_BIN}"

if [[ ":${PATH}:" != *":${BIN_DIR}:"* ]]; then
  echo "" >&2
  echo "Note: ${BIN_DIR} is not in your PATH. Add it with:" >&2
  echo "  export PATH=\"${BIN_DIR}:\$PATH\"" >&2
fi

cat >&2 <<EOF

Next steps:
  1. mgtls init --with-root-ca --starter   # initialize workspace, Root CA, and starter mgtls.yaml
  2. mgtls doctor                          # verify store health and 0600 key permissions
  3. mgtls guide                           # view the full end-to-end workflow guide
EOF
