#!/bin/sh
# TomPanel one-command bootstrap for Ubuntu Server 24.04 LTS (AMD64).
#
# Recommended invocation (keeps stdout a TTY so the one-time setup URL can
# be printed at the end):
#
#   curl -fsSL https://raw.githubusercontent.com/Dhanabhon/tom-panel/main/scripts/bootstrap.sh -o tompanel-bootstrap.sh
#   sh tompanel-bootstrap.sh
#
# The script downloads a release, verifies its SHA-256, and hands off to the
# shipped install.sh. The browser first-run setup stays the only wizard; this
# only gets the server to the point of printing a setup URL.
set -eu

REPO="${TOMPANEL_REPO:-Dhanabhon/tom-panel}"
VERSION="${TOMPANEL_VERSION:-}"
OFFLINE=""
CHECK=""

usage() {
  cat <<EOF
Usage: sh tompanel-bootstrap.sh [version] [--offline /path/to.deb] [--check]

  version              pin a release tag, e.g. 1.2.0 (default: latest)
  --offline /path.deb  install a local .deb (installer is still fetched)
  --check              preflight only: verify the host, change nothing
  -h, --help           show this help

Environment: TOMPANEL_REPO overrides the GitHub repository (owner/name).
             PANEL_DOMAIN=panel.example.com prints post-install steps for
             exposing the panel on that domain with HTTPS.
EOF
  exit 0
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --offline)
      [ "${2:-}" != "" ] || { echo "ERROR: --offline needs a path" >&2; exit 1; }
      OFFLINE="$2"; shift 2 ;;
    --check) CHECK=1; shift ;;
    -h|--help) usage ;;
    -*) echo "ERROR: unknown option $1 (see --help)" >&2; exit 1 ;;
    *) VERSION="$1"; shift ;;
  esac
done

fail() { echo "ERROR: $1" >&2; exit 1; }
note() { echo "==> $1"; }

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"
[ "$(uname -m)" = "x86_64" ] || fail "only AMD64 is supported"
[ "$(id -u)" = "0" ] || fail "run as root (the installer configures the host)"

work="$(mktemp -d /tmp/tompanel-bootstrap.XXXXXX)"
trap 'rm -rf "$work"' EXIT

if [ -n "$OFFLINE" ] && [ -n "$CHECK" ]; then
  fail "--check with --offline is not supported; run scripts/install.sh from the repository with TOMPANEL_CHECK=1 instead"
fi

if [ -n "$OFFLINE" ]; then
  [ -f "$OFFLINE" ] || fail "offline package $OFFLINE not found"
  note "using offline package $OFFLINE"
  cp "$OFFLINE" "$work/package.deb"
  if [ -f "$OFFLINE.sha256" ]; then
    (cd "$(dirname "$OFFLINE")" && sha256sum -c "$(basename "$OFFLINE").sha256") \
      || fail "offline checksum mismatch; refusing to install"
    note "offline checksum verified"
  fi
else
  if [ -z "$VERSION" ]; then
    note "resolving the latest release"
    VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
      sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
    [ -n "$VERSION" ] || fail "could not resolve the latest release (pass a version or set TOMPANEL_VERSION)"
  fi
  case "$VERSION" in
    v*) ;;
    *) VERSION="v$VERSION" ;;
  esac
  if [ -n "$CHECK" ]; then
    note "preflight mode: skipping package download"
  else
    asset_version="${VERSION#v}"
    base="https://github.com/$REPO/releases/download/$VERSION"
    note "downloading TomPanel $VERSION"
    curl -fsSL -o "$work/tompanel_${asset_version}_amd64.deb" \
      "$base/tompanel_${asset_version}_amd64.deb"
    curl -fsSL -o "$work/tompanel_${asset_version}_amd64.deb.sha256" \
      "$base/tompanel_${asset_version}_amd64.deb.sha256"
    (cd "$work" && sha256sum -c "tompanel_${asset_version}_amd64.deb.sha256") \
      || fail "checksum mismatch; refusing to install"
    note "checksum verified"
  fi
fi

if [ -z "$OFFLINE" ]; then
  note "downloading the installer shipped with $VERSION"
  curl -fsSL -o "$work/install.sh" \
    "https://raw.githubusercontent.com/$REPO/$VERSION/scripts/install.sh" ||
    curl -fsSL -o "$work/install.sh" \
      "https://github.com/$REPO/releases/download/$VERSION/install.sh" ||
    fail "could not download the installer for $VERSION"
fi

note "downloading the installer shipped with $VERSION"
curl -fsSL -o "$work/install.sh" \
  "https://raw.githubusercontent.com/$REPO/$VERSION/scripts/install.sh" ||
  curl -fsSL -o "$work/install.sh" \
    "https://github.com/$REPO/releases/download/$VERSION/install.sh" ||
  fail "could not download the installer for $VERSION"

if [ -n "$CHECK" ]; then
  note "running preflight only (no changes will be made)"
  TOMPANEL_CHECK=1 sh "$work/install.sh" "$work/package.deb"
  exit 0
fi

note "handing off to the installer"
sh "$work/install.sh" "$work/package.deb"

config=/etc/tompanel/config.toml
echo
echo "TomPanel is installed and running in private mode."
echo
echo "1) From your own computer, open the tunnel:"
echo "   ssh -L 8080:127.0.0.1:8080 <you>@<this-server>"
echo
echo "2) Then open:  http://127.0.0.1:8080"
if [ -t 1 ]; then
  note "generating your one-time setup URL"
  setup_url=$(sudo -u tompanel /usr/lib/tompanel/tompanel -config "$config" setup-url || true)
  if [ -n "$setup_url" ]; then
    echo
    echo "3) Open this single-use URL within 15 minutes:"
    echo "   $setup_url"
  else
    echo "3) Print your one-time setup URL on this server:"
    echo "   sudo -u tompanel /usr/lib/tompanel/tompanel -config $config setup-url"
  fi
else
  echo "3) Print your one-time setup URL on this server (interactive):"
  echo "   sudo -u tompanel /usr/lib/tompanel/tompanel -config $config setup-url"
fi
echo
echo "Uninstall later with: apt-get remove tompanel (sites and backups are"
echo "preserved; see scripts/uninstall.sh in the repository for data removal)."
if [ -n "${PANEL_DOMAIN:-}" ]; then
    PANEL_PORT="${PANEL_PORT:-4884}"
    echo
    echo "Panel domain: after first-run setup, open Settings → Panel endpoint,"
    echo "choose Public HTTPS, enter ${PANEL_DOMAIN}, an ACME email, and port"
    echo "${PANEL_PORT} (or your own non-standard port), then queue the change."
    echo "DNS first: point ${PANEL_DOMAIN} at this server. Behind Cloudflare"
    echo "proxy only ports 443 or 8443 work — port ${PANEL_PORT} requires"
    echo "DNS-only or direct access."
fi
