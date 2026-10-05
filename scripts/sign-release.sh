#!/bin/sh
# Sign or verify a TomPanel release manifest (Ed25519, per
# docs/release-signing.md). The signature covers exactly "version\nsha256".
#
# Sign (offline machine holding release.pem):
#   sh sign-release.sh sign /path/to/release.pem tompanel_1.2.0_amd64.deb 1.2.0
#   → prints the ReleaseManifest JSON to publish with the release
#
# Verify (any machine, using the published release.pub PEM):
#   sh sign-release.sh verify /path/to/release.pub tompanel_1.2.0_amd64.deb 1.2.0 < signature.b64
#   → exits 0 when the signature matches
set -eu

usage() {
  cat <<EOF
Usage:
  sh sign-release.sh sign   <private-key.pem> <file.deb> <version>
  sh sign-release.sh verify <release.pub.pem> <file.deb> <version> < signature.b64
EOF
  exit 0
}

fail() { echo "ERROR: $1" >&2; exit 1; }

[ "$#" -ge 1 ] || usage
MODE="$1"
shift

command -v openssl >/dev/null 2>&1 || fail "openssl is required"
command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 ||
  fail "sha256sum or shasum is required"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

case "$MODE" in
  sign)
    [ "$#" -eq 3 ] || usage
    KEY="$1"; FILE="$2"; VERSION="$3"
    [ -f "$KEY" ] || fail "private key $KEY not found"
    [ -f "$FILE" ] || fail "package $FILE not found"
    SHA256=$(sha256_of "$FILE")
    PAYLOAD_FILE=$(mktemp)
    SIG_FILE=$(mktemp)
    trap 'rm -f "$PAYLOAD_FILE" "$SIG_FILE"' EXIT
    printf '%s\n%s' "$VERSION" "$SHA256" > "$PAYLOAD_FILE"
    openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$PAYLOAD_FILE" -out "$SIG_FILE" ||
      fail "signing failed (is $KEY the Ed25519 private key?)"
    [ -s "$SIG_FILE" ] || fail "signing produced no signature"
    SIGNATURE=$(base64 < "$SIG_FILE" | tr -d '\n')
    URL="https://github.com/Dhanabhon/tom-panel/releases/download/v${VERSION}/$(basename "$FILE")"
    echo "Signature generated. ReleaseManifest for the updater:"
    cat <<EOF
{
  "version": "$VERSION",
  "sha256": "$SHA256",
  "signature": "$SIGNATURE",
  "url": "$URL"
}
EOF
    echo
    echo "Verify later with:"
    echo "  sh sign-release.sh verify <release.pub> $FILE $VERSION < signature.b64"
    ;;
  verify)
    [ "$#" -eq 3 ] || usage
    KEY="$1"; FILE="$2"; VERSION="$3"
    [ -f "$KEY" ] || fail "public key $KEY not found (export the PEM form: openssl pkey -in release.pem -pubout -out release.pub)"
    [ -f "$FILE" ] || fail "package $FILE not found"
    SHA256=$(sha256_of "$FILE")
    PAYLOAD_FILE=$(mktemp)
    SIG_FILE=$(mktemp)
    trap 'rm -f "$PAYLOAD_FILE" "$SIG_FILE"' EXIT
    printf '%s\n%s' "$VERSION" "$SHA256" > "$PAYLOAD_FILE"
    base64 -d > "$SIG_FILE" 2>/dev/null || base64 -D > "$SIG_FILE" 2>/dev/null
    [ -s "$SIG_FILE" ] || fail "no base64 signature on stdin"
    if openssl pkeyutl -verify -pubin -inkey "$KEY" -rawin -in "$PAYLOAD_FILE" -sigfile "$SIG_FILE" >/dev/null 2>&1; then
      echo "OK: signature valid for $VERSION ($SHA256)"
    else
      fail "signature INVALID for $VERSION"
    fi
    ;;
  *) usage ;;
esac
