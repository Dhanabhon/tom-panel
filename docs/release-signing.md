# TomPanel release signing

TomPanel stable releases are Ed25519-signed and verified by the panel's
updater before anything is staged or installed.

## Offline key ceremony

1. Generate the release key on an offline machine:

   ```sh
   openssl genpkey -algorithm ed25519 -out release.pem
   openssl pkey -in release.pem -pubout -out release.pub
   ```

2. The **private key never touches a build machine or the panel**. Store it
   on offline media; a hardware token is recommended.

3. Derive the 64-character hex form operators install:

   ```sh
   openssl pkey -in release.pub -pubout -outform DER | tail -c 32 | xxd -p -c 64
   ```

## Signing a release

The signature covers exactly `version\nsha256` of the `.deb`:

```sh
printf '%s\n%s' "$VERSION" "$SHA256" > /tmp/payload
openssl pkeyutl -sign -inkey release.pem -rawin -in /tmp/payload | base64
```

Publish the `.deb`, its SHA-256, the base64 signature, and the version in
the release notes. The panel rejects every manifest whose signature,
checksum, or HTTPS download URL does not verify.

## Key distribution and rotation

- Operators set `TOMPANEL_RELEASE_KEY` (hex public key) before enabling
  panel updates; without a key, updates fail closed.
- To rotate, sign the next release with both the old and new keys during a
  transition window, then publish the new key and drop the old one.

## Checksum generation

```sh
sha256sum tompanel_VERSION_amd64.deb > tompanel_VERSION_amd64.deb.sha256
```
