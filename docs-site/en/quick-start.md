# Quick Start

## Requirements

- Fresh Ubuntu Server 24.04 LTS (AMD64)
- 900+ MB RAM, 10+ GB disk
- Docker installed
- Root access

## Install

```bash
git clone https://github.com/Dhanabhon/tom-panel.git
cd tomlpanel
sudo sh scripts/quick-install.sh
```

The script builds a reproducible `.deb` from source, installs it, and prints your one-time setup URL.

## First-run wizard

1. Open the SSH tunnel from your computer:
   ```bash
   ssh -L 8080:127.0.0.1:8080 root@your-server
   ```
2. Open `http://127.0.0.1:8080` in your browser.
3. The wizard guides you through:
   - Creating your administrator account
   - Saving your TOTP secret (scan the QR code with your authenticator app)
   - Writing down your recovery codes (shown once — store them offline)

## Create your first site

1. Navigate to **Sites** → **Create site**.
2. Choose the type (Static, PHP, or Reverse Proxy).
3. Enter your domain name.
4. Click **Create and provision** — TomPanel sets up Nginx, directories, and PHP-FPM.

## Next steps

- [Connect your domain and SSL](domains.md)
- [Upload files via File Manager or SFTP](files.md)
- [Create a database](databases.md)
- [Install WordPress or deploy Laravel](apps.md)
