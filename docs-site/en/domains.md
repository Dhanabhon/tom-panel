# Domains & SSL

## Connect DNS

Before TomPanel can manage your domain, point it to your server:

1. Go to your DNS provider (Cloudflare, Route53, etc.)
2. Create an **A record**: `yourdomain.com` → `your-server-ip`
3. Wait for DNS propagation (usually 5–30 minutes)

## Configure Cloudflare (optional)

If you use Cloudflare for DNS:

1. Go to **Settings** → **Cloudflare**
2. Enter your **Zone ID** and **API Token**
3. Click **Save** then **Test connection**

With Cloudflare configured, TomPanel uses DNS-01 challenges for SSL certificates (no need to open port 80).

## Request an SSL certificate

1. Navigate to your site → **Domains & SSL**
2. Click **Issue certificate**
3. Choose the challenge type:
   - **DNS-01** (recommended if Cloudflare is configured) — no port 80 needed
   - **HTTP-01** — requires port 80 open (TomPanel manages this automatically)
4. TomPanel issues the certificate, validates the Nginx configuration, and activates it

## Panel HTTPS endpoint

To expose the panel itself on a public domain (instead of SSH tunnel):

1. Go to **Settings** → **Panel endpoint**
2. Select **Public HTTPS**
3. Enter your hostname (e.g., `panel.yourdomain.com`), port (default: 4884), and ACME email
4. Click **Queue endpoint change**

TomPanel will:
- Issue a certificate for your hostname
- Configure Nginx with TLS
- Health-check the new address
- Keep the private (tunnel) route alive until the new one is verified

> **Cloudflare note:** The proxy only forwards HTTPS on ports 443 and 8443. If you enable the proxy, switch to one of those ports. Port 4884 requires DNS-only (grey cloud).

## Certificate renewal

TomPanel automatically renews certificates before they expire. Renewal failures are visible on the Domains page with retry options.
