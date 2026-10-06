# Troubleshooting

## Run the doctor

The CLI includes a read-only health check:

```bash
sudo tompanel -config /etc/tompanel/config.toml doctor
```

This checks: master key, state directory, disk space, database, agent socket, Nginx, UFW, and systemd. Exit code is non-zero if anything fails.

## Common issues

### Panel won't start

```bash
sudo journalctl -u tompanel.service -n 20 --no-pager
sudo journalctl -u tomlpanel-agent.service -n 20 --no-pager
```

Check:
- `/etc/tompanel/master.key` exists with mode `0400`
- `/var/lib/tompanel` is writable by the `tompanel` user
- The agent socket exists at `/run/tompanel/agent.sock`

### Can't access the panel

The panel listens on `127.0.0.1:8080` only. Make sure your SSH tunnel is active:

```bash
ssh -L 8080:127.0.0.1:8080 root@your-server
```

### Setup URL doesn't work

Generate a new one:

```bash
sudo runuser -u tompanel -- /usr/lib/tompanel/tompanel -config /etc/tompanel/config.toml setup-url
```

Setup URLs expire after 15 minutes and can only be used once.

### Site provisioning failed

1. Check the job error on the Dashboard
2. Common causes:
   - DNS not yet pointing to the server
   - Port already in use by another service
   - Insufficient disk space

### Database connection refused

```bash
sudo systemctl status mariadb
sudo mysqladmin ping
```

### Certificate issuance failed

- DNS-01: verify your Cloudflare API token has Zone:Read and DNS:Edit permissions
- HTTP-01: verify port 80 is open in UFW (`sudo ufw status`)

### Redis object cache not working

```bash
sudo systemctl status redis-server
redis-cli -s /run/redis/redis-server.sock ping
```

## Reset everything

```bash
sudo apt-get remove --purge tomlpanel
sudo rm -rf /etc/tompanel /var/lib/tompanel /srv/tompanel
```

> **Warning:** This destroys all sites, databases, and backups. Export anything you need first.
