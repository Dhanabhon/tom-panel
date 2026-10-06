# แก้ปัญหา

## รัน doctor

```bash
sudo tompanel -config /etc/tompanel/config.toml doctor
```

ตรวจ: master key, state directory, disk, database, agent socket, Nginx, UFW, systemd — exit code ไม่เป็น 0 ถ้ามีปัญหา

## ปัญหาที่พบบ่อย

### แผงไม่เริ่มทำงาน

```bash
sudo journalctl -u tompanel.service -n 20 --no-pager
sudo journalctl -u tomlpanel-agent.service -n 20 --no-pager
```

เช็ค:
- `/etc/tompanel/master.key` มีและ mode `0400`
- `/var/lib/tompanel` เขียนได้โดย user `tompanel`
- Agent socket มีที่ `/run/tompanel/agent.sock`

### เข้าแผงไม่ได้

แผงรับฟังที่ `127.0.0.1:8080` เท่านั้น — ต้องเปิด SSH tunnel:

```bash
ssh -L 8080:127.0.0.1:8080 root@your-server
```

### Setup URL ใช้ไม่ได้

สร้างใหม่:

```bash
sudo runuser -u tompanel -- /usr/lib/tompanel/tompanel -config /etc/tompanel/config.toml setup-url
```

URL หมดอายุ 15 นาที ใช้ได้ครั้งเดียว

### สร้างเว็บล้ม

1. ดู error ใน Dashboard
2. สาเหตุบ่อย: DNS ยังไม่ชี้มา, port ถูกใช้, ดิสก์ไม่พอ

### ฐานข้อมูลเชื่อมไม่ได้

```bash
sudo systemctl status mariadb
sudo mysqladmin ping
```

### ออกใบรับรองล้ม

- DNS-01: เช็คว่า Cloudflare API token มีสิทธิ์ Zone:Read และ DNS:Edit
- HTTP-01: เช็คว่า port 80 เปิดใน UFW

### Redis cache ไม่ทำงาน

```bash
sudo systemctl status redis-server
redis-cli -s /run/redis/redis-server.sock ping
```

## รีเซ็ตทั้งหมด

```bash
sudo apt-get remove --purge tomlpanel
sudo rm -rf /etc/tompanel /var/lib/tompanel /srv/tompanel
```

> **คำเตือน:** ลบทุกอย่าง — เว็บ, ฐานข้อมูล, backups ส่งออกข้อมูลก่อน!
