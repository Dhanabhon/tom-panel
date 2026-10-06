# ความปลอดภัย

## การยืนยันตัวตน

TomPanel ใช้ระบบผู้ดูแลคนเดียว:

- **Password** — อย่างน้อย 12 ตัวอักษร
- **TOTP** — second factor บังคับ (แอป authenticator)
- **Recovery codes** — แสดงครั้งเดียวตอน setup ใช้ได้อย่างละครั้ง

### กู้คืน

ถ้าเข้าไม่ได้ รีเซ็ตจาก server console (ไม่ใช่ browser):

```bash
sudo tompanel -config /etc/tompanel/config.toml admin reset-password
sudo tompanel -config /etc/tompanel/config.toml admin set-username
sudo tompanel -config /etc/tompanel/config.toml admin reset-totp
```

## Step-up authentication

การกระทำที่อันตราย (ลบเว็บ, หมุนเวียน credential, ปิด SFTP, ติดตั้ง WordPress) ต้อง **ยืนยันตัวตนล่าสุด** — ระบบจะถาม password + TOTP อีกครั้ง

## สถาปัตยกรรม

| ชั้น | การป้องกัน |
|---|---|
| Web panel | สิทธิ์ต่ำ, loopback เท่านั้น, ไม่เปิดสาธารณะโดยตรง |
| Privileged agent | Typed operations เท่านั้น — ไม่รับ shell commands |
| Secrets | เข้ารหัส field ละ field, ไม่ปรากฏใน logs |
| ฐานข้อมูล | สิทธิ์แยกตามเว็บ, ไม่เข้าถึงข้ามเว็บ |
| Firewall | UFW เปิดใช้ เปิดเฉพาะ port ที่จำเป็น |

## SSH tunnel (แนะนำ)

แผงเข้าถึงได้เฉพาะ `127.0.0.1:8080` — เชื่อมจากเครื่องคุณ:

```bash
ssh -L 8080:127.0.0.1:8080 root@your-server
```

แล้วเปิด `http://127.0.0.1:8080` ใน browser

## HTTPS สาธารณะ (ไม่บังคับ)

ดู [โดเมนและ SSL](domains.md) สำหรับการตั้งค่า public endpoint พร้อมใบรับรองจริง

## อัปเดตแผง

อัปเดตถูกลงนามด้วย Ed25519 และตรวจสอบก่อนติดตั้ง — สำรองทั้งหมดก่อน และ rollback อัตโนมัติถ้าล้ม
