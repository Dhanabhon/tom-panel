# ฐานข้อมูล

## สร้างฐานข้อมูล

1. ไปที่เว็บไซต์ → **Databases**
2. ใส่ suffix (เช่น `shop` — ชื่อเต็มจะเป็น `tp_yoursiteid_shop`)
3. กด **Create database**

TomPanel:
- สร้าง MariaDB database และ user
- ให้สิทธิ์เฉพาะ database นั้น — ไม่สามารถเข้าถึงเว็บอื่นได้
- แสดง password ครั้งเดียว — ก๊อปทันที

## การหมุนเวียน credential

ใช้แบบ two-phase ที่ไม่ทำให้เว็บคุณล่ม:

1. กด **Rotate credential**
2. สร้าง user ใหม่ → อัปเดต config → ตรวจสุขภาพ → ปลด user เก่า
3. ถ้าขั้นไหนล้ม — credential เดิมยังใช้ได้

## Backup และ Restore

| การทำงาน | วิธี |
|---|---|
| Backup | กด **Back up** — สร้าง dump แบบ consistent |
| Restore | เลือก backup ใน list, ยืนยัน, กด **Restore** |

## phpMyAdmin

### โหมด

| โหมด | คำอธิบาย |
|---|---|
| **Private** (แนะนำ) | Loopback เท่านั้น ใช้ผ่าน SSH tunnel |
| **Public subdomain** | HTTPS hostname เฉพาะ |
| **Public port** | HTTPS บน port กำหนดเอง |

### เปิดใช้

1. ไปที่ **Databases** → **phpMyAdmin**
2. เลือกโหมด
3. สำหรับโหมด public ใส่ hostname และ ACME email
4. กด **Enable phpMyAdmin**

โหมด public จะเพิ่ม rate limiting และ HTTP Basic Auth ก่อนเข้า phpMyAdmin

> **หมายเหตุ:** password ของ Basic Auth แสดงครั้งเดียว — เก็บให้ดี
