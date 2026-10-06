# โดเมนและ SSL

## เชื่อมต่อ DNS

ก่อนที่ TomPanel จะจัดการโดเมนของคุณได้ ต้องชี้ DNS มาที่เซิร์ฟเวอร์ก่อน:

1. ไปที่ผู้ให้บริการ DNS (Cloudflare, Route53 ฯลฯ)
2. สร้าง **A record**: `yourdomain.com` → IP ของเซิร์ฟเวอร์
3. รอ DNS propagate (ปกติ 5–30 นาที)

## ตั้งค่า Cloudflare (ไม่บังคับ)

ถ้าใช้ Cloudflare:

1. ไปที่ **Settings** → **Cloudflare**
2. ใส่ **Zone ID** และ **API Token**
3. กด **Save** แล้ว **Test connection**

เมื่อตั้งค่าแล้ว TomPanel จะใช้ DNS-01 challenge (ไม่ต้องเปิด port 80)

## ขอใบรับรอง SSL

1. ไปที่เว็บไซต์ → **Domains & SSL**
2. กด **Issue certificate**
3. เลือก challenge:
   - **DNS-01** (แนะนำถ้ามี Cloudflare) — ไม่ต้องเปิด port 80
   - **HTTP-01** — ต้องเปิด port 80 (TomPanel จัดการให้อัตโนมัติ)
4. TomPanel ออกใบรับรอง, ตรวจสอบ Nginx, และเปิดใช้งาน

## เปิด HTTPS สำหรับแผงควบคุม

เพื่อใช้แผงผ่านโดเมนสาธารณะ (แทน SSH tunnel):

1. ไปที่ **Settings** → **Panel endpoint**
2. เลือก **Public HTTPS**
3. กรอก hostname (เช่น `panel.yourdomain.com`), port (default: 4884), และ ACME email
4. กด **Queue endpoint change**

> **หมายเหตุ Cloudflare:** proxy รองรับ HTTPS เฉพาะ port 443 และ 8443 — port 4884 ต้องใช้ DNS-only (กดเมฆสีเทา)

## ต่ออายุใบรับรอง

TomPanel ต่ออายุอัตโนมัติก่อนหมดอายุ หากล้มเหลวจะแสดงในหน้า Domains พร้อมปุ่ม retry
