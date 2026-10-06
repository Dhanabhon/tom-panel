# แอปพลิเคชัน

## WordPress

### ติดตั้ง

1. ไปที่เว็บไซต์ → **Applications** → **Install WordPress**
2. กรอก admin username, email, และชื่อเว็บ
3. TomPanel สร้าง password ที่ปลอดภัย, สร้าง database เฉพาะ, และติดตั้ง WordPress
4. ก๊อป credentials ที่แสดง — แสดงครั้งเดียวเท่านั้น

### ความปลอดภัย

- Secret ทั้งหมดส่งผ่าน stdin — ไม่ผ่าน command-line arguments
- เปิด `DISALLOW_FILE_EDIT` และ `FORCE_SSL_ADMIN` อัตโนมัติ

### อัปเดต

ไปที่ **Applications** → **Manage WordPress**:

| นโยบาย | คำอธิบาย |
|---|---|
| Security & minor | อัตโนมัติ (default) |
| Major core | กดเอง |
| Plugins | กดเอง (เปิด/ปิดแยก) |
| Themes | กดเอง (เปิด/ปิดแยก) |

อัปเดตสำรองข้อมูลก่อนเสมอ ถ้าล้ม TomPanel rollback อัตโนมัติ

### Object cache

เปิด Redis object cache เพื่อ performance ที่ดีขึ้น แต่ละเว็บมี ACL user เฉพาะ และ key prefix แยก — ไม่มี shared access

## Laravel

### ติดตั้ง

1. ไปที่ **Applications** → **Deploy Laravel**
2. ใส่ Git repository URL (HTTPS หรือ SSH เท่านั้น — `file://` ถูกปฏิเสธ)
3. เลือก branch และว่าจะรัน Node.js build ไหม
4. ยืนยันการ deploy

### Pipeline

```
checkout → composer install → [npm ci && npm run build] →
[php artisan migrate --force (ยืนยันแยก)] →
php artisan optimize → health check → เปิดใช้ release แบบ atomic
```

ถ้าขั้นไหนล้ม — release ปัจจุบันยังใช้งานได้ (zero-downtime)

### Deploy key สำหรับ private repo

TomPanel สร้าง Ed25519 key บนเซิร์ฟเวอร์ — เอา public key ไปเพิ่มใน Git host ของคุณ

### Queue workers

เปิด managed systemd units สำหรับ `queue:work` และ scheduler — TomPanel จัดการ unit และเก็บกวาดเมื่อปิด
