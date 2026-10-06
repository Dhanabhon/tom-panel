# เริ่มต้นใช้งาน

## ความต้องการ

- Ubuntu Server 24.04 LTS (AMD64) เครื่องใหม่
- RAM 900 MB ขึ้นไป, ดิสก์ 10 GB ขึ้นไป
- ติดตั้ง Docker แล้ว
- สิทธิ์ root

## ติดตั้ง

```bash
git clone https://github.com/Dhanabhon/tom-panel.git
cd tomlpanel
sudo sh scripts/quick-install.sh
```

สคริปต์จะ build `.deb` จาก source, ติดตั้ง, และพิมพ์ setup URL สำหรับใช้ครั้งเดียว

## Wizard แรกเริ่ม

1. เปิด SSH tunnel จากเครื่องคุณ:
   ```bash
   ssh -L 8080:127.0.0.1:8080 root@your-server
   ```
2. เปิด `http://127.0.0.1:8080` ใน browser
3. Wizard จะพาคุณผ่าน:
   - สร้างบัญชีผู้ดูแล
   - บันทึก TOTP secret (สแกน QR code ด้วยแอป authenticator)
   - จด recovery codes (แสดงครั้งเดียว — เก็บ offline)

## สร้างเว็บไซต์แรก

1. ไปที่ **Sites** → **Create site**
2. เลือกประเภท (Static, PHP, หรือ Reverse Proxy)
3. กรอกชื่อโดเมน
4. กด **Create and provision** — TomPanel ตั้งค่า Nginx, directories, และ PHP-FPM ให้อัตโนมัติ

## ขั้นต่อไป

- [เชื่อมต่อโดเมนและ SSL](../th/domains.md)
- [อัปโหลดไฟล์ผ่าน File Manager หรือ SFTP](../th/files.md)
- [สร้างฐานข้อมูล](../th/databases.md)
- [ติดตั้ง WordPress หรือ deploy Laravel](../th/apps.md)
