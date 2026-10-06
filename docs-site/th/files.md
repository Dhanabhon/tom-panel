# ไฟล์และการเข้าถึง

## File Manager

ไปที่เว็บไซต์ → **Files & Access** เพื่ออัปโหลด, แก้ไข, ลบ, ย้ายไฟล์

### ความปลอดภัย

- ทุก operation ถูกจำกัดอยู่ใน directory ของเว็บไซต์นั้น — หนีไม่ได้
- Archive ถูกตรวจสอบก่อนแตกไฟล์ (ป้องกัน symlink และ bomb)
- ไฟล์ที่ลบไปอยู่ใน **Trash** (กู้คืนได้ 7 วัน)

### งานที่ใช้บ่อย

| งาน | วิธีทำ |
|---|---|
| อัปโหลดไฟล์ | กดพื้นที่ upload หรือลากไฟล์มาวาง |
| แก้ไข text file | กดชื่อไฟล์, แก้ inline, กด Save |
| สร้าง directory | ใส่ชื่อ, เลือก "Directory", กด Create |
| บีบอัดไฟล์ | ติ๊ก checkbox, ใส่ชื่อ, กด "Archive selected" |
| แตก archive | อัปโหลด `.tar.gz`, TomPanel ตรวจสอบและแตกให้ |
| กู้จาก Trash | เลื่อนไปส่วน Trash, กด Restore |

## SFTP

แต่ละเว็บไซต์มีบัญชี SFTP แบบ chrooted ได้

### เปิดใช้ SFTP

1. ไปที่เว็บไซต์ → **Files & Access**
2. เลื่อนไปส่วน **SFTP access**
3. กด **Enable SFTP**

### เชื่อมต่อ

```bash
sftp tp_yoursiteid@your-server
```

### ความปลอดภัย

- Chrooted อยู่ใน directory ของเว็บไซต์เท่านั้น
- ปิด shell, port forwarding, tunneling, และ agent forwarding
- รองรับ password และ SSH public key
- การเปลี่ยน password ต้องยืนยันตัวตนล่าสุด (step-up)

### เพิ่ม SSH key

1. ใน **Files & Access**, วาง public key (เช่น `ssh-ed25519 AAAA… you@laptop`)
2. กด **Add key**
3. เชื่อมต่อด้วย private key — ไม่ต้องใส่ password
