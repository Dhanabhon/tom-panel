# การสำรองข้อมูล

## สำรองด้วยตนเอง

ไปที่เว็บไซต์ → **Backups** → **Back up now**

TomPanel:
- บีบอัดไฟล์ทั้งหมดของเว็บ
- Dump ฐานข้อมูลทั้งหมดแบบ consistent
- บันทึก manifest พร้อม checksums
- ตรวจสอบความสมบูรณ์

## สำรองอัตโนมัติ

สำรองตามเวลาที่กำหนดต่อเว็บ (คำนวณจาก site ID) เก็บ 7 ฉบับล่าสุด — ฉบับ manual ไม่ถูกลบอัตโนมัติ

## Disk guard

หยุดสำรองเมื่อ disk เกิน 85% หรือเหลือน้อยกว่า 2 GB — แสดง warning ในหน้า Backups

## Restore

1. เลือก backup ใน list
2. ยืนยัน
3. TomPanel:
   - สำรองก่อน restore (safety net)
   - Staging ในพื้นที่ชั่วคราว
   - ตรวจสอบ permissions
   - เปิดใช้แบบ atomic (หรือ rollback ถ้าล้ม)

## อัปโหลดไป S3/R2 แบบเข้ารหัส

1. ไปที่ **Settings** → **Object storage (S3/R2)**
2. ใส่ endpoint, bucket, credentials, และ age recipient public key
3. กด **Test connection**

ข้อมูลถูกเข้ารหัส client-side ด้วย `age` ก่อนอัปโหลด

## การลบเว็บไซต์

1. สำรองครั้งสุดท้าย
2. ปิด routes และ workers ทั้งหมด
3. ปลด DNS records ที่ TomPanel เป็นเจ้าของ (ไม่บังคับ)
4. ลบฐานข้อมูล
5. ย้ายข้อมูลไป **quarantine** (กู้คืนได้ 7 วัน)

วิธีลบ: ไปที่ **Backups** → **Danger zone**, พิมพ์ชื่อโดเมนให้ตรง, ยืนยัน — ต้องยืนยันตัวตนล่าสุด (step-up)

หลัง 7 วัน ข้อมูลใน quarantine ถูกลบถาวร
