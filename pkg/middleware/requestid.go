package middleware

// HeaderRequestID คือชื่อ header ที่ใช้ correlate log ข้าม service
// ใช้ชื่อเดียวกับ pet-service และ event-service เพื่อให้ตามรอย
// request เดียวข้าม service ได้ด้วย field เดียวกันใน Discover
const HeaderRequestID = "X-Request-Id"
