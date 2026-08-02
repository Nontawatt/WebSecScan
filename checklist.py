# -*- coding: utf-8 -*-
"""
ETDA ขมธอ. 4-2559 — Web Application Security Standard
Checklist ตามภาคผนวก ก.1 (แบบฟอร์มตรวจสอบสถานะความมั่นคงปลอดภัยสำหรับเว็บไซต์)

โครงสร้างแต่ละข้อ:
  id     : รหัสข้อ (เช่น 4.1-P1)
  cat    : รหัสหมวด (4.1 - 4.9)
  ptype  : prevent | mitigate | test
  text   : รายละเอียดการป้องกัน (ภาษาไทยตามเอกสาร)
  ref    : หัวข้อที่อ้างอิงถึง
  auto   : คีย์สัญญาณที่ probe อัตโนมัติได้ (None = ต้องประเมินเอง)
  otg    : รหัส OWASP Testing Guide (เฉพาะข้อทดสอบ)
"""

CATEGORIES = [
    ("4.1", "SQL Injection"),
    ("4.2", "OS Command Injection"),
    ("4.3", "Unchecked Path Parameter / Directory Traversal"),
    ("4.4", "Improper Session Management"),
    ("4.5", "Cross-Site Scripting (XSS)"),
    ("4.6", "Cross-Site Request Forgery (CSRF)"),
    ("4.7", "HTTP Header Injection"),
    ("4.8", "Mail Header Injection"),
    ("4.9", "Lack of Authentication and Authorization"),
]

CAT_NAME = {c: n for c, n in CATEGORIES}

PTYPE_LABEL = {
    "prevent": "การป้องกันการโจมตี",
    "mitigate": "การลดความเสียหายที่เกิดจากการถูกโจมตี",
    "test": "การทดสอบ",
}

# รายละเอียดภัยคุกคาม + แนวทางแก้ต่อหมวด (ใช้ในรายงาน)
CAT_INFO = {
    "4.1": {
        "threat": "ผู้ประสงค์ร้ายแทรกคำสั่ง SQL ผ่านพารามิเตอร์ที่ไม่ถูกตรวจสอบ ทำให้อ่าน/แก้ไข/ลบข้อมูลในฐานข้อมูล ข้ามการยืนยันตัวตน หรือสั่งงานระบบปฏิบัติการได้",
        "fix": "ใช้ Prepared Statement / Parameterized Query หรือ Stored Procedure; ห้ามต่อสตริง SQL จาก input โดยตรง; จำกัดสิทธิ์บัญชีฐานข้อมูลขั้นต่ำ; ไม่เปิดเผยรายละเอียด DB ใน error message",
    },
    "4.2": {
        "threat": "input ถูกนำไปประกอบเป็นคำสั่งระบบปฏิบัติการ (exec/system/popen) ผู้โจมตีแทรกคำสั่งเพิ่มเพื่อรันบนเซิร์ฟเวอร์ นำไปสู่การยึดเครื่อง",
        "fix": "หลีกเลี่ยงการเรียก shell/OS command ด้วย input ผู้ใช้; ปิดฟังก์ชันที่ไม่จำเป็น; ถ้าจำเป็นต้อง sanitize/allowlist ตัวแปรก่อนใช้",
    },
    "4.3": {
        "threat": "ผู้โจมตีใส่ ../ หรือ path ในพารามิเตอร์ชื่อไฟล์ เพื่ออ่าน/จัดการไฟล์นอกไดเรกทอรีที่กำหนด (เช่น /etc/passwd, .env)",
        "fix": "ห้ามรับชื่อไฟล์จาก external parameter โดยตรง; ใช้ fixed directory + allowlist; normalize path และปฏิเสธ ../; ตั้ง permission ไฟล์ให้เหมาะสม",
    },
    "4.4": {
        "threat": "Session ID เดาได้/คงที่/ส่งผ่านช่องทางไม่ปลอดภัย ทำให้ถูกขโมยหรือสวมรอย (Session Hijacking)",
        "fix": "สร้าง Session ID สุ่มด้วย CSPRNG; ตั้ง cookie Secure + HttpOnly; บังคับ HTTPS; ไม่เก็บ session ใน URL; กำหนดวันหมดอายุ cookie",
    },
    "4.5": {
        "threat": "input ถูกแสดงผลโดยไม่ encode ทำให้สคริปต์ของผู้โจมตีรันในเบราว์เซอร์เหยื่อ (ขโมย cookie/สวมรอย)",
        "fix": "ทำ Output Encoding ตามบริบท (HTML/URL/JS); Input validation ปฏิเสธ HTML tag; กำหนด charset ใน Content-Type; ใช้ HttpOnly cookie; พิจารณา CSP",
    },
    "4.6": {
        "threat": "เว็บไม่ตรวจว่าคำขอที่เปลี่ยนสถานะมาจากผู้ใช้จริง ผู้โจมตีหลอกให้เบราว์เซอร์เหยื่อส่งคำขอที่ผ่าน auth (โอนเงิน/เปลี่ยนรหัส) โดยไม่รู้ตัว",
        "fix": "ใส่ anti-CSRF token ต่อ session/คำขอ และตรวจฝั่งเซิร์ฟเวอร์; ใช้ POST + ตรวจ Referer/Origin; ตั้ง cookie SameSite; ยืนยันตัวตนซ้ำ/Captcha สำหรับฟังก์ชันสำคัญ",
    },
    "4.7": {
        "threat": "input ถูกใส่ลง HTTP response header โดยไม่กรอง CR/LF ทำให้แทรก header หรือแบ่ง response (HTTP Response Splitting) / cache poisoning",
        "fix": "ไม่นำ input ไปใส่ header โดยตรง; ลบ/ปฏิเสธอักขระ CR (%0d) และ LF (%0a); ใช้ Header API ของเฟรมเวิร์กที่ป้องกัน line feed",
    },
    "4.8": {
        "threat": "ฟอร์มส่งอีเมลนำ input (to/subject/from) มาประกอบ header ผู้โจมตีแทรก CR/LF เพื่อเพิ่ม Bcc/Cc ส่งสแปมหรือปลอมผู้ส่ง",
        "fix": "กำหนดองค์ประกอบ header เป็นค่าคงที่; ใช้ mail-sending API ที่ปลอดภัย; ลบ CR/LF ออกจาก input; ไม่กำหนดที่อยู่อีเมลใน HTML",
    },
    "4.9": {
        "threat": "ฟังก์ชัน/ข้อมูลเข้าถึงได้โดยไม่ยืนยันตัวตน หรือผู้ใช้เข้าถึงข้อมูลผู้อื่นได้ (IDOR/ยกระดับสิทธิ์) หรือใช้รหัสผ่านอ่อน/ดีฟอลต์",
        "fix": "บังคับยืนยันตัวตนทุก resource ที่ต้องควบคุม; ตรวจสิทธิ์ระดับ object ทุกคำขอ (กัน IDOR); เก็บรหัสผ่านแบบ hash มาตรฐาน; บังคับรหัสผ่านเข้ม ≥8 ตัว; ปิด default credentials",
    },
}

# ---------------------------------------------------------------------------
# รายการข้อตรวจทั้งหมด (46 ข้อ ตามภาคผนวก ก.1)
# auto: คีย์ที่ engine ตรวจอัตโนมัติได้; None = ต้องประเมินเอง (code-level / black-box มองไม่เห็น)
# ---------------------------------------------------------------------------
ITEMS = [
    # ----- 4.1 SQL Injection -----
    dict(cat="4.1", ptype="prevent", ref="4.1.2.1 ข้อ 1", auto=None,
         text="มีการจัดทำ Prepared Statement และ/หรือ Stored Procedure"),
    dict(cat="4.1", ptype="prevent", ref="4.1.2.1 ข้อ 2", auto=None,
         text="ไม่เขียนคำสั่ง SQL โดยตรงในตัวแปร (Parameter) ที่ส่งไปยังโปรแกรมประยุกต์บนเว็บ"),
    dict(cat="4.1", ptype="mitigate", ref="4.1.2.2 ข้อ 1", auto="error_leak",
         text="ควบคุมการแสดงผลข้อมูล Error Message (ไม่เปิดเผยชื่อ DB/ตาราง/คำสั่ง SQL)"),
    dict(cat="4.1", ptype="mitigate", ref="4.1.2.2 ข้อ 2", auto=None,
         text="กำหนดสิทธิขั้นต่ำให้บัญชีผู้ใช้ของฐานข้อมูล"),
    dict(cat="4.1", ptype="test", ref="4.1.3", otg="OTG-INPVAL-005", auto="sqli",
         text="SQL Injection Testing (OTG-INPVAL-005)"),

    # ----- 4.2 OS Command Injection -----
    dict(cat="4.2", ptype="prevent", ref="4.2.2.1", auto=None,
         text="พัฒนาโปรแกรมประยุกต์บนเว็บโดยปิดการใช้งานคำสั่งต่าง ๆ เพื่อป้องกันการเรียกใช้ที่ไม่พึงประสงค์"),
    dict(cat="4.2", ptype="mitigate", ref="4.2.2.2", auto=None,
         text="(กรณีเรียกใช้ OS Command) ตรวจสอบ Variables ที่จะใช้กับตัวแปรของ OS Command ก่อนนำไปประมวลผล"),
    dict(cat="4.2", ptype="test", ref="4.2.3", otg="OTG-INPVAL-013", auto="cmdi",
         text="Testing for Command Injection (OTG-INPVAL-013)"),

    # ----- 4.3 Directory Traversal -----
    dict(cat="4.3", ptype="prevent", ref="4.3.2.1 ข้อ 1", auto=None,
         text="ไม่อนุญาตให้ใส่ Filename เพื่อระบุถึงข้อมูลได้จาก External Parameter"),
    dict(cat="4.3", ptype="prevent", ref="4.3.2.1 ข้อ 2", auto=None,
         text="ใช้ Fixed Directory ในการจัดการระบุชื่อไฟล์"),
    dict(cat="4.3", ptype="mitigate", ref="4.3.2.2 ข้อ 1", auto=None,
         text="กำหนด Permission การเข้าถึงไฟล์บนเครื่องบริการเว็บให้เหมาะสม"),
    dict(cat="4.3", ptype="mitigate", ref="4.3.2.2 ข้อ 2", auto="traversal",
         text="ตรวจสอบ Filename เช่น มีการแปลง String ที่ระบุ Directory (เช่น / -> %2F)"),
    dict(cat="4.3", ptype="test", ref="4.3.3", otg="OTG-AUTHZ-001", auto="traversal",
         text="Testing Directory Traversal / File Include (OTG-AUTHZ-001)"),

    # ----- 4.4 Improper Session Management -----
    dict(cat="4.4", ptype="prevent", ref="4.4.2.1 ข้อ 1", auto="session_entropy",
         text="สร้าง Session ID ที่ยากต่อการคาดเดา (ไม่ใช้ Algorithm ง่ายเกินไป)"),
    dict(cat="4.4", ptype="prevent", ref="4.4.2.1 ข้อ 2", auto="session_in_url",
         text="ไม่ใช้ URL Parameter ในการเก็บ Session ID"),
    dict(cat="4.4", ptype="prevent", ref="4.4.2.1 ข้อ 3", auto="cookie_secure",
         text="เมื่อใช้งาน HTTPS Protocol ใช้ Secure Attribute ของ Cookies"),
    dict(cat="4.4", ptype="mitigate", ref="4.4.2.2 ข้อ 1", auto="session_entropy",
         text="กำหนดให้ Session ID เป็นค่าสุ่ม"),
    dict(cat="4.4", ptype="mitigate", ref="4.4.2.2 ข้อ 2", auto="cookie_expiry",
         text="กำหนดวันหมดอายุการใช้งานของ Cookies ที่เก็บ Session ID"),
    dict(cat="4.4", ptype="test", ref="4.4.3", otg="OTG-SESS-001 / OTG-SESS-004", auto="session_entropy",
         text="Testing for Bypassing Session Management (OTG-SESS-001) และ Exposed Session Variables (OTG-SESS-004)"),

    # ----- 4.5 XSS -----
    dict(cat="4.5", ptype="prevent", ref="4.5.2.1 ข้อ 1", auto="xss_reflected",
         text="ทำ Output Validation ในลักษณะ Sanitization"),
    dict(cat="4.5", ptype="prevent", ref="4.5.2.1 ข้อ 2", auto="xss_reflected",
         text="ทำ HTML Entity Encoding หรือ URL Encoding กับข้อมูลที่จะแสดงผล"),
    dict(cat="4.5", ptype="prevent", ref="4.5.2.1 ข้อ 3", auto=None,
         text="ตรวจสอบ Input Validation ไม่ให้ใช้ HTML Tag ใด ๆ (เช่นไม่ generate content จาก <script>)"),
    dict(cat="4.5", ptype="prevent", ref="4.5.2.1 ข้อ 4", auto="csp_present",
         text="ไม่อนุญาตให้เรียก Stylesheets จากเว็บไซต์ที่ไม่ได้ตรวจสอบก่อน"),
    dict(cat="4.5", ptype="prevent", ref="4.5.2.1 ข้อ 5", auto="charset_declared",
         text="ตั้งค่า Charset Parameter ของ HTTP Content-Type Header"),
    dict(cat="4.5", ptype="prevent", ref="4.5.2.1 ข้อ 6", auto=None,
         text="โปรแกรมประยุกต์บนเว็บต้องมีการตรวจสอบข้อมูลชุดคำสั่งในเว็บไซต์"),
    dict(cat="4.5", ptype="mitigate", ref="4.5.2.2", auto="cookie_httponly",
         text="มีการใช้งาน HTTPOnly Cookie Flag"),
    dict(cat="4.5", ptype="test", ref="4.5.3", otg="XSS Testing", auto="xss_reflected",
         text="Testing for Cross Site Scripting"),

    # ----- 4.6 CSRF -----
    dict(cat="4.6", ptype="prevent", ref="4.6.2.1 ข้อ 1", auto=None,
         text="ฟังก์ชันต่าง ๆ ควรดำเนินการผ่าน POST Method และตรวจสอบค่าที่ซ่อนอยู่ภายใน POST ก่อนดำเนินการ"),
    dict(cat="4.6", ptype="prevent", ref="4.6.2.1 ข้อ 2", auto=None,
         text="มีฟังก์ชันยืนยันตัวตนของผู้ใช้อีกครั้งและกรอก Captcha เมื่อเปลี่ยนสถานะการทำงานในฟังก์ชันสำคัญ"),
    dict(cat="4.6", ptype="prevent", ref="4.6.2.1 ข้อ 3", auto="csrf_token",
         text="ใช้ Unique Token และ/หรือตรวจสอบ Referrer ร่วมกับการส่งข้อมูลผ่านแบบฟอร์ม"),
    dict(cat="4.6", ptype="mitigate", ref="4.6.2.2", auto=None,
         text="ส่งอีเมลอัตโนมัติแจ้งผู้ใช้บริการทุกครั้งเมื่อการดำเนินการสำคัญทำสำเร็จ"),
    dict(cat="4.6", ptype="test", ref="4.6.3", otg="OTG-SESS-005", auto="csrf_token",
         text="Testing for Cross-Site Request Forgery (OTG-SESS-005)"),

    # ----- 4.7 HTTP Header Injection -----
    dict(cat="4.7", ptype="prevent", ref="4.7.2.1 ข้อ 1", auto="header_disclosure",
         text="ไม่ให้แสดงข้อมูล HTTP Header โดยตรง"),
    dict(cat="4.7", ptype="prevent", ref="4.7.2.1 ข้อ 2", auto=None,
         text="(ถ้าใช้ HTTP Header API) เพิ่มการป้องกัน Unexpected Line Feeds ด้วยตนเอง"),
    dict(cat="4.7", ptype="mitigate", ref="4.7.2.2", auto="crlf",
         text="ลบ Line Feed Characters ทั้งหมดที่ปรากฏใน External Text Input"),
    dict(cat="4.7", ptype="test", ref="4.7.3", otg="OTG-INPVAL-016", auto="crlf",
         text="HTTP Header Injection Testing (OTG-INPVAL-016)"),

    # ----- 4.8 Mail Header Injection -----
    dict(cat="4.8", ptype="prevent", ref="4.8.2.1 ข้อ 1", auto=None,
         text="กำหนดค่าคงที่ (Fixed Values) สำหรับองค์ประกอบของ Header"),
    dict(cat="4.8", ptype="prevent", ref="4.8.2.1 ข้อ 2", auto=None,
         text="(กรณีใช้ Fixed Header ไม่ได้) ใช้ Email-sending API ที่ใช้ร่วมกับโปรแกรมประยุกต์ได้"),
    dict(cat="4.8", ptype="prevent", ref="4.8.2.1 ข้อ 3", auto=None,
         text="ไม่กำหนดชื่อที่อยู่อีเมลใน HTML"),
    dict(cat="4.8", ptype="mitigate", ref="4.8.2.2", auto=None,
         text="ลบ Input Line Feed Character ทั้งหมดที่รับข้อมูลจากผู้ใช้บริการ"),
    dict(cat="4.8", ptype="test", ref="4.8.3", otg="OTG-INPVAL-011", auto="mail_form",
         text="Mail Header Injection Testing (OTG-INPVAL-011)"),

    # ----- 4.9 Lack of AuthN/AuthZ -----
    dict(cat="4.9", ptype="prevent", ref="4.9.1.1 ข้อ 1", auto="auth_surface",
         text="ระบุวิธีการยืนยันตัวตนของผู้ใช้บริการ (Authentication) กรณีมีการกำหนด Access Control"),
    dict(cat="4.9", ptype="prevent", ref="4.9.1.1 ข้อ 2", auto=None,
         text="เก็บรหัสผ่านในรูปที่มีการเข้ารหัสลับตามมาตรฐานด้านความมั่นคงปลอดภัย"),
    dict(cat="4.9", ptype="prevent", ref="4.9.2.1", auto=None,
         text="มีกระบวนการชัดเจนเพื่อให้แน่ใจว่าผู้ใช้ที่เข้าสู่ระบบไม่สามารถเข้าถึงบัญชี/ข้อมูลของผู้อื่นได้ (กัน IDOR)"),
    dict(cat="4.9", ptype="mitigate", ref="4.9.1.2", auto=None,
         text="รหัสผ่านประกอบด้วยตัวเล็ก ตัวใหญ่ ตัวเลข และอักขระพิเศษ ยาวไม่น้อยกว่า 8 หลัก"),
    dict(cat="4.9", ptype="test", ref="4.9.3", auto="default_creds",
         otg="OTG-AUTHN-002 / OTG-AUTHN-007 / OTG-AUTHZ-002 / OTG-AUTHZ-003",
         text="Testing for Default Credentials, Weak Password Policy, Bypassing Authorization, Privilege Escalation"),
]

# ---- framework meta (ใช้กับระบบ multi-framework) ----
FRAMEWORK_ID = "etda"
FRAMEWORK_NAME = "มาตรฐานการรักษาความมั่นคงปลอดภัยสำหรับโปรแกรมประยุกต์บนเว็บ (ETDA)"
FRAMEWORK_SHORT = "ETDA ขมธอ. 4-2559"
FRAMEWORK_STD = "ETDA ขมธอ. 4-2559 (Web Application Security Standard)"
USES_CSF = False
# (group_id, group_name, csf) — ETDA ไม่ใช้ CSF จึง csf=None
GROUPS = [(c, n, None) for c, n in CATEGORIES]


# กำหนด id คงที่ให้แต่ละข้อ (P=prevent, M=mitigate, T=test) + scheme/csf/level
def _assign_ids():
    counters = {}
    pmap = {"prevent": "P", "mitigate": "M", "test": "T"}
    smap = {"prevent": "ctrl", "mitigate": "ctrl", "test": "test"}
    for it in ITEMS:
        key = (it["cat"], it["ptype"])
        counters[key] = counters.get(key, 0) + 1
        it["id"] = f"{it['cat']}-{pmap[it['ptype']]}{counters[key]}"
        it["cat_name"] = CAT_NAME[it["cat"]]
        it["scheme"] = smap[it["ptype"]]
        it["csf"] = None
        it["level"] = "main"
        it.setdefault("otg", "")
        it.setdefault("applies_to", "")
    return ITEMS

_assign_ids()
ITEM_BY_ID = {it["id"]: it for it in ITEMS}

# ค่า verdict ที่ยอมรับ
# prevent/mitigate : ok (ยอมรับได้) | fix (ยังต้องปรับปรุง) | na (ไม่เกี่ยวข้อง) | unset
# test             : pass (ทดสอบผ่าน) | fail (ทดสอบไม่ผ่าน) | cannot (ยังทดสอบเองไม่ได้) | unset
VERDICTS_CTRL = ["ok", "fix", "na", "unset"]
VERDICTS_TEST = ["pass", "fail", "cannot", "unset"]

VERDICT_LABEL = {
    "ok": "ยอมรับได้",
    "fix": "ยังต้องปรับปรุง",
    "na": "ไม่เกี่ยวข้อง",
    "pass": "ทดสอบผ่าน",
    "fail": "ทดสอบไม่ผ่าน",
    "cannot": "ยังทดสอบเองไม่ได้",
    "unset": "ประเมินโดยผู้ตรวจ",
}


def default_verdict(item):
    return "unset"


def summary_counts(items_state):
    """นับสรุปจาก state {id: {verdict,...}}"""
    n = dict(ok=0, fix=0, na=0, pass_=0, fail=0, cannot=0, unset=0, total=len(ITEMS))
    for it in ITEMS:
        v = items_state.get(it["id"], {}).get("verdict", "unset")
        if v == "pass":
            n["pass_"] += 1
        elif v in n:
            n[v] += 1
        else:
            n["unset"] += 1
    return n


if __name__ == "__main__":
    print(f"total items = {len(ITEMS)}")
    from collections import Counter
    c = Counter(it["ptype"] for it in ITEMS)
    print(dict(c))
    for it in ITEMS:
        print(it["id"], "| auto=" + str(it["auto"]), "|", it["text"][:50])
