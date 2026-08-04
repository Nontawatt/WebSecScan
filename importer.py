# -*- coding: utf-8 -*-
"""
นำเข้าผลการประเมินจากไฟล์ CSV (รูปแบบเดียวกับที่ระบบ export) → items_state + remediation
ใช้กับหน้าอัปโหลด CSV เพื่อออกผล checklist โดยไม่ต้องสแกน (เช่น กรอกใน Excel แล้วนำกลับเข้ามา)
"""
import csv
import io
import re

import frameworks
import schemes


# ---------- multipart/form-data parser (ไม่พึ่ง cgi ที่ถูกถอดใน Python 3.13+) ----------
def parse_multipart(body, content_type):
    """คืน (fields: dict[str,str], files: dict[str,(filename,bytes)])"""
    m = re.search(r"boundary=([^;]+)", content_type or "")
    if not m:
        return {}, {}
    boundary = m.group(1).strip().strip('"')
    delim = b"--" + boundary.encode()
    fields, files = {}, {}
    for part in body.split(delim):
        part = part.strip(b"\r\n")
        if not part or part == b"--":
            continue
        if b"\r\n\r\n" not in part:
            continue
        head, _, data = part.partition(b"\r\n\r\n")
        head_txt = head.decode("utf-8", "replace")
        name_m = re.search(r'name="([^"]*)"', head_txt)
        if not name_m:
            continue
        name = name_m.group(1)
        fn_m = re.search(r'filename="([^"]*)"', head_txt)
        data = data.rstrip(b"\r\n")
        if fn_m:
            files[name] = (fn_m.group(1), data)
        else:
            fields[name] = data.decode("utf-8", "replace")
    return fields, files


# ---------- CSV → assessment ----------
def _label_to_verdict(scheme, label):
    label = (label or "").strip()
    if not label:
        return None
    for v, lab in schemes.SCHEMES.get(scheme, {}).get("labels", {}).items():
        if lab == label:
            return v
    return None


def detect_framework(text):
    first = (text.splitlines() or [""])[0]
    if "NCSA" in first or "สกมช" in first or first.count("N") and "ค.1" in text:
        return "ncsa"
    return "etda"


def parse_csv(text, fw_id=None):
    """
    คืน (fw_id, items_state, remediation, matched_count)
    matched_count = จำนวนข้อที่มีผลประเมิน (ไม่ใช่ unset) ที่จับคู่ได้
    """
    if text.startswith("﻿"):
        text = text[1:]
    fw_id = fw_id or detect_framework(text)
    fw = frameworks.get(fw_id)
    reader = list(csv.reader(io.StringIO(text)))

    items_state = {}
    remediation = []
    matched = 0

    # หา header row ของ checklist (คอลัมน์แรก = "ข้อที่")
    hdr_idx = next((i for i, r in enumerate(reader) if r and r[0].strip() == "ข้อที่"), None)
    if hdr_idx is not None:
        header = [h.strip() for h in reader[hdr_idx]]

        def col(name):
            return header.index(name) if name in header else None

        c_v = col("ผลการประเมิน")
        c_n = col("หมายเหตุ/หลักฐาน")
        for row in reader[hdr_idx + 1:]:
            if not row or not row[0].strip():
                break  # เจอบรรทัดว่าง = จบส่วน checklist
            iid = row[0].strip()
            it = fw.item_by_id.get(iid)
            if not it:
                continue
            label = row[c_v] if (c_v is not None and c_v < len(row)) else ""
            v = _label_to_verdict(it["scheme"], label) or "unset"
            note = row[c_n] if (c_n is not None and c_n < len(row)) else ""
            items_state[iid] = {"verdict": v, "auto": False, "note": "",
                                "evidence": "", "userNote": note}
            if v != "unset":
                matched += 1

    # ส่วนแผนแก้ไข (ค.2/ก.2): header row ที่คอลัมน์แรก = "ลำดับ"
    rem_idx = next((i for i, r in enumerate(reader)
                    if r and r[0].strip() == "ลำดับ" and "วันที่" in [c.strip() for c in r]), None)
    if rem_idx is not None:
        for row in reader[rem_idx + 1:]:
            if not row or not any(c.strip() for c in row):
                continue
            row = (row + [""] * 8)[:8]
            remediation.append({"date": row[1], "desc": row[2], "cause": row[3],
                                "temp": row[4], "fix": row[5], "owner": row[6], "due": row[7]})

    # เติม unset ให้ข้อที่ไม่มีในไฟล์
    for it in fw.items:
        items_state.setdefault(it["id"], {"verdict": "unset", "auto": False,
                                          "note": "", "evidence": "", "userNote": ""})
    return fw_id, items_state, remediation, matched


# ---------- Nessus vulnerability scan (.csv) → checklist ----------
def is_nessus(text):
    first = (text.splitlines() or [""])[0].lower()
    return "plugin id" in first and "risk" in first and "host" in first and "name" in first


def _neg_verdict(scheme):
    return {"test": "fail", "ctrl": "fix", "comply": "fix", "mat3": "notdone"}.get(scheme, "fix")


# keyword (lowercase substrings) -> รหัสข้อที่เกี่ยว (จะถูกตั้งเป็นผล "ไม่ผ่าน/ต้องปรับปรุง")
_ETDA_RULES = [
    (["sql injection"], ["4.1-T1", "4.1-P1"]),
    (["command injection", "os command", "code injection"], ["4.2-T1", "4.2-P1"]),
    (["directory traversal", "path traversal", "file inclusion", "lfi", "rfi",
      "directory listing", "browsable", "arbitrary file"], ["4.3-T1", "4.3-P1"]),
    (["session fixation", "session id", "cookie without httponly", "httponly",
      "secure cookie", "cookie secure"], ["4.4-T1", "4.5-M1"]),
    (["cross-site scripting", "cross site scripting", " xss", "(xss"], ["4.5-T1", "4.5-P1"]),
    (["cross-site request forgery", "csrf"], ["4.6-T1", "4.6-P3"]),
    (["response splitting", "crlf", "header injection", "clickjack", "x-frame-options",
      "hsts", "strict-transport", "missing http", "security header"], ["4.7-T1", "4.7-P1"]),
    (["smtp", "open relay", "mail injection"], ["4.8-T1"]),
    (["default cred", "default password", "default account", "weak password",
      "brute force", "login page", "authentication bypass"], ["4.9-T1", "4.9-P1"]),
    (["server version", "banner", "x-powered-by", "version disclos", "software version",
      "information disclosure"], ["4.7-P1"]),
]
_NCSA_RULES = [
    (["ssl", "tls", "cipher", "certificate", "sslv", "tlsv", "poodle", "beast", "weak encryption"], ["N8.7.4"]),
    (["clickjack", "x-frame-options", "hsts", "strict-transport", "security header",
      "missing http", "banner", "version disclos", "directory listing", "information disclosure"], ["N8.4.2"]),
    (["apache", "nginx", "iis", "php", "web server", "outdated", "end of life", "unsupported"], ["N8.6.1"]),
    (["sql injection", "cross-site scripting", " xss", "csrf", "traversal", "command injection",
      "file inclusion"], ["N8.1", "N8.2"]),
    (["default cred", "weak password", "login", "authentication", "brute force"], ["N8.5"]),
    (["rdp", "remote desktop"], ["N8.4.3", "N8.8"]),
    (["smb", "netbios", "msrpc"], ["N8.8", "N8.4.1"]),
]

# พอร์ตที่เปิดแล้วควรระวัง (แมปแม้ Risk=None เพราะเป็นข้อสังเกตด้าน hardening)
_RISKY_PORTS = {
    "3389": ("RDP (Remote Desktop)", ["N8.4.3", "N8.8"], "จำกัดการเข้าถึง RDP (ผ่าน VPN/allowlist IP) + บังคับ MFA หรือปิดถ้าไม่ใช้"),
    "139": ("NetBIOS/SMB", ["N8.8", "N8.4.1"], "ปิด/จำกัด SMB & NetBIOS ให้เฉพาะวงที่จำเป็น"),
    "135": ("MSRPC", ["N8.8"], "จำกัด MSRPC (135) ด้วยไฟร์วอลล์"),
    "445": ("SMB", ["N8.8", "N8.4.1"], "ปิด/จำกัด SMB (445)"),
    "5060": ("SIP", ["N8.8"], "จำกัดการเข้าถึง SIP (5060) เฉพาะที่จำเป็น"),
    "23": ("Telnet", ["N8.8", "N8.7.4"], "ปิด Telnet (ไม่เข้ารหัส) และใช้ SSH แทน"),
    "21": ("FTP", ["N8.8", "N8.7.4"], "หลีกเลี่ยง FTP แบบไม่เข้ารหัส ใช้ FTPS/SFTP"),
}


def parse_nessus(text, fw_id=None):
    """
    แมปผล Nessus CSV เข้ากับ checklist (ETDA หรือ NCSA)
    คืน (fw_id, items_state, remediation, matched_count, toollog)
    """
    fw_id = fw_id or "etda"
    fw = frameworks.get(fw_id)
    rows = list(csv.DictReader(io.StringIO(text)))
    rules = _NCSA_RULES if fw_id == "ncsa" else _ETDA_RULES

    matched = {}       # item_id -> verdict
    remediation = []
    toollog = [f"นำเข้าผล Nessus: {len(rows)} รายการ (มาตรฐาน {fw_id})"]
    n_vuln = 0
    n_obs = 0

    for r in rows:
        name = (r.get("Name") or "").strip()
        risk = (r.get("Risk") or "None").strip()
        host = (r.get("Host") or "").strip()
        port = str(r.get("Port") or "").strip()
        blob = " ".join((r.get(k) or "") for k in ("Name", "Synopsis", "Description", "Solution")).lower()
        is_vuln = risk not in ("None", "")

        hit = set()
        for kws, items in rules:
            if any(k in blob for k in kws):
                hit.update(items)
        risky = _RISKY_PORTS.get(port)
        if risky and fw_id == "ncsa":
            hit.update(risky[1])

        if is_vuln or risky:
            for iid in hit:
                it = fw.item_by_id.get(iid)
                if it:
                    matched[iid] = _neg_verdict(it["scheme"])

        if is_vuln:
            n_vuln += 1
            remediation.append({
                "date": "", "desc": f"[{risk}] {name} ({host}:{port})",
                "cause": (r.get("Synopsis") or "").strip(),
                "temp": (f"CVE: {r.get('CVE')}" if r.get("CVE") else ""),
                "fix": (r.get("Solution") or r.get("See Also") or "").strip(),
                "owner": "", "due": ""})
            toollog.append(f"[{risk}] {name} @ {host}:{port}")
        elif risky:
            n_obs += 1
            svc, _pit, note = risky
            remediation.append({
                "date": "", "desc": f"[ข้อสังเกต] พอร์ตเปิด {port}/{svc} ({host})",
                "cause": "พบจากการสแกนพอร์ต (Nessus, Risk=None) — ยังไม่ยืนยันเป็นช่องโหว่ แต่ควรทบทวนตามหลัก hardening",
                "temp": "", "fix": note, "owner": "", "due": ""})
            toollog.append(f"[open-port] {host}:{port} {svc}")

    items_state = {}
    for it in fw.items:
        v = matched.get(it["id"], "unset")
        items_state[it["id"]] = {"verdict": v, "auto": it["id"] in matched,
                                 "note": ("แมปจากผลสแกน Nessus" if it["id"] in matched else ""),
                                 "evidence": "", "userNote": ""}
    toollog.append(f"สรุป: ช่องโหว่ {n_vuln} รายการ · ข้อสังเกตพอร์ตเปิด {n_obs} · แมปเข้า checklist {len(matched)} ข้อ")
    if n_vuln == 0:
        toollog.append("หมายเหตุ: ไม่พบช่องโหว่ (Risk>=Low) ในไฟล์นี้ — ข้อ checklist ส่วนใหญ่จึงเป็น 'ประเมินโดยผู้ตรวจ'")
    return fw_id, items_state, remediation, len(matched), toollog


def blank_template_csv(fw_id):
    """เทมเพลต CSV เปล่าให้กรอกในช่อง 'ผลการประเมิน' (มีค่าที่กรอกได้กำกับต่อข้อ)"""
    fw = frameworks.get(fw_id)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([f"มาตรฐาน: {fw.std}"])
    w.writerow(["ข้อที่", "หมวด", "ฟังก์ชัน CSF", "ข้อกำหนด/ข้อเสนอแนะ", "อ้างอิง",
                "เงื่อนไขบังคับใช้", "ผลการประเมิน", "auto", "หมายเหตุ/หลักฐาน",
                "(ค่าที่กรอกได้ในช่องผลการประเมิน)"])
    for it in fw.items:
        allowed = " / ".join(schemes.label(it["scheme"], v)
                             for v in schemes.verdicts(it["scheme"]) if v != "unset")
        w.writerow([it["id"], it["cat_name"], it.get("csf") or "-", it["text"], it["ref"],
                    it.get("applies_to", ""), "", "", "", allowed])
    return "﻿".encode("utf-8") + buf.getvalue().encode("utf-8")
