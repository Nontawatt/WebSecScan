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
