# -*- coding: utf-8 -*-
"""
Export: PDF (exec summary + กราฟ + checklist ก.1/ค.1 + แผนแก้ไข ก.2/ค.2, ภาษาไทย fpdf2+Garuda),
CSV, JSON — รองรับหลายมาตรฐาน (ETDA / NCSA)
กราฟใน PDF วาดด้วย fpdf2 primitives (rect/แถบ) ไม่พึ่ง library ภายนอก
"""
import csv
import io
import json
import os
import sys

import frameworks
import schemes


def _font_dirs():
    dirs = []
    if getattr(sys, "frozen", False):
        dirs.append(os.path.join(getattr(sys, "_MEIPASS", ""), "fonts"))
        dirs.append(os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "fonts"))
    dirs.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts"))
    dirs += ["/usr/share/fonts/truetype/tlwg", "/usr/share/fonts/truetype/thai", r"C:\Windows\Fonts"]
    return dirs


# ฟอนต์ไทย (regular, bold) เรียงตามความชอบ — ตัวแรกที่พบจะถูกใช้
_FONT_CANDIDATES = [
    ("Garuda.ttf", "Garuda-Bold.ttf"),
    ("leelawui.ttf", "leelauib.ttf"),   # Leelawadee UI (Windows)
    ("leelawad.ttf", "leelawdb.ttf"),   # Leelawadee (Windows)
    ("tahoma.ttf", "tahomabd.ttf"),     # Tahoma (Windows, รองรับไทย)
]


def _font_files():
    for d in _font_dirs():
        if not d or not os.path.isdir(d):
            continue
        for reg_name, bold_name in _FONT_CANDIDATES:
            reg = os.path.join(d, reg_name)
            if os.path.exists(reg):
                bold = os.path.join(d, bold_name)
                return reg, (bold if os.path.exists(bold) else reg)
    return None, None


def _fw(rec):
    return frameworks.get(rec.get("framework", "etda"))


# --------------------------------------------------------------------------- #
# JSON / CSV
# --------------------------------------------------------------------------- #
def to_json(rec):
    return json.dumps(rec, ensure_ascii=False, indent=2).encode("utf-8")


def to_csv(rec):
    fw = _fw(rec)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([f"มาตรฐาน: {fw.std}"])
    w.writerow(["ข้อที่", "หมวด", "ฟังก์ชัน CSF", "ข้อกำหนด/ข้อเสนอแนะ", "อ้างอิง",
                "เงื่อนไขบังคับใช้", "ผลการประเมิน", "auto", "หมายเหตุ/หลักฐาน"])
    for it in fw.items:
        st = rec["items"].get(it["id"], {})
        v = st.get("verdict", "unset")
        w.writerow([
            it["id"], it["cat_name"], it.get("csf") or "-", it["text"], it["ref"],
            it.get("applies_to", ""), schemes.label(it["scheme"], v),
            "auto" if st.get("auto") else "manual",
            (st.get("note", "") + (" | " + st.get("evidence", "") if st.get("evidence") else "")
             + (" | " + st.get("userNote", "") if st.get("userNote") else "")).strip(),
        ])
    w.writerow([])
    w.writerow(["แบบรายงานรายการที่ยังต้องปรับปรุง (ค.2/ก.2)"])
    w.writerow(["ลำดับ", "วันที่", "รายการที่ต้องปรับปรุง", "สาเหตุ", "การแก้ไขชั่วคราว",
                "สิ่งที่ต้องแก้ไข", "รับผิดชอบโดย", "วันที่แล้วเสร็จ"])
    for i, r in enumerate(rec.get("remediation", []), 1):
        w.writerow([i, r.get("date", ""), r.get("desc", ""), r.get("cause", ""),
                    r.get("temp", ""), r.get("fix", ""), r.get("owner", ""), r.get("due", "")])
    return "﻿".encode("utf-8") + buf.getvalue().encode("utf-8")


# --------------------------------------------------------------------------- #
# PDF
# --------------------------------------------------------------------------- #
def to_pdf(rec):
    from fpdf import FPDF
    fw = _fw(rec)
    reg, bold = _font_files()
    if not reg:
        raise RuntimeError("ไม่พบฟอนต์ไทย (Garuda) ในเครื่อง")

    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(True, margin=15)
    pdf.add_font("TH", "", reg)
    pdf.add_font("TH", "B", bold)
    pdf.add_page()

    def mc(h, txt, align="L", font=None, size=None):
        if font is not None:
            pdf.set_font("TH", font, size)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, h, txt or "", align=align, new_x="LMARGIN", new_y="NEXT")

    comp = fw.compliance(rec["items"])
    bd = fw.breakdown(rec["items"])

    # ---------- หัวรายงาน / exec summary ----------
    mc(8, "รายงานผลการตรวจสอบสถานะความมั่นคงปลอดภัยของเว็บไซต์", "C", "B", 15)
    mc(6, fw.std, "C", "", 11)
    pdf.ln(3)

    pdf.set_font("TH", "", 11)
    for k, v in [("เว็บไซต์ / เป้าหมาย", rec.get("site_label") or rec.get("target", "")),
                 ("URL ที่ตรวจ", rec.get("target", "")),
                 ("ตรวจโดย", rec.get("audited_by", "") or "-"),
                 ("วันที่", rec.get("created", "")),
                 ("มาตรฐาน", fw.short)]:
        pdf.set_x(pdf.l_margin)
        pdf.set_font("TH", "B", 11); pdf.cell(42, 6, k)
        pdf.set_font("TH", "", 11); pdf.multi_cell(0, 6, ": " + str(v), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    # กล่องคะแนนรวม + progress bar
    pct = comp["pct"]
    col = (31, 138, 76) if (pct or 0) >= 80 else ((199, 123, 0) if (pct or 0) >= 50 else (198, 40, 40))
    x = pdf.l_margin
    y = pdf.get_y()
    pdf.set_fill_color(247, 249, 252)
    pdf.rect(x, y, 180, 26, style="DF")
    pdf.set_xy(x + 4, y + 3)
    pdf.set_font("TH", "B", 13)
    pdf.cell(0, 7, "ความสอดคล้องโดยรวม (Compliance)")
    pdf.set_xy(x + 150, y + 2)
    pdf.set_text_color(*col)
    pdf.set_font("TH", "B", 20)
    pdf.cell(26, 10, (f"{pct}%" if pct is not None else "N/A"), align="R")
    pdf.set_text_color(0, 0, 0)
    # progress bar
    bx, by, bw = x + 4, y + 15, 172
    pdf.set_fill_color(236, 239, 243); pdf.rect(bx, by, bw, 6, style="F")
    if pct:
        pdf.set_fill_color(*col); pdf.rect(bx, by, bw * pct / 100, 6, style="F")
    pdf.set_xy(x + 4, y + 21)
    pdf.set_font("TH", "", 9.5)
    pdf.cell(0, 4, f"ประเมินแล้ว {comp['assessed']}/{comp['total']} ข้อ · เกี่ยวข้อง {comp['applicable']} ข้อ · ไม่เกี่ยวข้อง {comp['na']} · ประเมินโดยผู้ตรวจ {comp['unset']}")
    pdf.set_y(y + 30)

    # แถบสัดส่วนผล
    _legend_bar(pdf, bd)

    # กราฟ CSF / หมวด
    pdf.ln(3)
    if fw.uses_csf:
        mc(7, "ความสอดคล้องตามฟังก์ชัน NIST CSF 2.0", "L", "B", 12)
        rows = [(c["label"].split(" (")[0], c["comp"]["pct"], c["color"]) for c in fw.csf_summary(rec["items"])]
    else:
        mc(7, "ความสอดคล้องตามหมวด", "L", "B", 12)
        rows = [(g["id"] + " " + g["name"].split(" (")[0][:34], g["comp"]["pct"], None) for g in fw.group_summary(rec["items"])]
    _bar_chart(pdf, rows)

    # ---------- ตาราง checklist ----------
    pdf.add_page()
    form_a = "ค.1" if fw.id == "ncsa" else "ก.1"
    mc(7, f"{form_a} แบบตรวจรายการเพื่อตรวจสอบสถานะความมั่นคงปลอดภัยของเว็บไซต์", "L", "B", 12)
    pdf.ln(1)

    W = {"id": 18, "detail": 96, "verdict": 38, "ref": 28}

    def header_row():
        pdf.set_font("TH", "B", 9); pdf.set_fill_color(30, 58, 95); pdf.set_text_color(255, 255, 255)
        for key, lab in [("id", "ข้อ"), ("detail", "ข้อกำหนด / ข้อเสนอแนะ"), ("verdict", "ผลการประเมิน"), ("ref", "อ้างอิง")]:
            pdf.cell(W[key], 7, lab, border=1, align="C", fill=True)
        pdf.ln(); pdf.set_text_color(0, 0, 0)

    header_row()
    cur_group = None
    cur_csf = None
    for it in fw.items:
        if fw.uses_csf and it["csf"] != cur_csf:
            cur_csf = it["csf"]
            r, g, b = _hex(fw.csf_color.get(cur_csf, "#334155"))
            pdf.set_font("TH", "B", 9.5); pdf.set_fill_color(r, g, b); pdf.set_text_color(255, 255, 255)
            pdf.set_x(pdf.l_margin)
            pdf.cell(sum(W.values()), 6.5, "  ◆ " + fw.csf_label.get(cur_csf, cur_csf), border=1, fill=True, ln=1)
            pdf.set_text_color(0, 0, 0)
        if it["cat"] != cur_group:
            cur_group = it["cat"]
            pdf.set_font("TH", "B", 9); pdf.set_fill_color(223, 231, 245)
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(sum(W.values()), 5.6, "  " + it["cat_name"], border=1, fill=True,
                           new_x="LMARGIN", new_y="NEXT")

        st = rec["items"].get(it["id"], {})
        v = st.get("verdict", "unset")
        detail = ("   " if it.get("level") == "sub" else "") + it["text"]
        if it.get("applies_to"):
            detail += f"\n  [เงื่อนไข: {it['applies_to']}]"
        note = st.get("note", "") or st.get("userNote", "")
        if note:
            detail += f"\n  » {note}"
        if st.get("evidence"):
            detail += f"\n  หลักฐาน: {st['evidence'][:110]}"

        pdf.set_font("TH", "", 8.3)
        line_h = 4.3
        lines = _wrapped(pdf, detail, W["detail"] - 2)
        vmark = _mark(it["scheme"], v)
        row_h = max(len(lines) * line_h, len(_wrapped(pdf, vmark, W["verdict"] - 2)) * line_h, 7)
        if pdf.get_y() + row_h > pdf.h - 15:
            pdf.add_page(); header_row()
        x0, y0 = pdf.l_margin, pdf.get_y()
        _box(pdf, x0, y0, W["id"], row_h, it["id"], line_h, align="C")
        _box(pdf, x0 + W["id"], y0, W["detail"], row_h, detail, line_h)
        fr, fg, fb = schemes.FILL.get(v, (255, 255, 255))
        _box(pdf, x0 + W["id"] + W["detail"], y0, W["verdict"], row_h, vmark, line_h, fill=(fr, fg, fb), align="C")
        ref = it["ref"] + (f"\n{it['otg']}" if it.get("otg") else "")
        _box(pdf, x0 + W["id"] + W["detail"] + W["verdict"], y0, W["ref"], row_h, ref, line_h, align="C")
        pdf.set_xy(x0, y0 + row_h)

    # ---------- แผนแก้ไข (แสดงเฉพาะเมื่อมีรายการ) ----------
    rem = rec.get("remediation", [])
    if rem:
        pdf.add_page()
        form_b = "ค.2" if fw.id == "ncsa" else "ก.2"
        mc(7, f"{form_b} แบบรายงานรายการที่ยังต้องปรับปรุง", "L", "B", 12)
        pdf.ln(1)
        cols = [("ลำดับ", 12), ("วันที่", 22), ("รายการที่ต้องปรับปรุง", 46), ("สาเหตุ", 30),
                ("สิ่งที่ต้องแก้ไข", 34), ("ผู้รับผิดชอบ", 22), ("แล้วเสร็จ", 14)]
        pdf.set_font("TH", "B", 8.5); pdf.set_fill_color(30, 58, 95); pdf.set_text_color(255, 255, 255)
        for lab, w in cols:
            pdf.cell(w, 7, lab, border=1, align="C", fill=True)
        pdf.ln(); pdf.set_text_color(0, 0, 0); pdf.set_font("TH", "", 8.5)
        for i, r in enumerate(rem, 1):
            vals = [str(i), r.get("date", ""), r.get("desc", ""), r.get("cause", ""),
                    r.get("fix", ""), r.get("owner", ""), r.get("due", "")]
            row_h = max([6] + [len(_wrapped(pdf, v, w - 2)) * 4.4 for (l, w), v in zip(cols, vals)])
            if pdf.get_y() + row_h > pdf.h - 15:
                pdf.add_page()
            x0, y0 = pdf.l_margin, pdf.get_y()
            cx = x0
            for (lab, w), val in zip(cols, vals):
                _box(pdf, cx, y0, w, row_h, val, 4.4)
                cx += w
            pdf.set_xy(x0, y0 + row_h)

    return bytes(pdf.output())


# ---------- PDF chart/box helpers ----------
def _hex(h):
    h = h.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _legend_bar(pdf, bd):
    total = sum(bd.values()) or 1
    segs = [("good", (31, 138, 76), "ผ่าน/ทำแล้ว"), ("partial", (199, 123, 0), "กำลังทำ"),
            ("bad", (198, 40, 40), "ต้องปรับปรุง"), ("na", (154, 164, 178), "ไม่เกี่ยว"),
            ("unset", (215, 220, 227), "ประเมินโดยผู้ตรวจ")]
    x = pdf.l_margin; y = pdf.get_y(); bw = 180
    cx = x
    for k, c, _ in segs:
        w = bd.get(k, 0) / total * bw
        if w > 0:
            pdf.set_fill_color(*c); pdf.rect(cx, y, w, 6, style="F"); cx += w
    pdf.set_y(y + 8)
    pdf.set_font("TH", "", 8.5)
    parts = "   ".join(f"{lab} {bd.get(k,0)}" for k, c, lab in segs)
    pdf.set_x(pdf.l_margin); pdf.cell(0, 4, parts, ln=1)


def _bar_chart(pdf, rows):
    pdf.set_font("TH", "", 9)
    lblw, barw, h = 62, 96, 5.4
    for label, pct, color in rows:
        y = pdf.get_y()
        if y + h + 2 > pdf.h - 15:
            pdf.add_page(); y = pdf.get_y()
        pdf.set_x(pdf.l_margin)
        pdf.cell(lblw, h + 1.5, label[:34])
        bx = pdf.l_margin + lblw
        pdf.set_fill_color(236, 239, 243); pdf.rect(bx, y + 1, barw, h, style="F")
        p = pct or 0
        c = _hex(color) if color else ((31, 138, 76) if p >= 80 else ((199, 123, 0) if p >= 50 else (198, 40, 40)))
        pdf.set_fill_color(*c); pdf.rect(bx, y + 1, barw * p / 100, h, style="F")
        pdf.set_xy(bx + barw + 2, y)
        pdf.cell(16, h + 1.5, (f"{pct}%" if pct is not None else "N/A"))
        pdf.ln(h + 2)


def _wrapped(pdf, text, w):
    lines = []
    for para in (text or "").split("\n"):
        if para == "":
            lines.append(""); continue
        cur = ""
        for ch in para:
            if pdf.get_string_width(cur + ch) > w and cur:
                lines.append(cur); cur = ch
            else:
                cur += ch
        lines.append(cur)
    return lines or [""]


def _box(pdf, x, y, w, h, text, line_h, fill=None, align="L"):
    if fill:
        pdf.set_fill_color(*fill); pdf.rect(x, y, w, h, style="DF")
    else:
        pdf.rect(x, y, w, h)
    lines = _wrapped(pdf, text, w - 2)
    ty = y + max((h - len(lines) * line_h) / 2, 0.4)
    for ln in lines:
        pdf.set_xy(x + 1, ty)
        pdf.cell(w - 2, line_h, ln, align=align)
        ty += line_h


def _mark(scheme, verdict):
    icon = {"ok": "[/]", "done": "[/]", "pass": "[/]", "fix": "[X]", "fail": "[X]",
            "notdone": "[X]", "inprog": "[~]", "cannot": "[?]", "na": "[-]", "unset": "[ ]"}.get(verdict, "[ ]")
    return f"{icon} {schemes.label(scheme, verdict)}"
