# -*- coding: utf-8 -*-
"""
กราฟ SVG แบบ server-side (ไม่พึ่ง library ภายนอก — ปลอดภัย offline/CSP)
ใช้ทั้งในหน้าเว็บและฝัง raster ใน PDF ไม่ได้ จึงมี helper วาดใน fpdf2 แยก (report.py)
"""
import math

# สีสถานะรวม
C_GOOD = "#1f8a4c"
C_PARTIAL = "#c77b00"
C_BAD = "#c62828"
C_NA = "#9aa4b2"
C_UNSET = "#d7dce3"


def _pt(cx, cy, r, ang_deg):
    a = math.radians(ang_deg - 90)  # 0 = บน
    return cx + r * math.cos(a), cy + r * math.sin(a)


def radar(series, size=340, ring_pct=(25, 50, 75, 100)):
    """
    series: list of {label, value(0-100), color}
    คืน SVG string (แกนละจุด, polygon ค่า, ป้ายกำกับ)
    """
    n = len(series)
    if n < 3:
        return _fallback_bars(series, size)
    cx = cy = size / 2
    R = size / 2 - 58
    grid = []
    # วงกลมระดับ
    for rp in ring_pct:
        pts = [_pt(cx, cy, R * rp / 100, i * 360 / n) for i in range(n)]
        poly = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
        grid.append(f'<polygon points="{poly}" fill="none" stroke="#e2e8f0" stroke-width="1"/>')
    # แกน + ป้าย
    axes = []
    for i, s in enumerate(series):
        x, y = _pt(cx, cy, R, i * 360 / n)
        axes.append(f'<line x1="{cx}" y1="{cy}" x2="{x:.1f}" y2="{y:.1f}" stroke="#e2e8f0" stroke-width="1"/>')
        lx, ly = _pt(cx, cy, R + 20, i * 360 / n)
        anchor = "middle"
        if lx < cx - 8:
            anchor = "end"
        elif lx > cx + 8:
            anchor = "start"
        val = s.get("value")
        vtxt = f'{val}%' if val is not None else 'N/A'
        axes.append(
            f'<text x="{lx:.1f}" y="{ly:.1f}" text-anchor="{anchor}" dominant-baseline="middle" '
            f'font-size="11" font-weight="700" fill="#334">{_esc(s["label"])}</text>'
            f'<text x="{lx:.1f}" y="{ly+13:.1f}" text-anchor="{anchor}" dominant-baseline="middle" '
            f'font-size="10" fill="{s.get("color","#2f6fb0")}">{vtxt}</text>')
    # polygon ค่า
    vpts = []
    dots = []
    for i, s in enumerate(series):
        v = s.get("value") or 0
        x, y = _pt(cx, cy, R * v / 100, i * 360 / n)
        vpts.append(f"{x:.1f},{y:.1f}")
        dots.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.2" fill="{s.get("color","#2f6fb0")}"/>')
    valpoly = (f'<polygon points="{" ".join(vpts)}" fill="rgba(47,111,176,.18)" '
               f'stroke="#2f6fb0" stroke-width="2"/>')
    return (f'<svg viewBox="0 0 {size} {size}" width="100%" style="max-width:{size}px" '
            f'xmlns="http://www.w3.org/2000/svg" role="img">'
            + "".join(grid) + "".join(axes) + valpoly + "".join(dots) + "</svg>")


def donut(pct, size=170, label="สอดคล้อง", sub=""):
    """โดนัทแสดง % รวม (สีตามระดับ)"""
    if pct is None:
        pct = 0
        disp = "N/A"
        col = C_UNSET
    else:
        disp = f"{pct}%"
        col = C_GOOD if pct >= 80 else (C_PARTIAL if pct >= 50 else C_BAD)
    cx = cy = size / 2
    r = size / 2 - 16
    circ = 2 * math.pi * r
    dash = circ * pct / 100
    return (f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" '
            f'xmlns="http://www.w3.org/2000/svg" role="img">'
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#eceff3" stroke-width="16"/>'
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{col}" stroke-width="16" '
            f'stroke-linecap="round" stroke-dasharray="{dash:.1f} {circ:.1f}" '
            f'transform="rotate(-90 {cx} {cy})"/>'
            f'<text x="{cx}" y="{cy-2}" text-anchor="middle" font-size="30" font-weight="800" fill="{col}">{disp}</text>'
            f'<text x="{cx}" y="{cy+20}" text-anchor="middle" font-size="12" fill="#6b7686">{_esc(label)}</text>'
            + (f'<text x="{cx}" y="{cy+36}" text-anchor="middle" font-size="10.5" fill="#9aa4b2">{_esc(sub)}</text>' if sub else "")
            + '</svg>')


def stacked_bar(bd, width=100, height=14):
    """แถบสัดส่วน good/partial/bad/na/unset (breakdown dict) — คืน SVG inline width 100%"""
    total = sum(bd.values()) or 1
    segs = [("good", C_GOOD), ("partial", C_PARTIAL), ("bad", C_BAD), ("na", C_NA), ("unset", C_UNSET)]
    x = 0
    rects = []
    for k, c in segs:
        w = bd.get(k, 0) / total * 100
        if w <= 0:
            continue
        rects.append(f'<rect x="{x:.2f}" y="0" width="{w:.2f}" height="{height}" fill="{c}"/>')
        x += w
    return (f'<svg viewBox="0 0 100 {height}" width="100%" height="{height}" preserveAspectRatio="none" '
            f'xmlns="http://www.w3.org/2000/svg" style="border-radius:6px">' + "".join(rects) + "</svg>")


def hbars(rows):
    """
    แถบแนวนอนต่อกลุ่ม: rows = list of {label, pct, color}
    """
    rh = 26
    h = rh * len(rows) + 8
    out = [f'<svg viewBox="0 0 400 {h}" width="100%" xmlns="http://www.w3.org/2000/svg" role="img">']
    for i, r in enumerate(rows):
        y = i * rh + 4
        pct = r.get("pct")
        w = (pct or 0) / 100 * 250
        col = r.get("color") or (C_GOOD if (pct or 0) >= 80 else (C_PARTIAL if (pct or 0) >= 50 else C_BAD))
        out.append(f'<text x="0" y="{y+13}" font-size="11" fill="#334">{_esc(r["label"][:26])}</text>')
        out.append(f'<rect x="120" y="{y+4}" width="250" height="13" rx="3" fill="#eef1f5"/>')
        out.append(f'<rect x="120" y="{y+4}" width="{w:.1f}" height="13" rx="3" fill="{col}"/>')
        out.append(f'<text x="376" y="{y+14}" font-size="10.5" text-anchor="end" fill="#556">'
                   f'{(str(pct)+"%") if pct is not None else "N/A"}</text>')
    out.append("</svg>")
    return "".join(out)


def legend():
    items = [("ผ่าน/ดำเนินการแล้ว", C_GOOD), ("อยู่ระหว่างดำเนินการ", C_PARTIAL),
             ("ยังต้องปรับปรุง", C_BAD), ("ไม่เกี่ยวข้อง", C_NA), ("ประเมินโดยผู้ตรวจ", C_UNSET)]
    sp = "".join(
        f'<span style="display:inline-flex;align-items:center;gap:5px;margin-right:12px;font-size:12px">'
        f'<span style="width:11px;height:11px;border-radius:3px;background:{c};display:inline-block"></span>{t}</span>'
        for t, c in items)
    return f'<div style="margin-top:6px">{sp}</div>'


def _fallback_bars(series, size):
    rows = [{"label": s["label"], "pct": s.get("value"), "color": s.get("color")} for s in series]
    return hbars(rows)


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
