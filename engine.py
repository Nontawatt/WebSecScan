# -*- coding: utf-8 -*-
"""
Engine: รัน probe → map signals → checklist verdict อัตโนมัติ (pre-fill) แบบรองรับหลายมาตรฐาน
ETDA: auto ครอบคลุมช่องโหว่เชิงเทคนิค
NCSA: ส่วนใหญ่เป็น governance (ประเมินเอง) — probe ช่วยเฉพาะข้อเทคนิค (TLS, hardening) เป็นข้อมูลประกอบ
"""
import probe as P


# ---- แปลง signal.status -> verdict ตาม scheme ----
def _verdict(scheme, status):
    if scheme == "test":
        return {"pass": "pass", "fail": "fail", "warn": "cannot", "na": "cannot",
                "cannot": "cannot", "info": "cannot"}.get(status, "cannot")
    if scheme == "mat3":
        return {"pass": "done", "fail": "notdone", "warn": "inprog", "na": "na",
                "cannot": "unset", "info": "unset"}.get(status, "unset")
    # ctrl (ETDA) และ comply (NCSA) ใช้ done/ok ต่างชื่อแต่ตรรกะเดียว
    good = "ok" if scheme == "ctrl" else "done"
    return {"pass": good, "fail": "fix", "warn": "fix", "na": "na",
            "cannot": "unset", "info": "unset"}.get(status, "unset")


# คีย์ auto พิเศษที่ไม่ใช่ signal ตรง ๆ (annotate อย่างเดียว ไม่ตั้ง verdict)
_LINK_NOTE = {
    "etda_link": "แนะนำประเมินจากผลสแกนมาตรฐาน ETDA (ขมธอ.4-2559) ในเครื่องมือนี้",
    "va_link": "อ้างอิงผลการประเมินช่องโหว่ (VA) / Penetration Testing",
    "access_surface": "ตรวจพื้นผิว auth เบื้องต้นจากการสแกน — ยืนยันการควบคุมสิทธิ์เชิงลึกด้วยตนเอง",
}


def run_scan(base_url, depth="tool", framework=None, logger=None):
    """
    framework: object จาก frameworks.get() (มี .items). None = ETDA
    depth: 'passive' | 'active' | 'tool'
    คืน (signals, items_state, toollog)
    """
    import frameworks
    fw = framework or frameworks.get("etda")
    toollog = []

    def log(msg):
        toollog.append(msg)
        if logger:
            logger(msg)

    signals = {}
    log(f"[{fw.short}] เริ่มตรวจ {base_url} (depth={depth})")
    log("[passive] วิเคราะห์ header/cookie/TLS")
    signals.update(P.probe_passive(base_url))

    if "_error" in signals:
        log("[error] " + signals["_error"]["detail"])
        return signals, {}, toollog

    log("[passive] ตรวจ TLS/HTTPS")
    signals["tls_cipher"] = P.probe_tls(base_url)
    # header_disclosure ได้จาก passive แล้ว; access_surface = auth_surface
    signals["access_surface"] = signals.get("auth_surface", {"status": "info", "detail": "", "evidence": ""})

    if depth in ("active", "tool"):
        log("[active] reflected XSS")
        signals["xss_reflected"] = P.probe_xss(base_url)
        log("[active] path traversal")
        signals["traversal"] = P.probe_traversal(base_url)
        log("[active] CRLF / header injection")
        signals["crlf"] = P.probe_crlf(base_url)
        log("[active] SQL error leak")
        signals["error_leak"] = P.probe_sql_error(base_url)
        log("[active] ฟอร์มส่งอีเมล")
        signals["mail_form"] = P.probe_mail_form(base_url)

    if depth == "tool":
        signals["sqli"] = P.tool_sqlmap(base_url, log)
        signals["default_creds"] = P.tool_nmap_auth(base_url, log)
        signals["cmdi"] = P.tool_wapiti(base_url, "exec", log)
        wx = P.tool_wapiti(base_url, "xss", log)
        if wx["status"] == "fail" and signals.get("xss_reflected", {}).get("status") != "fail":
            signals["xss_reflected"] = wx
    else:
        for k in ("sqli", "cmdi", "default_creds"):
            signals.setdefault(k, {"status": "cannot", "detail": "ข้ามการเรียกเครื่องมือ (depth != tool)", "evidence": ""})

    items_state = map_to_items(fw.items, signals)
    filled = sum(1 for v in items_state.values() if v["verdict"] != "unset")
    log(f"[done] auto-fill {filled} / {len(fw.items)} ข้อ")
    return signals, items_state, toollog


def map_to_items(items, signals):
    state = {}
    for it in items:
        auto = it.get("auto")
        entry = {"verdict": "unset", "auto": False, "note": "", "evidence": "",
                 "signal": auto, "userNote": ""}
        if auto in _LINK_NOTE:
            entry["note"] = _LINK_NOTE[auto]
        elif auto and auto in signals:
            sig = signals[auto]
            entry["verdict"] = _verdict(it["scheme"], sig["status"])
            entry["auto"] = entry["verdict"] != "unset"
            entry["note"] = sig.get("detail", "")
            entry["evidence"] = sig.get("evidence", "")
        state[it["id"]] = entry
    return state
