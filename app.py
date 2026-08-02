# -*- coding: utf-8 -*-
"""
ETDA/NCSA Website Security checklist scanner — เว็บ UI (stdlib http.server)
รองรับหลายมาตรฐาน (ETDA ขมธอ.4-2559 + NCSA 2568), สแกนอัตโนมัติ, กรอก checklist,
ฟอร์มแก้ไข, dashboard ข้ามโปรเจกต์, กราฟ SVG, export PDF/CSV/JSON

รัน:  ./run.sh   (default http://127.0.0.1:8091)
"""
import html
import json
import os
import threading
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import charts
import engine
import frameworks
import probe
import report
import schemes
import store

HOST = os.environ.get("ETDA_HOST", "127.0.0.1")
PORT = int(os.environ.get("ETDA_PORT", "8091"))

JOBS = {}
_jlock = threading.Lock()


def start_scan_job(pid, target, depth, fw_id):
    jid = store.nid("job")
    with _jlock:
        JOBS[jid] = {"id": jid, "pid": pid, "target": target, "depth": depth, "framework": fw_id,
                     "status": "running", "log": [], "assessment_id": None, "error": None}

    def logger(msg):
        with _jlock:
            JOBS[jid]["log"].append(msg)

    def work():
        try:
            fw = frameworks.get(fw_id)
            signals, items_state, toollog = engine.run_scan(target, depth, fw, logger)
            if "_error" in signals:
                with _jlock:
                    JOBS[jid]["status"] = "error"
                    JOBS[jid]["error"] = signals["_error"]["detail"]
                return
            rec = store.add_assessment(pid, target, depth, signals, items_state, toollog,
                                       probe.available_tools(), framework=fw_id)
            with _jlock:
                JOBS[jid]["status"] = "done"
                JOBS[jid]["assessment_id"] = rec["id"]
        except Exception as e:
            with _jlock:
                JOBS[jid]["status"] = "error"
                JOBS[jid]["error"] = f"{e}\n{traceback.format_exc()}"

    threading.Thread(target=work, daemon=True).start()
    return jid


def esc(s):
    return html.escape(str(s or ""))


PAGE = """<!doctype html><html lang="th"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root{{--card:#fff;--ink:#141c28;--muted:#5c6675;--line:#e3e8ef;
--brand:#1e3a5f;--brand2:#2f6fb0;--ok:#1f8a4c;--fix:#c62828;--warn:#c77b00;--na:#5a6473;}}
*{{box-sizing:border-box}}
html{{font-size:17.5px}}
body{{margin:0;font-family:"Garuda","TH Sarabun New","Segoe UI",Tahoma,sans-serif;
background:#eef1f6;color:var(--ink);font-size:1rem;line-height:1.62}}
a{{color:var(--brand2);text-decoration:none;font-weight:600}}a:hover{{text-decoration:underline}}
header{{background:linear-gradient(105deg,#13233a,#20456e);color:#fff;padding:18px 26px;
display:flex;align-items:center;gap:16px;box-shadow:0 3px 14px rgba(10,20,40,.22)}}
header .logo{{font-size:1.55rem;font-weight:800;letter-spacing:.3px}} header .sub{{opacity:.85;font-size:.86rem}}
header .spacer{{flex:1}} header a{{color:#dbe8f6;margin-left:20px;font-size:1rem}}
.wrap{{max-width:1220px;margin:26px auto;padding:0 20px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:24px 26px;
margin-bottom:22px;box-shadow:0 2px 12px rgba(20,30,50,.06)}}
h1{{font-size:1.75rem;margin:.15em 0;letter-spacing:-.01em}} h2{{font-size:1.32rem;margin:.5em 0}}
h3{{font-size:1.08rem;margin:.4em 0}}
.muted{{color:var(--muted)}}
.btn{{display:inline-block;background:var(--brand2);color:#fff;border:0;border-radius:10px;
padding:11px 20px;font-size:1rem;font-weight:700;cursor:pointer;font-family:inherit;transition:.15s}}
.btn:hover{{background:#255e97;text-decoration:none;box-shadow:0 3px 10px rgba(47,111,176,.3)}}
.btn.sm{{padding:7px 14px;font-size:.9rem}} .btn.gray{{background:#54606f}} .btn.red{{background:#c0392b}}
.btn.green{{background:#1f8a4c}} .btn.ghost{{background:#eef2f7;color:var(--brand)}}
input,select,textarea{{font-family:inherit;font-size:1rem;padding:11px 13px;border:1.5px solid #ccd5e0;
border-radius:10px;width:100%;background:#fff;color:var(--ink)}}
input:focus,select:focus,textarea:focus{{outline:none;border-color:var(--brand2);box-shadow:0 0 0 3px rgba(47,111,176,.15)}}
label{{font-size:.9rem;color:var(--muted);display:block;margin:12px 0 5px;font-weight:600}}
table{{width:100%;border-collapse:collapse;font-size:1rem}}
th,td{{border:1px solid var(--line);padding:11px 13px;text-align:left;vertical-align:top}}
th{{background:#eef3f9;font-weight:700;font-size:.98rem}}
tbody tr:hover{{background:#f8fafc}}
.row{{display:flex;gap:16px;flex-wrap:wrap}} .row>*{{flex:1;min-width:200px}}
.pill{{display:inline-block;padding:4px 12px;border-radius:20px;font-size:.9rem;font-weight:700}}
.pill.ok{{background:#dff6e0;color:var(--ok)}} .pill.fix{{background:#fbe0e0;color:var(--fix)}}
.pill.na{{background:#e9ecf1;color:var(--na)}} .pill.cannot{{background:#fff2d6;color:var(--warn)}}
.pill.warn{{background:#fff2d6;color:var(--warn)}} .pill.unset{{background:#eef1f5;color:#8a94a3}}
.pill.info{{background:#e0edf9;color:var(--brand2)}}
.cat-head td{{background:#e9f0f8;font-weight:700;font-size:1.05rem}}
.csf-head td{{color:#fff;font-weight:800;font-size:1.15rem;padding:12px 14px;letter-spacing:.02em}}
.sub td:first-child{{padding-left:26px}}
.sub{{background:#fafbfd}}
.autotag{{font-size:.78rem;background:#e0edf9;color:#2f6fb0;padding:2px 8px;border-radius:6px;margin-left:7px;font-weight:700}}
.mantag{{font-size:.78rem;background:#eceff3;color:#697382;padding:2px 8px;border-radius:6px;margin-left:7px;font-weight:700}}
.applytag{{font-size:.78rem;background:#fdf0e3;color:#b5701c;padding:2px 8px;border-radius:6px;margin-left:7px;font-weight:700}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:16px}}
.kpi{{text-align:center;padding:18px 14px;border-radius:14px;background:linear-gradient(180deg,#fafcfe,#f2f6fb);border:1px solid var(--line)}}
.kpi .n{{font-size:2.3rem;font-weight:800;line-height:1.1}}
.log{{background:#0d1622;color:#b8f0c8;font-family:ui-monospace,Consolas,monospace;font-size:.85rem;
padding:15px;border-radius:10px;max-height:340px;overflow:auto;white-space:pre-wrap;line-height:1.5}}
.small{{font-size:.86rem}}
.evi{{font-family:ui-monospace,Consolas,monospace;font-size:.8rem;color:#4a5364;white-space:pre-wrap;
word-break:break-all;background:#f5f8fb;border-radius:7px;padding:6px 9px;margin-top:5px}}
select.v{{padding:8px 10px;font-size:.95rem;font-weight:600}}
.fwbadge{{display:inline-block;padding:4px 13px;border-radius:8px;font-size:.86rem;font-weight:800}}
.fwbadge.etda{{background:#e3effb;color:#1e5fa0}} .fwbadge.ncsa{{background:#efe7f8;color:#6d4c9f}}
.flex{{display:flex;gap:20px;flex-wrap:wrap;align-items:center}}
footer{{text-align:center;color:#8b96a5;font-size:.82rem;padding:28px}}
</style></head><body>
<header>
<span style="display:inline-flex;align-items:center;gap:10px">
<svg width="26" height="30" viewBox="0 0 24 28" fill="none" xmlns="http://www.w3.org/2000/svg">
<path d="M12 1L22 5v8c0 6.2-4.3 11.6-10 13.5C6.3 24.6 2 19.2 2 13V5l10-4z" fill="#2f6fb0" stroke="#cfe0f2" stroke-width="1.2"/>
<path d="M7.5 13.5l3 3 6-6.5" stroke="#fff" stroke-width="2.2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>
<span class="logo">WebSec Checklist</span></span>
<div class="sub">แบบตรวจสอบความมั่นคงปลอดภัยเว็บไซต์ · ETDA ขมธอ.4-2559 + NCSA 2568</div>
<div class="spacer"></div>
<a href="/">โปรเจกต์</a><a href="/dashboard">แดชบอร์ด</a>
</header>
<div class="wrap">{body}</div>
<footer>ETDA ขมธอ.4-2559 · NCSA/สกมช. Website Security Standard 2568 · เครื่องมือช่วยประเมินตนเอง (Self-Assessment) · localhost</footer>
</body></html>"""


def render(title, body):
    return PAGE.format(title=esc(title), body=body).encode("utf-8")


def fw_badge(fw_id):
    fw = frameworks.get(fw_id)
    return f'<span class="fwbadge {fw.id}">{esc(fw.short)}</span>'


# ---------------- Index ---------------- #
def view_index():
    projects = store.list_projects()
    rows = ""
    for p in projects:
        rows += f"""<tr>
        <td><a href="/project?id={p['id']}"><b>{esc(p['name'])}</b></a><div class="muted small">{esc(p.get('note',''))}</div></td>
        <td>{esc(p.get('owner','') or '-')}</td><td>{len(p.get('assessments',[]))}</td>
        <td class="small muted">{esc(p['created'])}</td>
        <td><a class="btn sm red" href="/delete_project?id={p['id']}" onclick="return confirm('ลบโปรเจกต์และผลตรวจทั้งหมด?')">ลบ</a></td></tr>"""
    if not rows:
        rows = '<tr><td colspan="5" class="muted">ยังไม่มีโปรเจกต์ — สร้างใหม่ด้านล่าง</td></tr>'
    body = f"""
    <div class="card"><div class="flex" style="justify-content:space-between">
      <div><h1>โปรเจกต์ตรวจสอบเว็บไซต์</h1>
      <p class="muted" style="margin:0">ประเมินตามมาตรฐาน <b>ETDA ขมธอ.4-2559</b> (ช่องโหว่เว็บแอป) และ <b>NCSA 2568</b> (ครบวงจรตาม NIST CSF) — เก็บได้หลายเป้าหมายและหลายรอบ</p></div>
      <a class="btn" href="/dashboard">แดชบอร์ดรวม</a>
    </div></div>
    <div class="card"><table><thead><tr><th>โปรเจกต์</th><th>ผู้ดูแล</th><th>รอบตรวจ</th><th>สร้างเมื่อ</th><th></th></tr></thead>
      <tbody>{rows}</tbody></table></div>
    <div class="card"><h2>+ สร้างโปรเจกต์ใหม่</h2>
      <form method="post" action="/add_project">
        <div class="row"><div><label>ชื่อโปรเจกต์</label><input name="name" required placeholder="เช่น เว็บไซต์หน่วยงาน ก."></div>
          <div><label>ผู้ดูแล/หน่วยงาน</label><input name="owner" placeholder="เช่น ฝ่ายไอที"></div></div>
        <label>หมายเหตุ</label><input name="note" placeholder="รายละเอียดเพิ่มเติม (ถ้ามี)">
        <div style="margin-top:12px"><button class="btn">สร้างโปรเจกต์</button></div>
      </form></div>"""
    return render("โปรเจกต์", body)


# ---------------- Dashboard ---------------- #
def view_dashboard():
    projects = store.list_projects()
    cards = ""
    agg = {}  # fw_id -> list of pct
    for p in projects:
        for aid in p.get("assessments", []):
            rec = store.get_assessment(aid)
            if not rec:
                continue
            fw = frameworks.get(rec.get("framework", "etda"))
            comp = fw.compliance(rec["items"])
            agg.setdefault(fw.id, []).append(comp["pct"] or 0)
            bd = fw.breakdown(rec["items"])
            cards += f"""<tr>
              <td><a href="/project?id={p['id']}">{esc(p['name'])}</a></td>
              <td><a href="/assess?id={aid}">{esc(rec.get('site_label') or rec['target'])}</a></td>
              <td>{fw_badge(fw.id)}</td>
              <td style="min-width:160px">{charts.stacked_bar(bd)}</td>
              <td style="text-align:center"><b style="font-size:17px">{comp['pct'] if comp['pct'] is not None else '—'}%</b>
                <div class="muted small">ประเมิน {comp['assessed']}/{comp['total']}</div></td>
              <td class="small muted">{esc(rec['created'])}</td></tr>"""
    if not cards:
        cards = '<tr><td colspan="6" class="muted">ยังไม่มีผลการตรวจ</td></tr>'

    # KPI ต่อ framework
    kpis = ""
    for fw in frameworks.all_frameworks():
        vals = agg.get(fw.id, [])
        avg = round(sum(vals) / len(vals)) if vals else None
        kpis += f"""<div class="kpi"><div class="muted small">{esc(fw.short)}</div>
          <div class="n" style="color:{'#1f8a4c' if (avg or 0)>=80 else ('#c77b00' if (avg or 0)>=50 else '#c62828')}">{avg if avg is not None else '—'}%</div>
          <div class="muted small">เฉลี่ย {len(vals)} รอบตรวจ</div></div>"""

    body = f"""
    <div class="card"><h1>แดชบอร์ดรวม</h1>
      <p class="muted">ภาพรวมความสอดคล้อง (compliance) ทุกโปรเจกต์/ทุกรอบตรวจ</p>
      <div class="grid">{kpis}</div>
      {charts.legend()}
    </div>
    <div class="card"><h2>ผลการตรวจทั้งหมด</h2>
      <table><thead><tr><th>โปรเจกต์</th><th>เป้าหมาย</th><th>มาตรฐาน</th><th>สัดส่วนผล</th><th>สอดคล้อง</th><th>วันที่</th></tr></thead>
      <tbody>{cards}</tbody></table>
    </div>"""
    return render("แดชบอร์ด", body)


# ---------------- Project ---------------- #
def view_project(pid):
    p = store.get_project(pid)
    if not p:
        return render("ไม่พบ", '<div class="card">ไม่พบโปรเจกต์</div>')
    rows = ""
    for aid in p.get("assessments", []):
        rec = store.get_assessment(aid)
        if not rec:
            continue
        fw = frameworks.get(rec.get("framework", "etda"))
        comp = fw.compliance(rec["items"])
        bd = fw.breakdown(rec["items"])
        rows += f"""<tr>
        <td><a href="/assess?id={aid}"><b>{esc(rec.get('site_label') or rec['target'])}</b></a>
            <div class="muted small">{esc(rec['target'])}</div></td>
        <td>{fw_badge(fw.id)}</td>
        <td class="small">{esc(rec['created'])}</td>
        <td style="min-width:150px">{charts.stacked_bar(bd)}
            <div class="small muted">สอดคล้อง {comp['pct'] if comp['pct'] is not None else '—'}% · ประเมิน {comp['assessed']}/{comp['total']}</div></td>
        <td><a class="btn sm" href="/assess?id={aid}">เปิด</a>
          <a class="btn sm red" href="/delete_assess?id={aid}" onclick="return confirm('ลบผลตรวจนี้?')">ลบ</a></td></tr>"""
    if not rows:
        rows = '<tr><td colspan="5" class="muted">ยังไม่มีการตรวจ — เริ่มด้านล่าง</td></tr>'

    tools = probe.available_tools()
    tool_badges = " ".join(f'<span class="pill {"ok" if v else "unset"}">{k} {"✓" if v else "✗"}</span>' for k, v in tools.items())
    fw_opts = "".join(f'<option value="{fw.id}">{esc(fw.short)} — {esc(fw.name)}</option>' for fw in frameworks.all_frameworks())

    body = f"""
    <div class="card">
      <h1 style="margin:0">{esc(p['name'])}</h1>
      <div class="muted">{esc(p.get('owner',''))} · สร้าง {esc(p['created'])}</div>
      <p class="muted small">{esc(p.get('note',''))}</p>
    </div>
    <div class="card"><h2>เริ่มการตรวจใหม่</h2>
      <form method="post" action="/scan">
        <input type="hidden" name="pid" value="{pid}">
        <label>มาตรฐานที่ใช้ประเมิน</label>
        <select name="framework">{fw_opts}</select>
        <div class="row" style="margin-top:8px">
          <div style="flex:2"><label>URL เป้าหมาย (ใส่ query param เช่น ?id=1 เพื่อทดสอบ injection ได้แม่นขึ้น)</label>
            <input name="target" required placeholder="https://example.com/app?id=1"></div>
          <div><label>ระดับการสแกนอัตโนมัติ</label>
            <select name="depth">
              <option value="tool">Passive + Active + เครื่องมือจริง (แนะนำ)</option>
              <option value="active">Passive + Active</option>
              <option value="passive">Passive อย่างเดียว</option>
            </select></div>
        </div>
        <div style="margin-top:12px"><button class="btn green">เริ่มสแกน</button>
        <span class="muted small" style="margin-left:10px">เครื่องมือในเครื่อง: {tool_badges}</span></div>
      </form>
      <p class="muted small" style="margin-top:8px">ETDA เน้นช่องโหว่เทคนิค (auto-fill ได้มาก) · NCSA เป็น governance ตาม NIST CSF (ส่วนใหญ่ประเมินเอง — สแกนช่วยเฉพาะข้อเทคนิค)
      · ⚠ ตรวจเฉพาะเว็บที่ได้รับอนุญาต</p>
    </div>
    <div class="card"><h2>ประวัติการตรวจ</h2>
      <table><thead><tr><th>เป้าหมาย</th><th>มาตรฐาน</th><th>วันที่</th><th>สรุปผล</th><th></th></tr></thead>
      <tbody>{rows}</tbody></table></div>"""
    return render(p["name"], body)


def view_scan_wait(jid):
    body = f"""
    <div class="card"><h2>⏳ กำลังสแกน…</h2>
      <p class="muted">ตรวจอัตโนมัติ (passive → active → เครื่องมือ) แล้วเติมผลลง checklist ให้</p>
      <div class="log" id="log">เริ่มงาน…</div></div>
    <script>
    const jid="{jid}";
    async function poll(){{
      const r=await fetch("/job?id="+jid); const j=await r.json();
      document.getElementById("log").textContent=(j.log||[]).join("\\n");
      if(j.status==="done"){{location.href="/assess?id="+j.assessment_id;return;}}
      if(j.status==="error"){{document.getElementById("log").textContent+="\\n\\n[ผิดพลาด] "+j.error;return;}}
      setTimeout(poll,1200);
    }}
    poll();
    </script>"""
    return render("กำลังสแกน", body)


# ---------------- Assessment ---------------- #
def view_assessment(aid):
    rec = store.get_assessment(aid)
    if not rec:
        return render("ไม่พบ", '<div class="card">ไม่พบผลการตรวจ</div>')
    fw = frameworks.get(rec.get("framework", "etda"))
    comp = fw.compliance(rec["items"])
    bd = fw.breakdown(rec["items"])

    # ----- charts block -----
    donut = charts.donut(comp["pct"], label="สอดคล้องรวม",
                         sub=f"ประเมิน {comp['assessed']}/{comp['total']} ข้อ")
    if fw.uses_csf:
        csf = fw.csf_summary(rec["items"])
        series = [{"label": c["label"].split(" (")[0], "value": c["comp"]["pct"], "color": c["color"]} for c in csf]
        chart2 = f'<h3>ความสอดคล้องตามฟังก์ชัน NIST CSF</h3>{charts.radar(series)}'
        rows_hb = [{"label": c["label"].split(" (")[0], "pct": c["comp"]["pct"], "color": c["color"]} for c in csf]
    else:
        gs = fw.group_summary(rec["items"])
        rows_hb = [{"label": g["id"] + " " + g["name"].split(" (")[0], "pct": g["comp"]["pct"]} for g in gs]
        chart2 = f'<h3>ความสอดคล้องตามหมวด</h3>{charts.hbars(rows_hb)}'

    charts_block = f"""
    <div class="card"><div class="flex" style="align-items:flex-start">
      <div style="flex:0 0 auto;text-align:center">{donut}
        {charts.stacked_bar(bd)}</div>
      <div style="flex:1;min-width:280px">{chart2}</div>
    </div>{charts.legend()}</div>"""

    # ----- checklist table -----
    tbody = ""
    cur_group = None
    cur_csf = None
    for it in fw.items:
        # CSF band
        if fw.uses_csf and it["csf"] != cur_csf:
            cur_csf = it["csf"]
            col = fw.csf_color.get(cur_csf, "#334")
            tbody += f'<tr class="csf-head" style="background:{col}"><td colspan="4">◆ {esc(fw.csf_label.get(cur_csf,cur_csf))}</td></tr>'
        if it["cat"] != cur_group:
            cur_group = it["cat"]
            info = fw.cat_info.get(cur_group, {})
            extra = f'<div class="muted small" style="font-weight:400">ภัยคุกคาม: {esc(info.get("threat",""))}</div>' if info.get("threat") else ""
            tbody += f'<tr class="cat-head"><td colspan="4">{esc(it["cat_name"])}{extra}</td></tr>'

        st = rec["items"].get(it["id"], {})
        v = st.get("verdict", "unset")
        opts = schemes.verdicts(it["scheme"])
        sel = "".join(f'<option value="{o}" {"selected" if v==o else ""}>{esc(schemes.label(it["scheme"],o))}</option>' for o in opts)
        if st.get("auto"):
            tag = '<span class="autotag">auto</span>'
        elif it.get("auto"):
            tag = '<span class="autotag">auto?</span>'
        else:
            tag = '<span class="mantag">ประเมินเอง</span>'
        apply_tag = f'<span class="applytag">{esc(it["applies_to"])}</span>' if it.get("applies_to") else ""
        note_html = f'<div class="muted small" style="margin-top:3px">» {esc(st.get("note",""))}</div>' if st.get("note") else ""
        evi_html = f'<div class="evi">{esc(st.get("evidence",""))}</div>' if st.get("evidence") else ""
        row_cls = "sub" if it.get("level") == "sub" else ""
        ref_txt = esc(it["ref"]) + ((" · " + esc(it["otg"])) if it.get("otg") else "")
        pill = schemes.PILL.get(v, "unset")
        tbody += f"""<tr class="{row_cls}">
          <td class="small"><b>{esc(it['id'])}</b></td>
          <td>{esc(it['text'])}{tag}{apply_tag}{note_html}{evi_html}
            <div class="muted small" style="margin-top:3px">อ้างอิง {ref_txt}</div></td>
          <td style="width:190px">
            <select class="v" onchange="setv('{esc(it['id'])}',this.value)">{sel}</select>
            <input class="small" style="margin-top:5px" placeholder="หมายเหตุผู้ตรวจ" value="{esc(st.get('userNote',''))}"
                   onblur="setnote('{esc(it['id'])}',this.value)"></td>
          <td><span class="pill {pill}">{esc(schemes.label(it['scheme'],v))}</span></td>
        </tr>"""

    rem = rec.get("remediation", [])
    rem_json = json.dumps(rem, ensure_ascii=False)
    fix_verdicts = ["fix", "fail", "notdone"]
    depth_label = {"passive": "Passive", "active": "Passive + Active",
                   "tool": "Passive + Active + เครื่องมือจริง"}.get(rec["depth"], rec["depth"])
    is_ncsa = fw.id == "ncsa"
    form_a = "ค.1" if is_ncsa else "ก.1"
    form_b = "ค.2" if is_ncsa else "ก.2"

    body = f"""
    <div class="card">
      <div class="flex" style="justify-content:space-between">
        <div style="min-width:240px">
          <div>{fw_badge(fw.id)}</div>
          <h1 style="margin:.2em 0 0">{esc(rec.get('site_label') or rec['target'])}</h1>
          <div class="muted small">{esc(rec['target'])} · ตรวจ {esc(rec['created'])} · ระดับ {esc(depth_label)}</div>
        </div>
        <div>
          <a class="btn ghost sm" href="/export?id={aid}&fmt=pdf">PDF</a>
          <a class="btn ghost sm" href="/export?id={aid}&fmt=csv">CSV</a>
          <a class="btn ghost sm" href="/export?id={aid}&fmt=json">JSON</a>
          <a class="btn sm" href="/project?id={rec['project_id']}">← โปรเจกต์</a>
        </div>
      </div>
      <div class="row" style="margin-top:10px">
        <div><label>เว็บไซต์ (แสดงในรายงาน)</label><input id="site" value="{esc(rec.get('site_label',''))}" onblur="setmeta()"></div>
        <div><label>ตรวจโดยหน่วยงาน/ผู้ตรวจ</label><input id="auditor" value="{esc(rec.get('audited_by',''))}" onblur="setmeta()"></div>
      </div>
      <div class="muted small" style="margin-top:6px">มาตรฐาน: {esc(fw.std)}</div>
    </div>

    {charts_block}

    <div class="card">
      <h2>{form_a} แบบตรวจรายการเพื่อตรวจสอบสถานะความมั่นคงปลอดภัยของเว็บไซต์</h2>
      <p class="muted small"><span class="autotag">auto</span> = เติมจากผลสแกน · <span class="autotag">auto?</span> = มีข้อมูลประกอบให้พิจารณา · <span class="mantag">ประเมินเอง</span> = ระดับนโยบาย/กระบวนการ · <span class="applytag">เงื่อนไข</span> = บังคับใช้เฉพาะบางหน่วยงาน (เลือก "ไม่เกี่ยวข้อง" ได้)</p>
      <table><thead><tr><th style="width:70px">ข้อ</th><th>ข้อกำหนด / ข้อเสนอแนะ</th><th style="width:190px">ผลการประเมิน</th><th style="width:110px">สรุป</th></tr></thead>
      <tbody>{tbody}</tbody></table>
    </div>

    <div class="card">
      <h2>{form_b} แบบรายงานรายการที่ยังต้องปรับปรุง</h2>
      <p class="muted small">บันทึกแผนแก้ไขสำหรับข้อที่ผล = "ยังต้องปรับปรุง / ทดสอบไม่ผ่าน / ยังไม่ได้ดำเนินการ"</p>
      <table><thead><tr><th style="width:34px">#</th><th style="width:110px">วันที่</th><th>รายการที่ต้องปรับปรุง</th>
        <th>สาเหตุ</th><th>สิ่งที่ต้องแก้ไข</th><th style="width:110px">ผู้รับผิดชอบ</th>
        <th style="width:110px">วันแล้วเสร็จ</th><th style="width:40px"></th></tr></thead>
      <tbody id="rembody"></tbody></table>
      <div style="margin-top:10px">
        <button class="btn sm ghost" onclick="addrow()">+ เพิ่มแถว</button>
        <button class="btn sm ghost" onclick="fillfromfix()">↳ ดึงข้อที่ต้องปรับปรุงมาใส่</button>
        <button class="btn sm green" onclick="saverem()">บันทึก</button>
        <span id="remmsg" class="muted small"></span></div>
    </div>

    <div class="card"><h2>บันทึกการสแกน (log)</h2>
      <div class="log">{esc(chr(10).join(rec.get('toollog',[])))}</div></div>

    <script>
    const aid="{aid}";
    async function setv(id,v){{await fetch("/api/item",{{method:"POST",headers:{{'Content-Type':'application/json'}},
      body:JSON.stringify({{aid,id,verdict:v}})}});location.reload();}}
    async function setnote(id,v){{await fetch("/api/note",{{method:"POST",headers:{{'Content-Type':'application/json'}},
      body:JSON.stringify({{aid,id,note:v}})}});}}
    async function setmeta(){{await fetch("/api/meta",{{method:"POST",headers:{{'Content-Type':'application/json'}},
      body:JSON.stringify({{aid,site:document.getElementById('site').value,auditor:document.getElementById('auditor').value}})}});}}
    let rem={rem_json};
    const FIX_ITEMS={json.dumps([{"id":it["id"],"text":it["text"]} for it in fw.items], ensure_ascii=False)};
    const FIXVERD={json.dumps({it["id"]: rec["items"].get(it["id"],{}).get("verdict","unset") for it in fw.items}, ensure_ascii=False)};
    const FIXSET={json.dumps(fix_verdicts)};
    function td(v,k,i){{return '<td><textarea rows="2" style="min-width:120px" oninput="rem['+i+'].'+k+'=this.value">'+(v||'')+'</textarea></td>';}}
    function tdd(v,k,i){{return '<td><input value="'+(v||'').replace(/"/g,'&quot;')+'" oninput="rem['+i+'].'+k+'=this.value"></td>';}}
    function draw(){{const b=document.getElementById('rembody');b.innerHTML='';
      rem.forEach((r,i)=>{{const tr=document.createElement('tr');
        tr.innerHTML='<td>'+(i+1)+'</td>'+tdd(r.date,'date',i)+td(r.desc,'desc',i)+td(r.cause,'cause',i)+
          td(r.fix,'fix',i)+tdd(r.owner,'owner',i)+tdd(r.due,'due',i)+
          '<td><button class="btn sm red" onclick="rem.splice('+i+',1);draw()">×</button></td>';
        b.appendChild(tr);}});
      if(!rem.length)b.innerHTML='<tr><td colspan="8" class="muted">— ยังไม่มีรายการ —</td></tr>';}}
    function addrow(){{rem.push({{date:new Date().toISOString().slice(0,10),desc:'',cause:'',fix:'',owner:'',due:''}});draw();}}
    function fillfromfix(){{FIX_ITEMS.forEach(it=>{{const v=FIXVERD[it.id];
      if(FIXSET.includes(v) && !rem.some(r=>r.desc.startsWith('['+it.id+']')))
        rem.push({{date:new Date().toISOString().slice(0,10),desc:'['+it.id+'] '+it.text,cause:'',fix:'',owner:'',due:''}});}});draw();}}
    async function saverem(){{await fetch("/api/rem",{{method:"POST",headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{aid,rows:rem}})}});
      document.getElementById('remmsg').textContent='  ✓ บันทึกแล้ว';setTimeout(()=>document.getElementById('remmsg').textContent='',2000);}}
    draw();
    </script>"""
    return render(rec.get("site_label") or rec["target"], body)


# ---------------- HTTP handler ---------------- #
class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, ctype="text/html; charset=utf-8", code=200, headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, loc):
        self.send_response(303)
        self.send_header("Location", loc)
        self.end_headers()

    def _form(self):
        ln = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(ln).decode("utf-8") if ln else ""
        if "application/json" in self.headers.get("Content-Type", ""):
            return json.loads(raw or "{}")
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        path = u.path
        try:
            if path == "/":
                return self._send(view_index())
            if path == "/dashboard":
                return self._send(view_dashboard())
            if path == "/project":
                return self._send(view_project(q.get("id", [""])[0]))
            if path == "/assess":
                return self._send(view_assessment(q.get("id", [""])[0]))
            if path == "/scanwait":
                return self._send(view_scan_wait(q.get("id", [""])[0]))
            if path == "/job":
                with _jlock:
                    j = JOBS.get(q.get("id", [""])[0], {"status": "error", "error": "ไม่พบงาน"})
                return self._send(json.dumps(j, ensure_ascii=False), "application/json")
            if path == "/delete_project":
                store.delete_project(q.get("id", [""])[0])
                return self._redirect("/")
            if path == "/delete_assess":
                rec = store.get_assessment(q.get("id", [""])[0])
                pid = rec["project_id"] if rec else ""
                store.delete_assessment(q.get("id", [""])[0])
                return self._redirect(f"/project?id={pid}")
            if path == "/export":
                return self._export(q.get("id", [""])[0], q.get("fmt", ["json"])[0])
            return self._send("404", code=404)
        except Exception:
            return self._send(render("error", f'<div class="card"><h2>ผิดพลาด</h2><pre>{esc(traceback.format_exc())}</pre></div>'), code=500)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        try:
            f = self._form()
            if path == "/add_project":
                p = store.add_project(f.get("name", ""), f.get("owner", ""), f.get("note", ""))
                return self._redirect(f"/project?id={p['id']}")
            if path == "/scan":
                jid = start_scan_job(f["pid"], f["target"].strip(), f.get("depth", "tool"), f.get("framework", "etda"))
                return self._redirect(f"/scanwait?id={jid}")
            if path == "/api/item":
                store.update_item(f["aid"], f["id"], verdict=f.get("verdict"))
                return self._send('{"ok":true}', "application/json")
            if path == "/api/note":
                rec = store.get_assessment(f["aid"])
                if rec:
                    rec["items"].setdefault(f["id"], {})["userNote"] = f.get("note", "")
                    store.save_assessment(rec)
                return self._send('{"ok":true}', "application/json")
            if path == "/api/rem":
                store.set_remediation(f["aid"], f.get("rows", []))
                return self._send('{"ok":true}', "application/json")
            if path == "/api/meta":
                store.set_meta(f["aid"], f.get("site"), f.get("auditor"))
                return self._send('{"ok":true}', "application/json")
            return self._send("404", code=404)
        except Exception:
            return self._send(json.dumps({"ok": False, "error": traceback.format_exc()}, ensure_ascii=False),
                              "application/json", code=500)

    def _export(self, aid, fmt):
        rec = store.get_assessment(aid)
        if not rec:
            return self._send("not found", code=404)
        base = (rec.get("site_label") or rec["target"]).replace("https://", "").replace("http://", "")
        base = "".join(c if c.isalnum() else "_" for c in base)[:40] or "report"
        if fmt == "json":
            return self._send(report.to_json(rec), "application/json; charset=utf-8",
                              headers={"Content-Disposition": f'attachment; filename="{base}.json"'})
        if fmt == "csv":
            return self._send(report.to_csv(rec), "text/csv; charset=utf-8",
                              headers={"Content-Disposition": f'attachment; filename="{base}.csv"'})
        if fmt == "pdf":
            try:
                pdf = report.to_pdf(rec)
            except Exception:
                return self._send(render("error", f'<div class="card"><h2>สร้าง PDF ไม่ได้</h2><pre>{esc(traceback.format_exc())}</pre></div>'), code=500)
            return self._send(pdf, "application/pdf",
                              headers={"Content-Disposition": f'attachment; filename="{base}.pdf"'})
        return self._send("bad format", code=400)


def main():
    import sys
    # เลือกพอร์ตว่าง เริ่มจาก PORT แล้วไล่ขึ้นถ้าถูกใช้อยู่
    port = PORT
    srv = None
    for p in range(PORT, PORT + 20):
        try:
            srv = ThreadingHTTPServer((HOST, p), H)
            port = p
            break
        except OSError:
            continue
    if srv is None:
        print("ไม่พบพอร์ตว่างสำหรับเปิดเซิร์ฟเวอร์")
        return
    url = f"http://{HOST}:{port}"
    frozen = getattr(sys, "frozen", False)
    if frozen or os.environ.get("ETDA_OPEN"):
        import webbrowser
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    print("=" * 60)
    print("  WebSec Checklist — ETDA ขมธอ.4-2559 + NCSA 2568")
    print(f"  เปิดใช้งานที่: {url}")
    print(f"  frameworks: {[fw.short for fw in frameworks.all_frameworks()]}")
    print(f"  เครื่องมือเสริมที่พบ: {probe.available_tools()}")
    print("  ปิดโปรแกรม: กด Ctrl+C หรือปิดหน้าต่างนี้")
    print("=" * 60)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
