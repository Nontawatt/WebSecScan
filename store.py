# -*- coding: utf-8 -*-
"""
JSON file store: projects -> assessments
โครงสร้าง:
  data/
    projects.json                 index ของโปรเจกต์
    assess/<assessment_id>.json   ผลตรวจแต่ละครั้ง (ก.1 + ก.2)
"""
import json
import os
import secrets
import sys
import threading
import time

# เขียนข้อมูลไว้ข้าง ๆ ตัวโปรแกรม: โหมด .exe (frozen) ใช้โฟลเดอร์ของ exe, ปกติใช้โฟลเดอร์โมดูล
if getattr(sys, "frozen", False):
    _APPDIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    _APPDIR = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.join(_APPDIR, "data")
ASSESS = os.path.join(BASE, "assess")
PROJ_FILE = os.path.join(BASE, "projects.json")
_lock = threading.RLock()


def _init():
    os.makedirs(ASSESS, exist_ok=True)
    if not os.path.exists(PROJ_FILE):
        _write(PROJ_FILE, {"projects": []})


def _read(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _write(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def nid(prefix):
    return f"{prefix}_{int(time.time())}_{secrets.token_hex(3)}"


# ------------------- projects ------------------- #
def list_projects():
    with _lock:
        db = _read(PROJ_FILE, {"projects": []})
        return db["projects"]


def get_project(pid):
    for p in list_projects():
        if p["id"] == pid:
            return p
    return None


def add_project(name, owner="", note=""):
    with _lock:
        db = _read(PROJ_FILE, {"projects": []})
        p = {"id": nid("prj"), "name": name.strip() or "โปรเจกต์ใหม่",
             "owner": owner.strip(), "note": note.strip(),
             "created": now(), "assessments": []}
        db["projects"].insert(0, p)
        _write(PROJ_FILE, db)
        return p


def delete_project(pid):
    with _lock:
        db = _read(PROJ_FILE, {"projects": []})
        p = next((x for x in db["projects"] if x["id"] == pid), None)
        if p:
            for aid in p.get("assessments", []):
                try:
                    os.remove(os.path.join(ASSESS, aid + ".json"))
                except OSError:
                    pass
            db["projects"] = [x for x in db["projects"] if x["id"] != pid]
            _write(PROJ_FILE, db)
        return bool(p)


# ------------------- assessments ------------------- #
def add_assessment(pid, target, depth, signals, items_state, toollog, tools_used, framework="etda"):
    with _lock:
        db = _read(PROJ_FILE, {"projects": []})
        p = next((x for x in db["projects"] if x["id"] == pid), None)
        if not p:
            return None
        aid = nid("asm")
        rec = {
            "id": aid, "project_id": pid, "target": target, "depth": depth,
            "framework": framework,
            "created": now(), "signals": signals, "items": items_state,
            "toollog": toollog, "tools_used": tools_used,
            "remediation": [],   # ค.2 / ก.2
            "site_label": target, "audited_by": p.get("owner", ""),
        }
        _write(os.path.join(ASSESS, aid + ".json"), rec)
        p["assessments"].insert(0, aid)
        _write(PROJ_FILE, db)
        return rec


def get_assessment(aid):
    return _read(os.path.join(ASSESS, aid + ".json"))


def save_assessment(rec):
    with _lock:
        _write(os.path.join(ASSESS, rec["id"] + ".json"), rec)


def update_item(aid, item_id, verdict=None, note=None):
    with _lock:
        rec = get_assessment(aid)
        if not rec:
            return False
        it = rec["items"].setdefault(item_id, {"verdict": "unset", "auto": False, "note": "", "evidence": ""})
        if verdict is not None:
            it["verdict"] = verdict
            it["auto"] = False  # ผู้ใช้แก้เอง
        if note is not None:
            it["note"] = note
        save_assessment(rec)
        return True


def set_remediation(aid, rows):
    with _lock:
        rec = get_assessment(aid)
        if not rec:
            return False
        rec["remediation"] = rows
        save_assessment(rec)
        return True


def set_meta(aid, site_label=None, audited_by=None):
    with _lock:
        rec = get_assessment(aid)
        if not rec:
            return False
        if site_label is not None:
            rec["site_label"] = site_label
        if audited_by is not None:
            rec["audited_by"] = audited_by
        save_assessment(rec)
        return True


def delete_assessment(aid):
    with _lock:
        db = _read(PROJ_FILE, {"projects": []})
        for p in db["projects"]:
            if aid in p.get("assessments", []):
                p["assessments"].remove(aid)
        _write(PROJ_FILE, db)
        try:
            os.remove(os.path.join(ASSESS, aid + ".json"))
        except OSError:
            pass
        return True


_init()
