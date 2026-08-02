# -*- coding: utf-8 -*-
"""
Verdict schemes ที่ใช้ร่วมกันข้ามมาตรฐาน (ETDA / NCSA)
weight = None  -> ไม่นับใน compliance denominator (na / unset)
"""

SCHEMES = {
    # ETDA prevent/mitigate — 2 ระดับ (ยอมรับได้ / ยังต้องปรับปรุง)
    "ctrl": {
        "verdicts": ["ok", "fix", "na", "unset"],
        "weight": {"ok": 1.0, "fix": 0.0, "na": None, "unset": None},
        "labels": {"ok": "ยอมรับได้", "fix": "ยังต้องปรับปรุง", "na": "ไม่เกี่ยวข้อง", "unset": "ประเมินโดยผู้ตรวจ"},
    },
    # ETDA test — ผ่าน / ไม่ผ่าน / ทดสอบเองไม่ได้
    "test": {
        "verdicts": ["pass", "fail", "cannot", "unset"],
        "weight": {"pass": 1.0, "fail": 0.0, "cannot": None, "unset": None},
        "labels": {"pass": "ทดสอบผ่าน", "fail": "ทดสอบไม่ผ่าน", "cannot": "ยังทดสอบเองไม่ได้", "unset": "ประเมินโดยผู้ตรวจ"},
    },
    # NCSA ข้อกำหนดหลัก — 2 ระดับ (ดำเนินการแล้ว / ยังต้องปรับปรุง)
    "comply": {
        "verdicts": ["done", "fix", "na", "unset"],
        "weight": {"done": 1.0, "fix": 0.0, "na": None, "unset": None},
        "labels": {"done": "ดำเนินการแล้ว", "fix": "ยังต้องปรับปรุง", "na": "ไม่เกี่ยวข้อง", "unset": "ประเมินโดยผู้ตรวจ"},
    },
    # NCSA ข้อย่อย — 3 ระดับ maturity
    "mat3": {
        "verdicts": ["done", "inprog", "notdone", "na", "unset"],
        "weight": {"done": 1.0, "inprog": 0.5, "notdone": 0.0, "na": None, "unset": None},
        "labels": {"done": "ดำเนินการแล้ว", "inprog": "อยู่ระหว่างดำเนินการ",
                   "notdone": "ยังไม่ได้ดำเนินการ", "na": "ไม่เกี่ยวข้อง", "unset": "ประเมินโดยผู้ตรวจ"},
    },
}

# verdict -> css pill class (ใช้ใน UI)
PILL = {
    "ok": "ok", "done": "ok", "pass": "ok",
    "fix": "fix", "fail": "fix", "notdone": "fix",
    "inprog": "warn", "cannot": "cannot",
    "na": "na", "unset": "unset",
}

# verdict -> RGB fill (ใช้ใน PDF)
FILL = {
    "ok": (223, 246, 224), "done": (223, 246, 224), "pass": (223, 246, 224),
    "fix": (250, 224, 224), "fail": (250, 224, 224), "notdone": (250, 224, 224),
    "inprog": (255, 244, 214), "cannot": (255, 244, 214),
    "na": (238, 238, 238), "unset": (245, 245, 245),
}


def label(scheme, verdict):
    return SCHEMES.get(scheme, {}).get("labels", {}).get(verdict, verdict)


def verdicts(scheme):
    return SCHEMES.get(scheme, SCHEMES["comply"])["verdicts"]


def weight(scheme, verdict):
    return SCHEMES.get(scheme, {}).get("weight", {}).get(verdict)


def compliance(items, state):
    """
    คืน dict: pct (0-100 หรือ None), applicable, achieved(float), assessed, total, na, unset
    pct = คะแนนที่ได้ / จำนวนข้อที่ประเมินและเกี่ยวข้อง
    """
    achieved = 0.0
    applicable = 0
    assessed = 0
    na = 0
    unset = 0
    for it in items:
        v = state.get(it["id"], {}).get("verdict", "unset")
        w = weight(it["scheme"], v)
        if v == "unset":
            unset += 1
            continue
        assessed += 1
        if v == "na":
            na += 1
            continue
        if w is None:
            continue
        applicable += 1
        achieved += w
    pct = round(achieved / applicable * 100) if applicable else None
    return {"pct": pct, "applicable": applicable, "achieved": achieved,
            "assessed": assessed, "total": len(items), "na": na, "unset": unset}


def verdict_breakdown(items, state):
    """นับจำนวนแต่ละกลุ่มผลเพื่อทำ bar/donut: good/partial/bad/na/unset"""
    n = {"good": 0, "partial": 0, "bad": 0, "na": 0, "unset": 0}
    for it in items:
        v = state.get(it["id"], {}).get("verdict", "unset")
        if v in ("ok", "done", "pass"):
            n["good"] += 1
        elif v == "inprog":
            n["partial"] += 1
        elif v in ("fix", "fail", "notdone"):
            n["bad"] += 1
        elif v == "na":
            n["na"] += 1
        else:
            n["unset"] += 1
    return n
