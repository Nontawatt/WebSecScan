# -*- coding: utf-8 -*-
"""
Registry รวมมาตรฐานหลายชุด (ETDA ขมธอ.4-2559 + NCSA 2568) ให้ interface เดียวกัน
"""
import checklist as _etda
import ncsa as _ncsa
import schemes


class Framework:
    def __init__(self, mod):
        self.mod = mod
        self.id = mod.FRAMEWORK_ID
        self.name = mod.FRAMEWORK_NAME
        self.short = mod.FRAMEWORK_SHORT
        self.std = mod.FRAMEWORK_STD
        self.uses_csf = getattr(mod, "USES_CSF", False)
        self.items = mod.ITEMS
        self.item_by_id = mod.ITEM_BY_ID
        self.groups = mod.GROUPS
        self.cat_info = getattr(mod, "CAT_INFO", {})
        self.csf_order = getattr(mod, "CSF_ORDER", [])
        self.csf_label = getattr(mod, "CSF_LABEL", {})
        self.csf_color = getattr(mod, "CSF_COLOR", {})

    # --- summaries ---
    def compliance(self, state):
        return schemes.compliance(self.items, state)

    def breakdown(self, state):
        return schemes.verdict_breakdown(self.items, state)

    def group_summary(self, state):
        """คืน list ต่อกลุ่ม: {id,name,csf,comp,bd}"""
        out = []
        for gid, gname, csf in self.groups:
            its = [it for it in self.items if it["cat"] == gid]
            out.append({"id": gid, "name": gname, "csf": csf,
                        "comp": schemes.compliance(its, state),
                        "bd": schemes.verdict_breakdown(its, state)})
        return out

    def csf_summary(self, state):
        """คืน list ต่อฟังก์ชัน CSF: {csf,label,color,comp,bd} (เฉพาะ framework ที่ใช้ CSF)"""
        if not self.uses_csf:
            return []
        out = []
        for f in self.csf_order:
            its = [it for it in self.items if it["csf"] == f]
            if not its:
                continue
            out.append({"csf": f, "label": self.csf_label.get(f, f),
                        "color": self.csf_color.get(f, "#2f6fb0"),
                        "comp": schemes.compliance(its, state),
                        "bd": schemes.verdict_breakdown(its, state)})
        return out


_ETDA = Framework(_etda)
_NCSA = Framework(_ncsa)
REGISTRY = {_ETDA.id: _ETDA, _NCSA.id: _NCSA}
ORDER = [_ETDA.id, _NCSA.id]


def get(fw_id):
    return REGISTRY.get(fw_id or "etda", _ETDA)


def all_frameworks():
    return [REGISTRY[i] for i in ORDER]


if __name__ == "__main__":
    for fw in all_frameworks():
        print(fw.id, fw.short, "| items:", len(fw.items), "| csf:", fw.uses_csf)
