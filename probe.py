# -*- coding: utf-8 -*-
"""
Auto-probe engine สำหรับ ETDA ขมธอ.4-2559 WAS scanner.

รวม 2 ระดับ:
  1) passive  — ยิง HTTP ด้วย urllib วิเคราะห์ header/cookie/TLS/charset/CSP/CSRF/session
  2) active   — ทดสอบแบบไม่รุกราน: reflected XSS, path traversal, CRLF, SQL error
  3) tools    — เรียกเครื่องมือจริงถ้ามีในเครื่อง: sqlmap, nmap, nikto, wapiti (degrade gracefully)

ผลลัพธ์ต่อ 'signal' = {status: pass|fail|warn|cannot|info, detail: str, evidence: str}
signal เหล่านี้ถูก map เข้ากับ checklist.item.auto ใน engine.map_to_items()
"""
import json
import math
import os
import re
import shutil
import socket
import ssl
import subprocess
import time
import urllib.parse
import urllib.request
from collections import Counter
from http.cookiejar import CookieJar

UA = "ETDA-WAS-Scanner/1.0 (ETDA-4-2559)"
TIMEOUT = 12


# --------------------------------------------------------------------------- #
# HTTP helper
# --------------------------------------------------------------------------- #
class Resp:
    def __init__(self, url, status, headers, body, set_cookies, elapsed, final_url):
        self.url = url
        self.status = status
        self.headers = headers            # dict lowercase
        self.body = body                  # str (best-effort)
        self.set_cookies = set_cookies    # list of raw Set-Cookie strings
        self.elapsed = elapsed
        self.final_url = final_url


def http_get(url, extra_headers=None, method="GET", data=None, timeout=TIMEOUT, redirect=True):
    hdr = {"User-Agent": UA, "Accept": "*/*"}
    if extra_headers:
        hdr.update(extra_headers)
    req = urllib.request.Request(url, data=data, headers=hdr, method=method)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if not redirect:
        handlers.append(NoRedirect)
    opener = urllib.request.build_opener(*handlers)
    t0 = time.time()
    set_cookies = []
    try:
        r = opener.open(req, timeout=timeout)
        raw = r.read(600000)
        status = r.status
        headers = {k.lower(): v for k, v in r.headers.items()}
        set_cookies = r.headers.get_all("Set-Cookie") or []
        final_url = r.geturl()
    except urllib.error.HTTPError as e:
        raw = e.read(600000) if hasattr(e, "read") else b""
        status = e.code
        headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        set_cookies = (e.headers.get_all("Set-Cookie") if e.headers else []) or []
        final_url = url
    body = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
    return Resp(url, status, headers, body, set_cookies, time.time() - t0, final_url)


def shannon_entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# --------------------------------------------------------------------------- #
# Passive checks
# --------------------------------------------------------------------------- #
def parse_cookies(set_cookie_list):
    out = []
    for raw in set_cookie_list:
        parts = [p.strip() for p in raw.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name, _, val = parts[0].partition("=")
        attrs = {p.split("=")[0].lower(): (p.split("=", 1)[1] if "=" in p else True) for p in parts[1:]}
        out.append(dict(name=name.strip(), value=val.strip(), attrs=attrs, raw=raw))
    return out


SESSION_NAMES = ("sess", "sid", "phpsessid", "jsessionid", "asp.net_sessionid",
                 "aspsessionid", "connect.sid", "session", "csrftoken", "auth", "token")


def is_session_cookie(name):
    n = name.lower()
    return any(s in n for s in SESSION_NAMES)


def probe_passive(base_url):
    """คืน dict ของ signals จากการดู header/cookie/tls"""
    sig = {}
    is_https = base_url.lower().startswith("https")
    try:
        r = http_get(base_url, redirect=True)
    except Exception as e:
        return {"_error": {"status": "cannot", "detail": f"เชื่อมต่อไม่ได้: {e}", "evidence": ""}}

    cookies = parse_cookies(r.set_cookies)
    sess_cookies = [c for c in cookies if is_session_cookie(c["name"])] or cookies

    # header_disclosure (4.7-P1) — Server / X-Powered-By เปิดเผยเวอร์ชัน
    disclose = []
    for h in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        if h in r.headers and re.search(r"\d", r.headers[h] or ""):
            disclose.append(f"{h}: {r.headers[h]}")
    sig["header_disclosure"] = {
        "status": "fail" if disclose else "pass",
        "detail": "พบ header เปิดเผยซอฟต์แวร์/เวอร์ชัน" if disclose else "ไม่พบการเปิดเผยเวอร์ชันใน header",
        "evidence": "; ".join(disclose),
    }

    # cookie_secure (4.4-P3)
    if not is_https:
        sig["cookie_secure"] = {"status": "na", "detail": "เว็บไม่ได้ใช้ HTTPS จึงประเมิน Secure flag ไม่ได้", "evidence": ""}
    elif not sess_cookies:
        sig["cookie_secure"] = {"status": "cannot", "detail": "ไม่พบ cookie ให้ตรวจ", "evidence": ""}
    else:
        bad = [c["name"] for c in sess_cookies if "secure" not in c["attrs"]]
        sig["cookie_secure"] = {
            "status": "fail" if bad else "pass",
            "detail": ("cookie ไม่มี Secure: " + ", ".join(bad)) if bad else "cookie มี Secure ครบ",
            "evidence": "; ".join(c["raw"] for c in sess_cookies),
        }

    # cookie_httponly (4.5-M1)
    if not sess_cookies:
        sig["cookie_httponly"] = {"status": "cannot", "detail": "ไม่พบ cookie ให้ตรวจ", "evidence": ""}
    else:
        bad = [c["name"] for c in sess_cookies if "httponly" not in c["attrs"]]
        sig["cookie_httponly"] = {
            "status": "fail" if bad else "pass",
            "detail": ("cookie ไม่มี HttpOnly: " + ", ".join(bad)) if bad else "cookie มี HttpOnly ครบ",
            "evidence": "; ".join(c["raw"] for c in sess_cookies),
        }

    # cookie_expiry (4.4-M2) — มี Expires/Max-Age
    if not sess_cookies:
        sig["cookie_expiry"] = {"status": "cannot", "detail": "ไม่พบ cookie ให้ตรวจ", "evidence": ""}
    else:
        noexp = [c["name"] for c in sess_cookies if "expires" not in c["attrs"] and "max-age" not in c["attrs"]]
        sig["cookie_expiry"] = {
            "status": "warn" if noexp else "pass",
            "detail": ("cookie เป็น session cookie ไม่กำหนดวันหมดอายุ: " + ", ".join(noexp)) if noexp
                      else "cookie กำหนดวันหมดอายุ (Expires/Max-Age)",
            "evidence": "; ".join(c["raw"] for c in sess_cookies),
        }

    # session_entropy (4.4-P1/M1/T1)
    vals = [c["value"] for c in sess_cookies if len(c["value"]) >= 8]
    if vals:
        best = max(vals, key=len)
        ent = shannon_entropy(best)
        bits = ent * len(best)
        ok = bits >= 64 and len(best) >= 16
        sig["session_entropy"] = {
            "status": "pass" if ok else "warn",
            "detail": f"Session/Cookie value ยาว {len(best)} ตัวอักษร, entropy ~{bits:.0f} bit "
                      + ("(เดายาก)" if ok else "(อาจคาดเดาได้ง่าย ควรตรวจสอบ)"),
            "evidence": (best[:40] + "…") if len(best) > 40 else best,
        }
    else:
        sig["session_entropy"] = {"status": "cannot", "detail": "ไม่พบ session cookie ที่ยาวพอจะประเมิน entropy", "evidence": ""}

    # session_in_url (4.4-P2) — พบ sid/sessionid ใน query/redirect
    combined = (r.final_url + " " + r.body[:5000]).lower()
    m = re.search(r"[?&](jsessionid|phpsessid|sid|sessionid|session_id)=", combined)
    sig["session_in_url"] = {
        "status": "fail" if m else "pass",
        "detail": "พบ Session ID ถูกส่งผ่าน URL parameter" if m else "ไม่พบ Session ID ใน URL",
        "evidence": m.group(0) if m else "",
    }

    # charset_declared (4.5-P5)
    ct = r.headers.get("content-type", "")
    has_charset = "charset=" in ct.lower()
    meta_charset = bool(re.search(r'<meta[^>]+charset', r.body[:3000], re.I))
    sig["charset_declared"] = {
        "status": "pass" if has_charset else ("warn" if meta_charset else "fail"),
        "detail": (f"Content-Type ระบุ charset ({ct})" if has_charset
                   else ("ไม่มี charset ใน header แต่พบใน <meta>" if meta_charset
                         else "ไม่พบการประกาศ charset")),
        "evidence": ct,
    }

    # csp_present (4.5-P4)
    csp = r.headers.get("content-security-policy", "")
    sig["csp_present"] = {
        "status": "pass" if csp else "warn",
        "detail": "มี Content-Security-Policy header" if csp else "ไม่มี CSP (ควบคุมแหล่ง stylesheet/script ไม่ได้จาก header)",
        "evidence": csp[:200],
    }

    # csrf_token (4.6-P3/T1) — มองหา hidden token ในฟอร์ม + SameSite
    forms = re.findall(r"<form\b.*?</form>", r.body, re.I | re.S)
    token_pat = re.compile(r'name=["\']?(csrf|_token|authenticity_token|__requestverificationtoken|xsrf)[^"\'>]*', re.I)
    has_token = any(token_pat.search(f) for f in forms)
    samesite = any("samesite" in c["attrs"] for c in sess_cookies)
    if not forms:
        sig["csrf_token"] = {"status": "cannot", "detail": "ไม่พบ <form> ในหน้าแรก จึงประเมิน CSRF token อัตโนมัติไม่ได้", "evidence": ""}
    else:
        ok = has_token or samesite
        sig["csrf_token"] = {
            "status": "pass" if ok else "warn",
            "detail": (("พบ anti-CSRF token ในฟอร์ม" if has_token else "") +
                       (" + cookie ตั้ง SameSite" if samesite else "")) or
                      f"พบ {len(forms)} ฟอร์มแต่ไม่พบ anti-CSRF token/SameSite",
            "evidence": f"forms={len(forms)}, token={has_token}, samesite={samesite}",
        }

    # auth_surface (4.9-P1) — มีหน้า login / WWW-Authenticate
    login_hint = bool(re.search(r'type=["\']?password', r.body, re.I)) or "www-authenticate" in r.headers
    sig["auth_surface"] = {
        "status": "info",
        "detail": ("พบส่วนยืนยันตัวตน (login form / WWW-Authenticate) — ตรวจสอบการควบคุมสิทธิ์ต่อ"
                   if login_hint else "ไม่พบ login form บนหน้าแรก (อาจอยู่ path อื่น)"),
        "evidence": "",
    }

    sig["_meta"] = {"status": "info", "detail": f"HTTP {r.status}, {len(r.body)} bytes, {r.elapsed*1000:.0f} ms",
                    "evidence": r.final_url, "https": is_https}
    return sig


# --------------------------------------------------------------------------- #
# Active (non-destructive) checks
# --------------------------------------------------------------------------- #
def _param_urls(base_url):
    """สร้าง URL ทดสอบจาก query params ที่มีอยู่ ถ้าไม่มีให้ลอง ?q= / ?file= / ?id="""
    p = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qsl(p.query)
    if not qs:
        qs = [("q", "1"), ("id", "1"), ("file", "index")]
    return p, qs


def _rebuild(p, qs):
    return urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(qs)))


def probe_xss(base_url):
    marker = "etdaXSS9137"
    payload = f"<{marker}>\"'"
    p, qs = _param_urls(base_url)
    hits = []
    for i, (k, _) in enumerate(qs):
        test = list(qs)
        test[i] = (k, payload)
        u = _rebuild(p, test)
        try:
            r = http_get(u)
        except Exception:
            continue
        if f"<{marker}>" in r.body:
            hits.append(f"param '{k}' สะท้อน payload กลับมาโดยไม่ encode")
    return {"status": "fail" if hits else "pass",
            "detail": ("พบ reflected XSS: " + "; ".join(hits)) if hits
                      else "ไม่พบการสะท้อน payload แบบไม่ encode (จาก param ที่ทดสอบ)",
            "evidence": "; ".join(hits)}


def probe_traversal(base_url):
    payloads = ["../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd", "....//....//etc/passwd"]
    p, qs = _param_urls(base_url)
    file_params = [i for i, (k, _) in enumerate(qs) if k.lower() in ("file", "path", "page", "doc", "template", "id")]
    if not file_params:
        file_params = list(range(len(qs)))
    hits = []
    for i in file_params:
        for pl in payloads:
            test = list(qs)
            test[i] = (test[i][0], pl)
            u = _rebuild(p, test)
            try:
                r = http_get(u)
            except Exception:
                continue
            if re.search(r"root:.*:0:0:", r.body):
                hits.append(f"param '{test[i][0]}' อ่าน /etc/passwd ได้")
                break
    return {"status": "fail" if hits else "pass",
            "detail": ("พบ Directory Traversal: " + "; ".join(hits)) if hits
                      else "ไม่พบการอ่านไฟล์ระบบผ่าน path traversal (จาก param ที่ทดสอบ)",
            "evidence": "; ".join(hits)}


def probe_crlf(base_url):
    p, qs = _param_urls(base_url)
    inj = "%0d%0aX-Etda-Crlf%3a-injected"
    hits = []
    for i, (k, _) in enumerate(qs):
        test = list(qs)
        test[i] = (k, "1" + inj)
        u = _rebuild(p, test)
        try:
            r = http_get(u, redirect=False)
        except Exception:
            continue
        if "x-etda-crlf" in {h.lower() for h in r.headers}:
            hits.append(f"param '{k}' แทรก header ผ่าน CRLF ได้")
    return {"status": "fail" if hits else "pass",
            "detail": ("พบ HTTP Header/CRLF Injection: " + "; ".join(hits)) if hits
                      else "ไม่พบการแทรก header ผ่าน CRLF (จาก param ที่ทดสอบ)",
            "evidence": "; ".join(hits)}


SQL_ERRORS = [
    r"you have an error in your sql syntax", r"warning: mysql", r"unclosed quotation mark",
    r"quoted string not properly terminated", r"pg_query\(\)", r"sqlstate\[", r"ora-\d{5}",
    r"microsoft ole db provider", r"odbc.*driver", r"sqlite3?::", r"psql: error",
]


def probe_sql_error(base_url):
    p, qs = _param_urls(base_url)
    hits = []
    for i, (k, _) in enumerate(qs):
        test = list(qs)
        test[i] = (k, test[i][1] + "'\"")
        u = _rebuild(p, test)
        try:
            r = http_get(u)
        except Exception:
            continue
        low = r.body.lower()
        for pat in SQL_ERRORS:
            if re.search(pat, low):
                hits.append(f"param '{k}' ทำให้เกิด SQL error message รั่ว ({pat})")
                break
    return {"status": "fail" if hits else "pass",
            "detail": ("พบ SQL error message รั่ว (บ่งชี้ช่องโหว่ + ไม่ควบคุม error): " + "; ".join(hits)) if hits
                      else "ไม่พบ SQL error message รั่วจากการใส่ single/double quote",
            "evidence": "; ".join(hits)}


def probe_tls(base_url):
    """ตรวจ TLS/HTTPS พื้นฐาน: ใช้ HTTPS ได้ไหม, เวอร์ชัน, HSTS (ใช้ประกอบข้อ NCSA Cipher/TLS)"""
    p = urllib.parse.urlparse(base_url)
    if p.scheme != "https":
        host = p.hostname
        # ลองต่อ https ตรง ๆ
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    ver = ss.version()
            return {"status": "warn",
                    "detail": f"หน้าที่ตรวจเป็น HTTP แต่พอร์ต 443 รองรับ {ver} — ควรบังคับใช้ HTTPS",
                    "evidence": ver}
        except Exception:
            return {"status": "fail", "detail": "ไม่พบการให้บริการผ่าน HTTPS (TLS)", "evidence": ""}
    host = p.hostname
    port = p.port or 443
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                ver = ss.version()
                cipher = ss.cipher()
    except Exception as e:
        return {"status": "cannot", "detail": f"เชื่อมต่อ TLS ไม่ได้: {e}", "evidence": ""}
    weak = ver in ("TLSv1", "TLSv1.1", "SSLv3")
    try:
        r = http_get(base_url)
        hsts = "strict-transport-security" in r.headers
    except Exception:
        hsts = False
    detail = f"ใช้ {ver}, cipher {cipher[0] if cipher else '?'}" + (", มี HSTS" if hsts else ", ไม่มี HSTS")
    status = "fail" if weak else ("warn" if not hsts else "pass")
    return {"status": status, "detail": detail, "evidence": f"{ver} / {cipher}"}


def probe_mail_form(base_url):
    try:
        r = http_get(base_url)
    except Exception:
        return {"status": "cannot", "detail": "เชื่อมต่อไม่ได้", "evidence": ""}
    forms = re.findall(r"<form\b.*?</form>", r.body, re.I | re.S)
    mail_forms = [f for f in forms if re.search(r'type=["\']?email|name=["\']?(email|mail|to|subject|from)', f, re.I)]
    if mail_forms:
        return {"status": "warn",
                "detail": f"พบ {len(mail_forms)} ฟอร์มที่อาจส่งอีเมล — ต้องทดสอบ Mail Header Injection ด้วยมือ (แทรก CR/LF ในช่อง to/subject)",
                "evidence": ""}
    return {"status": "cannot", "detail": "ไม่พบฟอร์มส่งอีเมลบนหน้าแรก — ต้องระบุ endpoint เอง", "evidence": ""}


# --------------------------------------------------------------------------- #
# External tools (degrade gracefully)
# --------------------------------------------------------------------------- #
def tool_path(name, env=None):
    if env and os.environ.get(env):
        return os.environ[env]
    return shutil.which(name)


def run_cmd(argv, timeout=180):
    try:
        pr = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return pr.returncode, (pr.stdout or "") + (pr.stderr or "")
    except subprocess.TimeoutExpired as e:
        return 124, f"timeout after {timeout}s\n" + (e.stdout or "")
    except Exception as e:
        return 1, f"error: {e}"


def tool_sqlmap(base_url, log):
    b = tool_path("sqlmap", "SQLMAP_BIN")
    if not b:
        return {"status": "cannot", "detail": "ไม่พบ sqlmap ในเครื่อง", "evidence": ""}
    p = urllib.parse.urlparse(base_url)
    if not p.query:
        base_url = _rebuild(*_param_urls(base_url))
    argv = [b, "-u", base_url, "--batch", "--level", "1", "--risk", "1",
            "--crawl", "0", "--technique", "BEUST", "--timeout", "10", "--retries", "1",
            "--flush-session", "--disable-coloring", "--random-agent"]
    log(f"$ sqlmap -u {base_url} --batch --level 1 --risk 1")
    rc, out = run_cmd(argv, timeout=240)
    vuln = "is vulnerable" in out.lower() or "sqlmap identified the following injection point" in out.lower()
    tail = "\n".join(out.strip().splitlines()[-25:])
    return {"status": "fail" if vuln else "pass",
            "detail": "sqlmap พบจุด SQL injection" if vuln else "sqlmap ไม่พบจุด SQL injection (level1/risk1)",
            "evidence": tail}


def tool_nmap_auth(base_url, log):
    b = tool_path("nmap", "NMAP_BIN")
    if not b:
        return {"status": "cannot", "detail": "ไม่พบ nmap ในเครื่อง", "evidence": ""}
    p = urllib.parse.urlparse(base_url)
    host = p.hostname
    port = str(p.port or (443 if p.scheme == "https" else 80))
    argv = [b, "-Pn", "-p", port, "--script",
            "http-auth,http-default-accounts,http-security-headers", "-oN", "-", host]
    log(f"$ nmap -p {port} --script http-auth,http-default-accounts,http-security-headers {host}")
    rc, out = run_cmd(argv, timeout=180)
    low = out.lower()
    hit = "default" in low and ("valid credentials" in low or "possible" in low)
    tail = "\n".join(out.strip().splitlines()[-30:])
    return {"status": "fail" if hit else "info",
            "detail": "nmap พบ default account ที่อาจใช้ได้" if hit else "nmap รันสคริปต์ auth เสร็จ (ดูหลักฐานประกอบ)",
            "evidence": tail}


def tool_nikto(base_url, log):
    b = tool_path("nikto", "NIKTO_BIN")
    if not b:
        return {"status": "cannot", "detail": "ไม่พบ nikto ในเครื่อง", "evidence": ""}
    argv = [b, "-h", base_url, "-maxtime", "90s", "-Tuning", "1234567", "-nointeractive", "-ask", "no"]
    log(f"$ nikto -h {base_url} -maxtime 90s")
    rc, out = run_cmd(argv, timeout=150)
    n = len(re.findall(r"^\+ ", out, re.M))
    tail = "\n".join([l for l in out.splitlines() if l.startswith("+ ")][:40])
    return {"status": "info", "detail": f"nikto พบ {n} รายการที่น่าสนใจ", "evidence": tail}


def tool_wapiti(base_url, modules, log):
    b = tool_path("wapiti", "WAPITI_BIN")
    if not b:
        return {"status": "cannot", "detail": "ไม่พบ wapiti ในเครื่อง", "evidence": ""}
    out = f"/tmp/wapiti-{int(time.time())}.json"
    argv = [b, "-u", base_url, "-m", modules, "--scope", "page", "--flush-session",
            "--max-scan-time", "60", "-f", "json", "-o", out, "--no-bugreport", "-v", "0"]
    log(f"$ wapiti -u {base_url} -m {modules} --max-scan-time 60")
    rc, txt = run_cmd(argv, timeout=120)
    vulns = 0
    detail = "wapiti รันเสร็จ"
    try:
        with open(out) as f:
            data = json.load(f)
        for k, v in (data.get("vulnerabilities") or {}).items():
            vulns += len(v)
        os.remove(out)
    except Exception:
        pass
    return {"status": "fail" if vulns else "info",
            "detail": f"wapiti พบช่องโหว่ {vulns} รายการ (module: {modules})" if vulns else detail,
            "evidence": ""}


def available_tools():
    return {n: bool(tool_path(n, e)) for n, e in
            (("sqlmap", "SQLMAP_BIN"), ("nmap", "NMAP_BIN"),
             ("nikto", "NIKTO_BIN"), ("wapiti", "WAPITI_BIN"))}
