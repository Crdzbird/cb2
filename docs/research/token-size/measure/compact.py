import json, glob, struct, uuid, datetime, statistics, sys

def head(major, n):
    if n < 24: return bytes([major << 5 | n])
    if n < 256: return bytes([major << 5 | 24, n])
    if n < 65536: return bytes([major << 5 | 25]) + struct.pack(">H", n)
    return bytes([major << 5 | 26]) + struct.pack(">I", n)

def enc(v):
    if isinstance(v, bool): return b"\xf5" if v else b"\xf4"
    if isinstance(v, int): return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes): return head(2, len(v)) + v
    if isinstance(v, str): b = v.encode(); return head(3, len(b)) + b
    if isinstance(v, dict): return head(5, len(v)) + b"".join(enc(k) + enc(x) for k, x in v.items())
    raise TypeError(v)

CWT = {"iss": 1, "sub": 2, "aud": 3, "exp": 4, "nbf": 5, "iat": 6, "jti": 7}
def epoch(s): return int(datetime.datetime.fromisoformat(s).timestamp())

def cwt(c):
    o = {}
    for k, v in c.items():
        if k in ("exp", "iat", "nbf"): v = epoch(v)
        o[CWT.get(k, k)] = v
    return enc(o)

def cwt_tight(c, iss_table={"https://auth.example.com": 0}, aud_table={"api": 0, "billing": 1, "admin-console": 2, "mobile": 3}):
    o = {}
    for k, v in c.items():
        if k in ("exp", "iat", "nbf"): v = epoch(v)
        if k == "jti":
            try: v = uuid.UUID(v).bytes
            except ValueError: pass
        if k == "iss" and v in iss_table: v = iss_table[v]
        if k == "aud" and v in aud_table: v = aud_table[v]
        o[CWT.get(k, k)] = v
    if 4 in o and 6 in o: o[4] = o[4] - o[6]
    return enc(o)

files = sorted(glob.glob("test/*.json"))
rows = {"json": [], "cbor_cwt_keys": [], "cbor_tight": []}
for f in files:
    raw = open(f, "rb").read()
    c = json.loads(raw)
    rows["json"].append(len(raw))
    b = cwt(c); rows["cbor_cwt_keys"].append(len(b)); open(f.replace(".json", ".cwt"), "wb").write(b)
    t = cwt_tight(c); rows["cbor_tight"].append(len(t)); open(f.replace(".json", ".tight"), "wb").write(t)
for k, v in rows.items():
    print(f"{k:15} mean {statistics.mean(v):6.1f}  min {min(v)}  max {max(v)}")
