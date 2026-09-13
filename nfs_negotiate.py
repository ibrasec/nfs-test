#!/usr/bin/env python3
"""
NFSv4 export-isolation / tenant-validation prober.

Hand-crafts RPC/NFSv4 COMPOUND requests directly on port 2049 (no rpcbind,
no mount protocol) to walk an arbitrary export path and read it, while
asserting a chosen AUTH_SYS identity (uid/gid/aux-gids) from a chosen local
address. Every step logs the exact NFS4 status returned so you can tell
whether a TrueNAS share is gating access by:

  - source IP / "Authorized Networks" (export-level ACL)          -> test with --bind-ip
  - maproot/mapall UID remap + dataset mode/ACL (identity-level)   -> test with --uid/--gid/--try-uids
  - security flavor (sec=sys/none/krb5) required for the export   -> checked automatically, see below

IMPORTANT: source IP cannot be spoofed here — TCP requires a real 3-way
handshake, so the only honest way to test the IP gate is to actually
originate the connection from a permitted vs. non-permitted interface
(--bind-ip), not to lie about it in a packet.

By default (no flag needed) every run first calls SECINFO on the target
path to get the server's own declared list of acceptable security flavors,
then actually attempts the walk+read/readdir under each flavor it can
genuinely speak:
  - sec=none  -> attempted for real if declared acceptable
  - sec=sys   -> attempted for real (with --uid/--gid/--gids) if declared acceptable
  - sec=krb5* -> reported as declared acceptable but NOT attempted — completing
                 RPCSEC_GSS requires a live Kerberos context (a real ticket via
                 kinit + the NFS service's SPN), which a hand-built raw-socket
                 client cannot fake. Ask for python-gssapi based krb5 support
                 to be added if you have a working ticket for the target realm.

Only use against systems you are authorized to test.
"""
import argparse
import random
import socket
import struct
import sys

# ---------------------------------------------------------------- constants

PROG_NFS = 100003
VERS_NFS4 = 4
PROC_COMPOUND = 1

AUTH_NONE = 0
AUTH_SYS = 1

OP_ACCESS = 3
OP_GETATTR = 9
OP_GETFH = 10
OP_LOOKUP = 15
OP_PUTROOTFH = 24
OP_READ = 25
OP_READDIR = 26
OP_SECINFO = 33

OP_NAMES = {
    OP_ACCESS: "ACCESS", OP_GETATTR: "GETATTR", OP_GETFH: "GETFH",
    OP_LOOKUP: "LOOKUP", OP_PUTROOTFH: "PUTROOTFH", OP_READ: "READ",
    OP_READDIR: "READDIR", OP_SECINFO: "SECINFO",
}

RPCSEC_GSS = 6
SEC_FLAVOR_NAMES = {AUTH_NONE: "AUTH_NONE", AUTH_SYS: "AUTH_SYS", RPCSEC_GSS: "RPCSEC_GSS"}
GSS_SERVICE_NAMES = {1: "krb5", 2: "krb5i", 3: "krb5p"}


def describe_flavor(entry):
    if entry["flavor"] == RPCSEC_GSS:
        return "RPCSEC_GSS/%s" % GSS_SERVICE_NAMES.get(entry["service"], "service=%d" % entry["service"])
    return SEC_FLAVOR_NAMES.get(entry["flavor"], "flavor=%d" % entry["flavor"])

ACCESS4_READ = 0x01
ACCESS4_LOOKUP = 0x02
ACCESS4_MODIFY = 0x04
ACCESS4_EXTEND = 0x08
ACCESS4_DELETE = 0x10
ACCESS4_EXECUTE = 0x20
ACCESS4_ALL = 0x3F

FATTR4_TYPE = 1
FATTR4_SIZE = 4
NF4_TYPE_NAME = {1: "NF4REG (file)", 2: "NF4DIR (directory)", 5: "NF4LNK (symlink)"}

NFS4_STATUS = {
    0: "NFS4_OK", 1: "NFS4ERR_PERM", 2: "NFS4ERR_NOENT", 5: "NFS4ERR_IO",
    6: "NFS4ERR_NXIO", 13: "NFS4ERR_ACCESS", 17: "NFS4ERR_EXIST",
    18: "NFS4ERR_XDEV", 20: "NFS4ERR_NOTDIR", 21: "NFS4ERR_ISDIR",
    22: "NFS4ERR_INVAL", 27: "NFS4ERR_FBIG", 28: "NFS4ERR_NOSPC",
    30: "NFS4ERR_ROFS", 31: "NFS4ERR_MLINK", 63: "NFS4ERR_NAMETOOLONG",
    66: "NFS4ERR_NOTEMPTY", 69: "NFS4ERR_DQUOT", 70: "NFS4ERR_STALE",
    10001: "NFS4ERR_BADHANDLE", 10003: "NFS4ERR_BAD_COOKIE",
    10004: "NFS4ERR_NOTSUPP", 10005: "NFS4ERR_TOOSMALL",
    10006: "NFS4ERR_SERVERFAULT", 10007: "NFS4ERR_BADTYPE",
    10008: "NFS4ERR_DELAY", 10010: "NFS4ERR_DENIED", 10011: "NFS4ERR_EXPIRED",
    10012: "NFS4ERR_LOCKED", 10013: "NFS4ERR_GRACE",
    10014: "NFS4ERR_FHEXPIRED", 10015: "NFS4ERR_SHARE_DENIED",
    10016: "NFS4ERR_WRONGSEC", 10018: "NFS4ERR_RESOURCE",
    10019: "NFS4ERR_MOVED", 10020: "NFS4ERR_NOFILEHANDLE",
    10023: "NFS4ERR_STALE_STATEID", 10025: "NFS4ERR_BAD_STATEID",
    10032: "NFS4ERR_ATTRNOTSUPP", 10036: "NFS4ERR_BADXDR",
    10038: "NFS4ERR_OPENMODE",
}

# Interpretation hints keyed by status code — printed once, right under the
# failing op, so the log reads like a running commentary on the negotiation.
HINTS = {
    13: "access denied by file mode / ACL (or maproot/mapall) for this UID/GID -> identity-based gate",
    1: "operation restricted to owner -> identity-based gate",
    2: "no such entry -> either a real path miss, or the export subtree isn't visible to this client at all",
    10016: "server wants a different security flavor (e.g. krb5) than AUTH_SYS -> auth-flavor gate, not IP/UID",
    10038: "needs a real OPEN state before READ; anonymous stateid isn't accepted here",
    10025: "stateid rejected; server requires a proper OPEN/SETCLIENTID sequence for READ",
}


def status_name(code):
    return NFS4_STATUS.get(code, "UNKNOWN(%d)" % code)


# ---------------------------------------------------------------- XDR codec

def pad4(b):
    n = len(b) % 4
    return b + b"\x00" * ((4 - n) % 4)


def xdr_opaque(b):
    if isinstance(b, str):
        b = b.encode()
    return struct.pack(">I", len(b)) + pad4(b)


def xdr_u32(v):
    return struct.pack(">I", v & 0xFFFFFFFF)


def xdr_u64(v):
    return struct.pack(">Q", v & 0xFFFFFFFFFFFFFFFF)


def xdr_bitmap(words):
    words = list(words)
    return xdr_u32(len(words)) + b"".join(xdr_u32(w) for w in words)


class XdrReader:
    def __init__(self, data):
        self.data = data
        self.off = 0

    def raw(self, n):
        v = self.data[self.off:self.off + n]
        if len(v) != n:
            raise ValueError("short read: wanted %d bytes, got %d" % (n, len(v)))
        self.off += n
        return v

    def u32(self):
        return struct.unpack(">I", self.raw(4))[0]

    def u64(self):
        return struct.unpack(">Q", self.raw(8))[0]

    def opaque(self):
        n = self.u32()
        v = self.raw(n)
        pad = (4 - n % 4) % 4
        if pad:
            self.raw(pad)
        return v

    def string(self):
        return self.opaque().decode("utf-8", "replace")

    def bitmap(self):
        n = self.u32()
        return [self.u32() for _ in range(n)]


# ---------------------------------------------------------------- op builders

def op_putrootfh():
    return (OP_PUTROOTFH, b"")


def op_lookup(name):
    return (OP_LOOKUP, xdr_opaque(name))


def op_getfh():
    return (OP_GETFH, b"")


def op_getattr(bitmap=()):
    return (OP_GETATTR, xdr_bitmap(bitmap))


def op_access(mask=ACCESS4_ALL):
    return (OP_ACCESS, xdr_u32(mask))


def op_readdir(cookie=0, cookieverf=b"\x00" * 8, dircount=8192, maxcount=8192, attr_request=()):
    return (OP_READDIR,
            xdr_u64(cookie) + cookieverf + xdr_u32(dircount) + xdr_u32(maxcount) + xdr_bitmap(attr_request))


ANON_STATEID = (0, b"\x00" * 12)  # special "no OPEN" stateid, RFC 7530 9.1.4.3


def op_read(offset=0, count=65536, stateid=ANON_STATEID):
    seqid, other = stateid
    return (OP_READ, xdr_u32(seqid) + other + xdr_u64(offset) + xdr_u32(count))


def op_secinfo(name):
    return (OP_SECINFO, xdr_opaque(name))


# ---------------------------------------------------------------- RPC framing

def build_auth_sys(uid, gid, gids=(), machine="probe", stamp=0):
    body = (xdr_u32(stamp) + xdr_opaque(machine) + xdr_u32(uid) + xdr_u32(gid) +
             xdr_u32(len(gids)) + b"".join(xdr_u32(g) for g in gids))
    return xdr_u32(AUTH_SYS) + xdr_opaque(body)


def build_auth_none():
    return xdr_u32(AUTH_NONE) + xdr_opaque(b"")


def build_compound(tag, ops, minorversion=0):
    out = xdr_opaque(tag) + xdr_u32(minorversion) + xdr_u32(len(ops))
    for opcode, args in ops:
        out += xdr_u32(opcode) + args
    return out


def build_rpc_call(xid, auth, verf, body):
    return (xdr_u32(xid) + xdr_u32(0) + xdr_u32(2) +  # msg_type=CALL, rpcvers=2
            xdr_u32(PROG_NFS) + xdr_u32(VERS_NFS4) + xdr_u32(PROC_COMPOUND) +
            auth + verf + body)


def frame(body):
    return struct.pack(">I", 0x80000000 | len(body)) + body


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed while reading %d bytes" % n)
        buf += chunk
    return buf


def recv_rpc_reply(sock):
    buf = b""
    while True:
        hdr = recv_exact(sock, 4)
        val = struct.unpack(">I", hdr)[0]
        length = val & 0x7FFFFFFF
        last = bool(val & 0x80000000)
        buf += recv_exact(sock, length)
        if last:
            return buf


def parse_rpc_reply(data):
    r = XdrReader(data)
    xid = r.u32()
    mtype = r.u32()
    if mtype != 1:
        raise ValueError("not a REPLY message (mtype=%d)" % mtype)
    reply_stat = r.u32()
    if reply_stat != 0:
        reject_stat = r.u32()
        return {"xid": xid, "denied": True, "reject_stat": reject_stat}
    _verf_flavor = r.u32()
    r.opaque()
    accept_stat = r.u32()
    if accept_stat != 0:
        return {"xid": xid, "accepted": True, "accept_stat": accept_stat, "reader": None}
    return {"xid": xid, "accepted": True, "accept_stat": 0, "reader": r}


def parse_compound_res(r):
    status = r.u32()
    tag = r.string()
    n = r.u32()
    results = []
    for _ in range(n):
        opcode = r.u32()
        op_status = r.u32()
        data = {}
        if op_status == 0:
            if opcode == OP_GETFH:
                data["fh"] = r.opaque()
            elif opcode == OP_GETATTR:
                data["bitmap"] = r.bitmap()
                data["attrs"] = r.opaque()
            elif opcode == OP_ACCESS:
                data["supported"] = r.u32()
                data["access"] = r.u32()
            elif opcode == OP_READDIR:
                data["cookieverf"] = r.raw(8)
                entries = []
                while r.u32() == 1:
                    r.u64()  # cookie
                    name = r.string()
                    r.bitmap()
                    r.opaque()  # attrs — empty, we request none
                    entries.append(name)
                data["entries"] = entries
                data["eof"] = bool(r.u32())
            elif opcode == OP_READ:
                data["eof"] = bool(r.u32())
                data["data"] = r.opaque()
            elif opcode == OP_SECINFO:
                count = r.u32()
                flavors = []
                for _ in range(count):
                    flavor = r.u32()
                    entry = {"flavor": flavor}
                    if flavor == RPCSEC_GSS:
                        r.opaque()  # mechanism oid, not needed to name the flavor
                        r.u32()  # qop
                        entry["service"] = r.u32()
                    flavors.append(entry)
                data["flavors"] = flavors
        results.append({"op": opcode, "status": op_status, "data": data})
    return {"status": status, "tag": tag, "results": results}


def decode_type_size(bitmap, attrs_raw):
    """Best-effort decode of a GETATTR blob requested with [TYPE, SIZE] only."""
    r = XdrReader(attrs_raw)
    out = {}
    mask = bitmap[0] if bitmap else 0
    if mask & (1 << FATTR4_TYPE):
        out["type"] = r.u32()
    if mask & (1 << FATTR4_SIZE):
        out["size"] = r.u64()
    return out


# ---------------------------------------------------------------- transport

class RpcConnection:
    """A single TCP connection reused across many COMPOUND calls.

    Plain run_compound() opens/closes a socket per call, which is fine for a
    one-shot probe but wasteful for a UID/GID scan issuing hundreds of calls —
    this lets a scan send them all over one connection.
    """

    def __init__(self, host, port, timeout, bind_ip=None):
        self.host, self.port, self.timeout, self.bind_ip = host, port, timeout, bind_ip
        self.sock = None
        self.connect_error = None

    def __enter__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        try:
            if self.bind_ip:
                self.sock.bind((self.bind_ip, 0))
            self.sock.connect((self.host, self.port))
        except OSError as e:
            # Covers socket.timeout, ConnectionRefusedError, etc. — don't raise
            # out of the `with` block, just remember it so call() can report
            # it the same way as any other transport_error.
            self.connect_error = "connect to %s:%d failed: %s" % (self.host, self.port, e)
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            self.sock.close()
        except OSError:
            pass

    def call(self, ops, auth, tag="probe"):
        if self.connect_error:
            return {"transport_error": self.connect_error}
        try:
            xid = random.randint(1, 0xFFFFFFFF)
            verf = build_auth_none()
            body = build_rpc_call(xid, auth, verf, build_compound(tag, ops))
            self.sock.sendall(frame(body))
            raw = recv_rpc_reply(self.sock)
        except OSError as e:
            return {"transport_error": "socket error during call: %s" % e}
        try:
            reply = parse_rpc_reply(raw)
        except (ValueError, struct.error) as e:
            return {"transport_error": "malformed RPC reply: %s" % e}
        if reply.get("denied"):
            return {"transport_error": "MSG_DENIED reject_stat=%d" % reply["reject_stat"]}
        if reply["accept_stat"] != 0:
            return {"transport_error": "RPC accept_stat=%d (0=OK,1=PROG_UNAVAIL,2=PROG_MISMATCH,3=PROC_UNAVAIL,4=GARBAGE_ARGS,5=SYSTEM_ERR)" % reply["accept_stat"]}
        try:
            return parse_compound_res(reply["reader"])
        except (ValueError, struct.error) as e:
            return {"transport_error": "malformed COMPOUND reply: %s" % e}


def run_compound(host, port, timeout, ops, auth, bind_ip=None, tag="probe"):
    with RpcConnection(host, port, timeout, bind_ip) as conn:
        return conn.call(ops, auth, tag)


# ---------------------------------------------------------------- logging

def log_compound(ops, result, label):
    print("  [%s]" % label)
    if "transport_error" in result:
        print("    ** transport/RPC failure: %s **" % result["transport_error"])
        print("    -> if this is a connect timeout/refusal, suspect an IP/network-level gate (test with --bind-ip)")
        return None
    print("    overall compound status: %s" % status_name(result["status"]))
    for (opcode, _args), res in zip(ops, result["results"]):
        name = OP_NAMES.get(opcode, str(opcode))
        st = status_name(res["status"])
        extra = ""
        if opcode == OP_ACCESS and res["status"] == 0:
            extra = " (requested=0x%02x granted=0x%02x)" % (ACCESS4_ALL, res["data"]["access"])
        if opcode == OP_GETATTR and res["status"] == 0:
            tsz = decode_type_size(res["data"]["bitmap"], res["data"]["attrs"])
            if "type" in tsz:
                extra = " (%s%s)" % (
                    NF4_TYPE_NAME.get(tsz["type"], "type=%d" % tsz["type"]),
                    ", size=%d" % tsz["size"] if "size" in tsz else "",
                )
        if opcode == OP_READDIR and res["status"] == 0:
            extra = " (%d entries%s)" % (len(res["data"]["entries"]), "" if res["data"]["eof"] else ", truncated")
        print("    %-10s -> %s%s" % (name, st, extra))
        if res["status"] in HINTS:
            print("               ^ %s" % HINTS[res["status"]])
    if len(result["results"]) < len(ops):
        stalled_op = ops[len(result["results"])]
        print("    ** COMPOUND stopped before '%s' — server aborts at the first failing op **" %
              OP_NAMES.get(stalled_op[0], stalled_op[0]))
    return result


# ---------------------------------------------------------------- high-level probe

def probe_path(host, port, timeout, path, auth, bind_ip, label):
    components = [c for c in path.strip("/").split("/") if c]

    walk_ops = [op_putrootfh()] + [op_lookup(c) for c in components] + [
        op_getfh(),
        op_getattr([(1 << FATTR4_TYPE) | (1 << FATTR4_SIZE)]),
        op_access(ACCESS4_ALL),
    ]
    result = run_compound(host, port, timeout, walk_ops, auth, bind_ip, tag="walk:" + path)
    print("--- %s ---" % label)
    walked = log_compound(walk_ops, result, "PUTROOTFH + LOOKUP(%s) + GETFH + GETATTR + ACCESS" % path)

    if not walked or len(walked["results"]) < len(walk_ops):
        return  # didn't even reach GETATTR/ACCESS — gate already visible above

    getattr_res = walked["results"][-2]
    entry_type = decode_type_size(getattr_res["data"]["bitmap"], getattr_res["data"]["attrs"]).get("type")

    if entry_type == 2:  # NF4DIR
        rd_ops = [op_putrootfh()] + [op_lookup(c) for c in components] + [op_readdir(attr_request=[])]
        rd_result = run_compound(host, port, timeout, rd_ops, auth, bind_ip, tag="readdir:" + path)
        rd = log_compound(rd_ops, rd_result, "READDIR")
        if rd and rd["results"][-1]["status"] == 0:
            for name in rd["results"][-1]["data"]["entries"]:
                print("      - %s" % name)
    elif entry_type == 1:  # NF4REG
        rf_ops = [op_putrootfh()] + [op_lookup(c) for c in components] + [op_read(0, 65536)]
        rf_result = run_compound(host, port, timeout, rf_ops, auth, bind_ip, tag="read:" + path)
        rf = log_compound(rf_ops, rf_result, "READ (anonymous stateid, no prior OPEN)")
        if rf and rf["results"][-1]["status"] == 0:
            data = rf["results"][-1]["data"]["data"]
            print("      read %d bytes, eof=%s" % (len(data), rf["results"][-1]["data"]["eof"]))
            print("      preview: %r" % data[:200])


# ---------------------------------------------------------------- security-flavor discovery

def discover_secinfo(host, port, timeout, path, uid, gid, gids, machine, bind_ip):
    """Ask the server (via SECINFO) which security flavors it accepts for `path`.

    Tried first as AUTH_SYS (most common default), then AUTH_NONE as a
    fallback, since either an intermediate LOOKUP or the target SECINFO call
    itself can fail with NFS4ERR_WRONGSEC depending on what the export
    actually requires.
    """
    components = [c for c in path.strip("/").split("/") if c]
    if not components:
        print("  path is the export root — SECINFO needs a parent dir + name, skipping discovery")
        return []

    secinfo_ops = [op_putrootfh()] + [op_lookup(c) for c in components[:-1]] + [op_secinfo(components[-1])]

    for name, auth in (("sys", build_auth_sys(uid, gid, gids, machine)), ("none", build_auth_none())):
        result = run_compound(host, port, timeout, secinfo_ops, auth, bind_ip, tag="secinfo:" + path)
        if "transport_error" in result:
            print("  SECINFO probe (as sec=%s) failed at transport: %s" % (name, result["transport_error"]))
            continue
        reached = len(result["results"])
        if reached == len(secinfo_ops) and result["results"][-1]["status"] == 0:
            flavors = result["results"][-1]["data"]["flavors"]
            print("  SECINFO reached using sec=%s -> server declares acceptable flavors for '%s': %s" %
                  (name, path, ", ".join(describe_flavor(f) for f in flavors)))
            return flavors
        failing_status = result["results"][reached - 1]["status"] if reached else None
        print("  SECINFO probe (as sec=%s) stalled at op #%d/%d (%s), trying next flavor..." %
              (name, reached, len(secinfo_ops),
               status_name(failing_status) if failing_status is not None else "no response"))

    print("  could not reach SECINFO with sec=sys or sec=none for '%s' — "
          "the path likely requires RPCSEC_GSS (krb5) even to be looked up" % path)
    return []


def run_sec_matrix(host, port, timeout, path, uid, gid, gids, machine, bind_ip, try_uids=None):
    print("=== security flavor discovery for %s ===" % path)
    flavors = discover_secinfo(host, port, timeout, path, uid, gid, gids, machine, bind_ip)
    if not flavors:
        return
    print()

    for entry in flavors:
        if entry["flavor"] == AUTH_NONE:
            print("=== attempting read/list with sec=none (declared acceptable) ===")
            probe_path(host, port, timeout, path, build_auth_none(), bind_ip, label="sec=none")
            print()
        elif entry["flavor"] == AUTH_SYS:
            uids = try_uids if try_uids else [uid]
            for u in uids:
                print("=== attempting read/list with sec=sys, uid=%d gid=%d (declared acceptable) ===" % (u, gid))
                label = "sec=sys uid=%d gid=%d%s from %s" % (
                    u, gid, (" gids=%s" % list(gids)) if gids else "", bind_ip or "(default route)")
                probe_path(host, port, timeout, path, build_auth_sys(u, gid, gids, machine), bind_ip, label=label)
                print()
        elif entry["flavor"] == RPCSEC_GSS:
            print("=== sec=%s declared acceptable but NOT attempted ===" % describe_flavor(entry))
            print("    RPCSEC_GSS/krb5 requires completing a real GSS context (RPCSEC_GSS_INIT with a")
            print("    live Kerberos ticket for the NFS service principal) — a hand-built AUTH_SYS/NONE")
            print("    packet cannot satisfy this. If you have a valid ticket (kinit'd) for this target's")
            print("    realm, say so and I'll add python-gssapi based krb5 support.")
            print()


# ---------------------------------------------------------------- uid/gid enumeration

def parse_id_set(s):
    """'0-2000' / '0,33,1000-1010,65534,4294967294' -> sorted list of ints."""
    ids = set()
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ids.update(range(int(a), int(b) + 1))
        else:
            ids.add(int(part))
    return sorted(ids)


def scan_identity(host, port, timeout, path, dimension, values, fixed_uid, fixed_gid, gids, machine, bind_ip,
                   abort_after_identical_stalls=5):
    """Enumerate `values` over uid or gid (AUTH_SYS is client-asserted and
    unverified, so nothing stops you from just trying every value and
    watching which ones the server grants ACCESS to).

    dimension: 'uid' or 'gid' — the other identity field stays fixed.
    Silently skips values that are flatly denied; only prints ones where
    ACCESS granted something nonzero, plus a running abort if the first
    few values all stall at the exact same op/status (a sign this gate
    isn't identity-dependent at all, so scanning further is pointless).
    """
    components = [c for c in path.strip("/").split("/") if c]
    walk_ops = [op_putrootfh()] + [op_lookup(c) for c in components] + [
        op_getattr([(1 << FATTR4_TYPE) | (1 << FATTR4_SIZE)]),
        op_access(ACCESS4_ALL),
    ]
    fixed_label = "gid=%d" % fixed_gid if dimension == "uid" else "uid=%d" % fixed_uid
    print("=== scanning %s over %d value(s) against %s (sec=sys, %s fixed) ===" %
          (dimension, len(values), path, fixed_label))

    hits = []
    stall_signature = None
    identical_stalls = 0
    with RpcConnection(host, port, timeout, bind_ip) as conn:
        for v in values:
            uid = v if dimension == "uid" else fixed_uid
            gid = v if dimension == "gid" else fixed_gid
            auth = build_auth_sys(uid, gid, gids, machine)
            result = conn.call(walk_ops, auth, tag="scan:%s=%d" % (dimension, v))

            if "transport_error" in result:
                print("  %s=%-10d -> transport error: %s (aborting scan)" % (dimension, v, result["transport_error"]))
                break

            reached = len(result["results"])
            if reached < len(walk_ops):
                stall_status = result["results"][reached - 1]["status"] if reached else None
                sig = (reached, stall_status)
                if sig == stall_signature:
                    identical_stalls += 1
                else:
                    stall_signature = sig
                    identical_stalls = 1
                if identical_stalls >= abort_after_identical_stalls:
                    print("  %d consecutive %s values all stalled at op #%d (%s) — this gate doesn't look "
                          "identity-dependent, aborting scan (check IP/network or sec flavor instead)" %
                          (identical_stalls, dimension, reached, status_name(stall_status)))
                    break
                continue

            granted = result["results"][-1]["data"]["access"]
            if not granted:
                continue
            hits.append((v, granted))
            print("  %s=%-10d -> ACCESS granted=0x%02x" % (dimension, v, granted))

            getattr_res = result["results"][-2]
            entry_type = decode_type_size(getattr_res["data"]["bitmap"], getattr_res["data"]["attrs"]).get("type")

            if entry_type == 2 and (granted & ACCESS4_LOOKUP):  # NF4DIR
                rd_ops = [op_putrootfh()] + [op_lookup(c) for c in components] + [op_readdir(attr_request=[])]
                rd = conn.call(rd_ops, auth, tag="scan-readdir:%s=%d" % (dimension, v))
                if "transport_error" in rd:
                    print("      readdir failed: %s" % rd["transport_error"])
                elif rd["results"][-1]["status"] != 0:
                    print("      readdir -> %s" % status_name(rd["results"][-1]["status"]))
                else:
                    entries = rd["results"][-1]["data"]["entries"]
                    print("      %d entries%s:" % (len(entries), "" if rd["results"][-1]["data"]["eof"] else ", truncated"))
                    for name in entries:
                        print("        - %s" % name)
            elif entry_type == 1 and (granted & ACCESS4_READ):  # NF4REG
                rf_ops = [op_putrootfh()] + [op_lookup(c) for c in components] + [op_read(0, 65536)]
                rf = conn.call(rf_ops, auth, tag="scan-read:%s=%d" % (dimension, v))
                if "transport_error" in rf:
                    print("      read failed: %s" % rf["transport_error"])
                elif rf["results"][-1]["status"] != 0:
                    print("      read -> %s" % status_name(rf["results"][-1]["status"]))
                else:
                    data = rf["results"][-1]["data"]["data"]
                    print("      read %d bytes, eof=%s, preview=%r" %
                          (len(data), rf["results"][-1]["data"]["eof"], data[:200]))

    print("--- scan done: %d/%d value(s) granted some access ---" % (len(hits), len(values)))
    return hits


# ---------------------------------------------------------------- CLI

def parse_gids(s):
    return [int(x) for x in s.split(",") if x.strip()] if s else []


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True, help="target NFS server IP/hostname")
    ap.add_argument("--path", required=True, help="export-relative path to walk, e.g. /x/y/z")
    ap.add_argument("--port", type=int, default=2049)
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--uid", type=int, default=0, help="AUTH_SYS uid to assert (default 0)")
    ap.add_argument("--gid", type=int, default=0, help="AUTH_SYS gid to assert (default 0)")
    ap.add_argument("--gids", default="", help="comma-separated aux gids to assert")
    ap.add_argument("--machine", default=socket.gethostname(), help="AUTH_SYS machine name field")
    ap.add_argument("--bind-ip", default=None,
                    help="local address to originate the connection from — the only honest way "
                         "to test IP/network-based export ACLs (you cannot spoof source IP over TCP)")
    ap.add_argument("--try-uids", default=None,
                    help="comma-separated uids to test in turn against the SAME path/gid, to see "
                         "whether varying identity changes the outcome (identity-based gate)")
    ap.add_argument("--scan-uids", default=None,
                    help="enumerate uids instead of guessing one — e.g. '0-2000' or "
                         "'0,33,1000-1010,65534,4294967294'. AUTH_SYS uid/gid are client-asserted "
                         "and unverified, so this just tries each one and reports which get ACCESS "
                         "granted. Runs over one reused TCP connection; auto-aborts if the gate "
                         "clearly isn't identity-dependent. Skips SECINFO/sec=none/krb5 handling — "
                         "this is a focused sec=sys identity sweep.")
    ap.add_argument("--scan-gids", default=None,
                    help="same as --scan-uids but enumerates gid instead, holding --uid fixed")
    args = ap.parse_args()

    gids = parse_gids(args.gids)
    try_uids = [int(x) for x in args.try_uids.split(",")] if args.try_uids else None

    if args.scan_uids or args.scan_gids:
        if args.scan_uids:
            scan_identity(args.host, args.port, args.timeout, args.path, "uid",
                          parse_id_set(args.scan_uids), args.uid, args.gid, gids, args.machine, args.bind_ip)
        if args.scan_gids:
            scan_identity(args.host, args.port, args.timeout, args.path, "gid",
                          parse_id_set(args.scan_gids), args.uid, args.gid, gids, args.machine, args.bind_ip)
        return

    run_sec_matrix(args.host, args.port, args.timeout, args.path, args.uid, args.gid, gids,
                   args.machine, args.bind_ip, try_uids=try_uids)


if __name__ == "__main__":
    main()
