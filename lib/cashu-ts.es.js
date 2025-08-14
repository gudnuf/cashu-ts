import { Buffer as L } from "buffer";
import { verifyDLEQProof_reblind as Xt } from "./crypto/client/NUT12.es.js";
import { pointFromHex as rt, hashToCurve as St } from "./crypto/common.es.js";
import { hexToBytes as F, bytesToHex as G } from "@noble/curves/abstract/utils";
import { sha256 as It } from "@noble/hashes/sha2";
import { signP2PKProofs as Mt } from "./crypto/client/NUT11.es.js";
import { signMintQuote as Yt } from "./crypto/client/NUT20.es.js";
import { constructProofFromPromise as Zt, serializeProof as te, blindMessage as ht } from "./crypto/client.es.js";
import { hexToBytes as qt, bytesToHex as X, randomBytes as Bt } from "@noble/hashes/utils";
import { deriveSecret as ee, deriveBlindingFactor as ne } from "./crypto/client/NUT09.es.js";
function se(o) {
  return L.from(o).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function Dt(o) {
  return L.from(o, "base64");
}
function xt(o) {
  const t = JSON.stringify(o);
  return ie(L.from(t).toString("base64"));
}
function oe(o) {
  const t = L.from(re(o), "base64").toString();
  return JSON.parse(t);
}
function re(o) {
  return o.replace(/-/g, "+").replace(/_/g, "/").split("=")[0];
}
function ie(o) {
  return o.replace(/\+/g, "-").replace(/\//g, "_").split("=")[0];
}
function ae(o) {
  return typeof o == "number" || typeof o == "string";
}
function gt(o) {
  const t = [];
  return wt(o, t), new Uint8Array(t);
}
function wt(o, t) {
  if (o === null)
    t.push(246);
  else if (o === void 0)
    t.push(247);
  else if (typeof o == "boolean")
    t.push(o ? 245 : 244);
  else if (typeof o == "number")
    Ft(o, t);
  else if (typeof o == "string")
    Qt(o, t);
  else if (Array.isArray(o))
    ue(o, t);
  else if (o instanceof Uint8Array)
    ce(o, t);
  else if (
    // Defensive: POJO only (null/array handled above)
    typeof o == "object" && o !== null && !Array.isArray(o)
  )
    he(o, t);
  else
    throw new Error("Unsupported type");
}
function Ft(o, t) {
  if (o < 24)
    t.push(o);
  else if (o < 256)
    t.push(24, o);
  else if (o < 65536)
    t.push(25, o >> 8, o & 255);
  else if (o < 4294967296)
    t.push(26, o >> 24, o >> 16 & 255, o >> 8 & 255, o & 255);
  else
    throw new Error("Unsupported integer size");
}
function ce(o, t) {
  const e = o.length;
  if (e < 24)
    t.push(64 + e);
  else if (e < 256)
    t.push(88, e);
  else if (e < 65536)
    t.push(89, e >> 8 & 255, e & 255);
  else if (e < 4294967296)
    t.push(
      90,
      e >> 24 & 255,
      e >> 16 & 255,
      e >> 8 & 255,
      e & 255
    );
  else
    throw new Error("Byte string too long to encode");
  for (let n = 0; n < o.length; n++)
    t.push(o[n]);
}
function Qt(o, t) {
  const e = new TextEncoder().encode(o), n = e.length;
  if (n < 24)
    t.push(96 + n);
  else if (n < 256)
    t.push(120, n);
  else if (n < 65536)
    t.push(121, n >> 8 & 255, n & 255);
  else if (n < 4294967296)
    t.push(
      122,
      n >> 24 & 255,
      n >> 16 & 255,
      n >> 8 & 255,
      n & 255
    );
  else
    throw new Error("String too long to encode");
  for (let s = 0; s < e.length; s++)
    t.push(e[s]);
}
function ue(o, t) {
  const e = o.length;
  if (e < 24)
    t.push(128 | e);
  else if (e < 256)
    t.push(152, e);
  else if (e < 65536)
    t.push(153, e >> 8, e & 255);
  else
    throw new Error("Unsupported array length");
  for (const n of o)
    wt(n, t);
}
function he(o, t) {
  const e = Object.keys(o);
  Ft(e.length, t), t[t.length - 1] |= 160;
  for (const n of e)
    Qt(n, t), wt(o[n], t);
}
function kt(o) {
  const t = new DataView(o.buffer, o.byteOffset, o.byteLength);
  return it(t, 0).value;
}
function it(o, t) {
  if (t >= o.byteLength)
    throw new Error("Unexpected end of data");
  const e = o.getUint8(t++), n = e >> 5, s = e & 31;
  switch (n) {
    case 0:
      return le(o, t, s);
    case 1:
      return de(o, t, s);
    case 2:
      return fe(o, t, s);
    case 3:
      return me(o, t, s);
    case 4:
      return pe(o, t, s);
    case 5:
      return ye(o, t, s);
    case 7:
      return we(o, t, s);
    default:
      throw new Error(`Unsupported major type: ${n}`);
  }
}
function V(o, t, e) {
  if (e < 24) return { value: e, offset: t };
  if (e === 24) return { value: o.getUint8(t++), offset: t };
  if (e === 25) {
    const n = o.getUint16(t, !1);
    return t += 2, { value: n, offset: t };
  }
  if (e === 26) {
    const n = o.getUint32(t, !1);
    return t += 4, { value: n, offset: t };
  }
  if (e === 27) {
    const n = o.getUint32(t, !1), s = o.getUint32(t + 4, !1);
    return t += 8, { value: n * 2 ** 32 + s, offset: t };
  }
  throw new Error(`Unsupported length: ${e}`);
}
function le(o, t, e) {
  const { value: n, offset: s } = V(o, t, e);
  return { value: n, offset: s };
}
function de(o, t, e) {
  const { value: n, offset: s } = V(o, t, e);
  return { value: -1 - n, offset: s };
}
function fe(o, t, e) {
  const { value: n, offset: s } = V(o, t, e);
  if (s + n > o.byteLength)
    throw new Error("Byte string length exceeds data length");
  return { value: new Uint8Array(o.buffer, o.byteOffset + s, n), offset: s + n };
}
function me(o, t, e) {
  const { value: n, offset: s } = V(o, t, e);
  if (s + n > o.byteLength)
    throw new Error("String length exceeds data length");
  const r = new Uint8Array(o.buffer, o.byteOffset + s, n);
  return { value: new TextDecoder().decode(r), offset: s + n };
}
function pe(o, t, e) {
  const { value: n, offset: s } = V(o, t, e), r = [];
  let a = s;
  for (let i = 0; i < n; i++) {
    const c = it(o, a);
    r.push(c.value), a = c.offset;
  }
  return { value: r, offset: a };
}
function ye(o, t, e) {
  const { value: n, offset: s } = V(o, t, e), r = {};
  let a = s;
  for (let i = 0; i < n; i++) {
    const c = it(o, a);
    if (!ae(c.value))
      throw new Error("Invalid key type");
    const h = it(o, c.offset);
    r[c.value] = h.value, a = h.offset;
  }
  return { value: r, offset: a };
}
function ge(o) {
  const t = (o & 31744) >> 10, e = o & 1023, n = o & 32768 ? -1 : 1;
  return t === 0 ? n * 2 ** -14 * (e / 1024) : t === 31 ? e ? NaN : n * (1 / 0) : n * 2 ** (t - 15) * (1 + e / 1024);
}
function we(o, t, e) {
  if (e < 24)
    switch (e) {
      case 20:
        return { value: !1, offset: t };
      case 21:
        return { value: !0, offset: t };
      case 22:
        return { value: null, offset: t };
      case 23:
        return { value: void 0, offset: t };
      default:
        throw new Error(`Unknown simple value: ${e}`);
    }
  if (e === 24) return { value: o.getUint8(t++), offset: t };
  if (e === 25) {
    const n = ge(o.getUint16(t, !1));
    return t += 2, { value: n, offset: t };
  }
  if (e === 26) {
    const n = o.getFloat32(t, !1);
    return t += 4, { value: n, offset: t };
  }
  if (e === 27) {
    const n = o.getFloat64(t, !1);
    return t += 8, { value: n, offset: t };
  }
  throw new Error(`Unknown simple or float value: ${e}`);
}
class _t {
  constructor(t, e, n, s, r, a, i = !1, c) {
    this.transport = t, this.id = e, this.amount = n, this.unit = s, this.mints = r, this.description = a, this.singleUse = i, this.nut10 = c;
  }
  toRawRequest() {
    const t = {};
    return this.transport && (t.t = this.transport.map((e) => ({
      t: e.type,
      a: e.target,
      g: e.tags
    }))), this.id && (t.i = this.id), this.amount && (t.a = this.amount), this.unit && (t.u = this.unit), this.mints && (t.m = this.mints), this.description && (t.d = this.description), this.singleUse && (t.s = this.singleUse), this.nut10 && (t.nut10 = {
      k: this.nut10.kind,
      d: this.nut10.data,
      t: this.nut10.tags
    }), t;
  }
  toEncodedRequest() {
    const t = this.toRawRequest(), e = gt(t);
    return "creqA" + L.from(e).toString("base64");
  }
  getTransport(t) {
    return this.transport?.find((e) => e.type === t);
  }
  static fromRawRequest(t) {
    const e = t.t ? t.t.map((s) => ({
      type: s.t,
      target: s.a,
      tags: s.g
    })) : void 0, n = t.nut10 ? {
      kind: t.nut10.k,
      data: t.nut10.d,
      tags: t.nut10.t
    } : void 0;
    return new _t(
      e,
      t.i,
      t.a,
      t.u,
      t.m,
      t.d,
      t.s,
      n
    );
  }
  static fromEncodedRequest(t) {
    if (!t.startsWith("creq"))
      throw new Error("unsupported pr: invalid prefix");
    if (t[4] !== "A")
      throw new Error("unsupported pr version");
    const n = t.slice(5), s = Dt(n), r = kt(s);
    return this.fromRawRequest(r);
  }
}
const ke = "A", _e = "cashu";
function R(o, t, e, n) {
  if (e) {
    const r = Rt(e);
    if (r > o)
      throw new Error(`Split is greater than total amount: ${r} > ${o}`);
    if (e.some((a) => !Lt(a, t)))
      throw new Error("Provided amount preferences do not match the amounts of the mint keyset.");
    o = o - Rt(e);
  } else
    e = [];
  return Nt(t, "desc").forEach((r) => {
    const a = Math.floor(o / r);
    for (let i = 0; i < a; ++i) e?.push(r);
    o %= r;
  }), e.sort((r, a) => r - a);
}
function vt(o, t, e, n) {
  const s = [], r = o.map((h) => h.amount);
  Nt(e, "asc").forEach((h) => {
    const u = r.filter((d) => d === h).length, f = Math.max(n - u, 0);
    for (let d = 0; d < f && !(s.reduce((l, m) => l + m, 0) + h > t); ++d)
      s.push(h);
  });
  const i = t - s.reduce((h, u) => h + u, 0);
  return i && R(i, e).forEach((u) => {
    s.push(u);
  }), s.sort((h, u) => h - u);
}
function Nt(o, t = "desc") {
  return t == "desc" ? Object.keys(o).map((e) => parseInt(e)).sort((e, n) => n - e) : Object.keys(o).map((e) => parseInt(e)).sort((e, n) => e - n);
}
function Lt(o, t) {
  return o in t;
}
function be(o) {
  return Wt(G(o));
}
function Wt(o) {
  return BigInt(`0x${o}`);
}
function Ae(o) {
  return o.toString(16).padStart(64, "0");
}
function Ot(o) {
  return /^[a-f0-9]*$/i.test(o);
}
function bt(o) {
  return Array.isArray(o) ? o.some((t) => !Ot(t.id)) : !Ot(o.id);
}
function Ee(o, t) {
  bt(o.proofs) || (o.proofs = Ct(o.proofs)), t && (o.proofs = at(o.proofs));
  const e = { token: [{ mint: o.mint, proofs: o.proofs }] };
  return o.unit && (e.unit = o.unit), o.memo && (e.memo = o.memo), _e + ke + xt(e);
}
function Ct(o) {
  return o.map((t) => {
    const e = { ...t };
    return e.id = e.id.slice(0, 16), e;
  });
}
function Ze(o, t) {
  if (bt(o.proofs) || t?.version === 3) {
    if (t?.version === 4)
      throw new Error("can not encode to v4 token if proofs contain non-hex keyset id");
    return Ee(o, t?.removeDleq);
  }
  return Pe(o, t?.removeDleq);
}
function Pe(o, t) {
  if (t && (o.proofs = at(o.proofs)), o.proofs.forEach((c) => {
    if (c.dleq && c.dleq.r == null)
      throw new Error("Missing blinding factor in included DLEQ proof");
  }), bt(o.proofs))
    throw new Error("can not encode to v4 token if proofs contain non-hex keyset id");
  o.proofs = Ct(o.proofs);
  const n = jt(o), s = gt(n), r = "cashu", a = "B", i = se(s);
  return r + a + i;
}
function jt(o) {
  const t = {}, e = o.mint;
  for (let s = 0; s < o.proofs.length; s++) {
    const r = o.proofs[s];
    t[r.id] ? t[r.id].push(r) : t[r.id] = [r];
  }
  const n = {
    m: e,
    u: o.unit || "sat",
    t: Object.keys(t).map(
      (s) => ({
        i: F(s),
        p: t[s].map(
          (r) => ({
            a: r.amount,
            s: r.secret,
            c: F(r.C),
            ...r.dleq && {
              d: {
                e: F(r.dleq.e),
                s: F(r.dleq.s),
                r: F(r.dleq.r ?? "00")
              }
            },
            ...r.witness && {
              w: JSON.stringify(r.witness)
            }
          })
        )
      })
    )
  };
  return o.memo && (n.d = o.memo), n;
}
function $t(o) {
  const t = [];
  o.t.forEach(
    (n) => n.p.forEach((s) => {
      t.push({
        secret: s.s,
        C: G(s.c),
        amount: s.a,
        id: G(n.i),
        ...s.d && {
          dleq: {
            r: G(s.d.r),
            s: G(s.d.s),
            e: G(s.d.e)
          }
        },
        ...s.w && {
          witness: s.w
        }
      });
    })
  );
  const e = { mint: o.m, proofs: t, unit: o.u || "sat" };
  return o.d && (e.memo = o.d), e;
}
function Se(o, t) {
  ["web+cashu://", "cashu://", "cashu:", "cashu"].forEach((s) => {
    o.startsWith(s) && (o = o.slice(s.length));
  });
  const n = Ie(o);
  return n.proofs = ve(n.proofs, t), n;
}
function Ie(o) {
  const t = o.slice(0, 1), e = o.slice(1);
  if (t === "A") {
    const n = oe(e);
    if (n.token.length > 1)
      throw new Error("Multi entry token are not supported");
    const s = n.token[0], r = {
      mint: s.mint,
      proofs: s.proofs,
      unit: n.unit || "sat"
    };
    return n.memo && (r.memo = n.memo), r;
  } else if (t === "B") {
    const n = Dt(e), s = kt(n);
    return $t(s);
  }
  throw new Error("Token version is not supported");
}
function Me(o, t, e, n) {
  let s = Object.entries(o).sort((i, c) => +i[0] - +c[0]).map(([, i]) => F(i)).reduce((i, c) => lt(i, c), new Uint8Array());
  n || (n = 0);
  let r, a;
  switch (n) {
    case 0:
      return r = It(s), a = L.from(r).toString("hex").slice(0, 14), "00" + a;
    case 1:
      if (!t)
        throw new Error("Couldn't compute ID version 2: no unit was given.");
      return s = lt(s, L.from("unit:" + t)), e && (s = lt(
        s,
        L.from("final_expiry:" + e.toString())
      )), r = It(s), a = L.from(r).toString("hex"), "01" + a;
  }
}
function lt(o, t) {
  const e = new Uint8Array(o.length + t.length);
  return e.set(o), e.set(t, o.length), e;
}
function D(o) {
  return typeof o == "object";
}
function A(...o) {
  return o.map((t) => t.replace(/(^\/+|\/+$)/g, "")).join("/");
}
function zt(o) {
  return o.replace(/\/$/, "");
}
function j(o) {
  return o.reduce((t, e) => t + e.amount, 0);
}
function tn(o) {
  return _t.fromEncodedRequest(o);
}
class qe {
  get value() {
    return this._value;
  }
  set value(t) {
    this._value = t;
  }
  get next() {
    return this._next;
  }
  set next(t) {
    this._next = t;
  }
  constructor(t) {
    this._value = t, this._next = null;
  }
}
class Be {
  get first() {
    return this._first;
  }
  set first(t) {
    this._first = t;
  }
  get last() {
    return this._last;
  }
  set last(t) {
    this._last = t;
  }
  get size() {
    return this._size;
  }
  set size(t) {
    this._size = t;
  }
  constructor() {
    this._first = null, this._last = null, this._size = 0;
  }
  enqueue(t) {
    const e = new qe(t);
    return this._size === 0 || !this._last ? (this._first = e, this._last = e) : (this._last.next = e, this._last = e), this._size++, !0;
  }
  dequeue() {
    if (this._size === 0 || !this._first) return null;
    const t = this._first;
    return this._first = t.next, t.next = null, this._size--, t.value;
  }
}
function at(o) {
  return o.map((t) => {
    const e = { ...t };
    return delete e.dleq, e;
  });
}
function Tt(o) {
  const t = F(o.id)[0];
  return Me(o.keys, o.unit, o.final_expiry, t) === o.id;
}
function ve(o, t) {
  const e = [];
  for (const n of o) {
    let s;
    try {
      s = F(n.id);
    } catch {
      e.push(n);
      continue;
    }
    if (s[0] === 0)
      e.push(n);
    else if (s[0] === 1) {
      if (!t)
        throw new Error("A short keyset ID v2 was encountered, but got no keysets to map it to.");
      let r = !1;
      for (const a of t)
        if (n.id === a.id.slice(0, n.id.length)) {
          n.id = a.id, e.push(n), r = !0;
          break;
        }
      if (!r)
        throw new Error(
          `Couldn't map short keyset ID ${n.id} to any known keysets of the current Mint`
        );
    } else
      throw new Error(`Unknown keyset ID version: ${s[0]}`);
  }
  return e;
}
function Gt(o, t) {
  if (o.dleq == null)
    return !1;
  const e = {
    e: F(o.dleq.e),
    s: F(o.dleq.s),
    r: Wt(o.dleq.r ?? "00")
  };
  if (!Lt(o.amount, t.keys))
    throw new Error(`undefined key for amount ${o.amount}`);
  const n = t.keys[o.amount];
  return !!Xt(
    new TextEncoder().encode(o.secret),
    e,
    rt(o.C),
    rt(n)
  );
}
function Oe(...o) {
  const t = o.reduce((s, r) => s + r.length, 0), e = new Uint8Array(t);
  let n = 0;
  for (let s = 0; s < o.length; s++)
    e.set(o[s], n), n = n + o[s].length;
  return e;
}
function en(o) {
  const t = new TextEncoder(), e = jt(o), n = gt(e), s = t.encode("craw"), r = t.encode("B");
  return Oe(s, r, n);
}
function nn(o) {
  const t = new TextDecoder(), e = t.decode(o.slice(0, 4)), n = t.decode(new Uint8Array([o[4]]));
  if (e !== "craw" || n !== "B")
    throw new Error("not a valid binary token");
  const s = o.slice(5), r = kt(s);
  return $t(r);
}
function Rt(o) {
  return o.reduce((t, e) => t + e, 0);
}
let ct;
typeof WebSocket < "u" && (ct = WebSocket);
function sn(o) {
  ct = o;
}
function Te() {
  if (ct === void 0)
    throw new Error("WebSocket implementation not initialized");
  return ct;
}
const B = {
  FATAL: "FATAL",
  ERROR: "ERROR",
  WARN: "WARN",
  INFO: "INFO",
  DEBUG: "DEBUG",
  TRACE: "TRACE"
}, x = {
  fatal() {
  },
  error() {
  },
  warn() {
  },
  info() {
  },
  debug() {
  },
  trace() {
  },
  log() {
  }
}, Z = class Z {
  constructor(t = B.INFO) {
    this.minLevel = t;
  }
  logToConsole(t, e, n) {
    if (Z.SEVERITY[t] > Z.SEVERITY[this.minLevel]) return;
    const s = `[${t}] `;
    let r = e;
    const a = /* @__PURE__ */ new Set();
    if (n) {
      const i = Object.fromEntries(
        Object.entries(n).map(([u, f]) => [
          u,
          f instanceof Error ? { message: f.message, stack: f.stack } : f
        ])
      );
      r = e.replace(/\{(\w+)\}/g, (u, f) => {
        if (f in i && i[f] !== void 0) {
          a.add(f);
          const d = i[f];
          return typeof d == "string" ? d : typeof d == "number" || typeof d == "boolean" ? d.toString() : d == null ? "" : JSON.stringify(d);
        }
        return u;
      });
      const c = Object.fromEntries(
        Object.entries(i).filter(([u]) => !a.has(u))
      ), h = this.getConsoleMethod(t);
      Object.keys(c).length > 0 ? h(s + r, c) : h(s + r);
    } else
      this.getConsoleMethod(t)(s + r);
  }
  // Note: NOT static as test suite needs to spy on the output
  getConsoleMethod(t) {
    switch (t) {
      case B.FATAL:
      case B.ERROR:
        return console.error;
      case B.WARN:
        return console.warn;
      case B.INFO:
        return console.info;
      case B.DEBUG:
        return console.debug;
      case B.TRACE:
        return console.trace;
      default:
        return console.log;
    }
  }
  // Interface methods
  fatal(t, e) {
    this.logToConsole(B.FATAL, t, e);
  }
  error(t, e) {
    this.logToConsole(B.ERROR, t, e);
  }
  warn(t, e) {
    this.logToConsole(B.WARN, t, e);
  }
  info(t, e) {
    this.logToConsole(B.INFO, t, e);
  }
  debug(t, e) {
    this.logToConsole(B.DEBUG, t, e);
  }
  trace(t, e) {
    this.logToConsole(B.TRACE, t, e);
  }
  log(t, e, n) {
    this.logToConsole(t, e, n);
  }
};
Z.SEVERITY = {
  [B.FATAL]: 0,
  [B.ERROR]: 1,
  [B.WARN]: 2,
  [B.INFO]: 3,
  [B.DEBUG]: 4,
  [B.TRACE]: 5
};
let Ut = Z;
function Re() {
  const o = Date.now();
  return {
    elapsed: () => Date.now() - o
  };
}
class H {
  constructor() {
    this.connectionMap = /* @__PURE__ */ new Map();
  }
  static getInstance() {
    return H.instance || (H.instance = new H()), H.instance;
  }
  getConnection(t, e) {
    if (this.connectionMap.has(t))
      return this.connectionMap.get(t);
    const n = new Ue(t, e);
    return this.connectionMap.set(t, n), n;
  }
}
class Ue {
  constructor(t, e) {
    this.subListeners = {}, this.rpcListeners = {}, this.rpcId = 0, this.onCloseCallbacks = [], this._WS = Te(), this.url = new URL(t), this.messageQueue = new Be(), this._logger = e ?? x;
  }
  connect() {
    return this.connectionPromise || (this.connectionPromise = new Promise((t, e) => {
      try {
        this.ws = new this._WS(this.url.toString()), this.onCloseCallbacks = [];
      } catch (n) {
        e(n instanceof Error ? n : new Error(String(n)));
        return;
      }
      this.ws.onopen = () => {
        t();
      }, this.ws.onerror = () => {
        e(new Error("Failed to open WebSocket"));
      }, this.ws.onmessage = (n) => {
        this.messageQueue.enqueue(n.data), this.handlingInterval || (this.handlingInterval = setInterval(
          this.handleNextMessage.bind(this),
          0
        ));
      }, this.ws.onclose = (n) => {
        this.connectionPromise = void 0, this.onCloseCallbacks.forEach((s) => s(n));
      };
    })), this.connectionPromise;
  }
  sendRequest(t, e) {
    if (this.ws?.readyState !== 1) {
      if (t === "unsubscribe")
        return;
      throw this._logger.error("Attempted sendRequest, but socket was not open"), new Error("Socket not open");
    }
    const n = this.rpcId;
    this.rpcId++;
    const s = JSON.stringify({ jsonrpc: "2.0", method: t, params: e, id: n });
    this.ws?.send(s);
  }
  /**
   * @deprecated Use cancelSubscription for JSONRPC compliance.
   */
  closeSubscription(t) {
    this.ws?.send(JSON.stringify(["CLOSE", t]));
  }
  addSubListener(t, e) {
    (this.subListeners[t] = this.subListeners[t] || []).push(
      e
    );
  }
  addRpcListener(t, e, n) {
    this.rpcListeners[n] = { callback: t, errorCallback: e };
  }
  removeRpcListener(t) {
    delete this.rpcListeners[t];
  }
  removeListener(t, e) {
    if (this.subListeners[t]) {
      if (this.subListeners[t].length === 1) {
        delete this.subListeners[t];
        return;
      }
      this.subListeners[t] = this.subListeners[t].filter(
        (n) => n !== e
      );
    }
  }
  async ensureConnection() {
    this.ws?.readyState !== 1 && await this.connect();
  }
  handleNextMessage() {
    if (this.messageQueue.size === 0) {
      clearInterval(this.handlingInterval), this.handlingInterval = void 0;
      return;
    }
    const t = this.messageQueue.dequeue();
    let e;
    try {
      if (e = JSON.parse(t), "result" in e && e.id != null)
        this.rpcListeners[e.id] && (this.rpcListeners[e.id].callback(), this.removeRpcListener(e.id));
      else if ("error" in e && e.id != null)
        this.rpcListeners[e.id] && (this.rpcListeners[e.id].errorCallback(new Error(e.error.message)), this.removeRpcListener(e.id));
      else if ("method" in e && !("id" in e)) {
        const n = e.params?.subId;
        if (!n)
          return;
        if (this.subListeners[n]?.length > 0) {
          const s = e;
          this.subListeners[n].forEach((r) => r(s.params?.payload));
        }
      }
    } catch (n) {
      this._logger.error("Error doing handleNextMessage", { e: n });
      return;
    }
  }
  createSubscription(t, e, n) {
    if (this.ws?.readyState !== 1)
      throw this._logger.error("Attempted createSubscription, but socket was not open"), new Error("Socket is not open");
    const s = (Math.random() + 1).toString(36).substring(7);
    return this.addRpcListener(
      () => {
        this.addSubListener(s, e);
      },
      n,
      this.rpcId
    ), this.sendRequest("subscribe", { ...t, subId: s }), this.rpcId++, s;
  }
  /**
   * Cancels a subscription, sending an unsubscribe request and handling responses.
   *
   * @param subId The subscription ID to cancel.
   * @param callback The original payload callback to remove.
   * @param errorCallback Optional callback for unsubscribe errors (defaults to logging).
   */
  cancelSubscription(t, e, n) {
    this.removeListener(t, e), this.addRpcListener(
      () => {
        this._logger.info("Unsubscribed {subId}", { subId: t });
      },
      n || ((s) => this._logger.error("Unsubscribe failed", { e: s })),
      this.rpcId
    ), this.sendRequest("unsubscribe", { subId: t });
  }
  get activeSubscriptions() {
    return Object.keys(this.subListeners);
  }
  close() {
    this.ws && this.ws?.close();
  }
  onClose(t) {
    this.onCloseCallbacks.push(t);
  }
}
const on = {
  UNSPENT: "UNSPENT",
  PENDING: "PENDING",
  SPENT: "SPENT"
}, tt = {
  UNPAID: "UNPAID",
  PENDING: "PENDING",
  PAID: "PAID"
}, pt = {
  UNPAID: "UNPAID",
  PAID: "PAID",
  ISSUED: "ISSUED"
};
var Ke = /* @__PURE__ */ ((o) => (o.POST = "post", o.NOSTR = "nostr", o))(Ke || {});
class et extends Error {
  constructor(t, e) {
    super(t), this.status = e, this.name = "HttpResponseError", Object.setPrototypeOf(this, et.prototype);
  }
}
class At extends Error {
  constructor(t) {
    super(t), this.name = "NetworkError", Object.setPrototypeOf(this, At.prototype);
  }
}
class Et extends et {
  constructor(t, e) {
    super(e || "Unknown mint operation error", 400), this.code = t, this.name = "MintOperationError", Object.setPrototypeOf(this, Et.prototype);
  }
}
let Ht = {}, Vt = x;
function rn(o) {
  Ht = o;
}
function De(o) {
  Vt = o;
}
async function xe({
  endpoint: o,
  requestBody: t,
  headers: e,
  ...n
}) {
  const s = t ? JSON.stringify(t) : void 0, r = {
    Accept: "application/json, text/plain, */*",
    ...s ? { "Content-Type": "application/json" } : void 0,
    ...e
  };
  let a;
  try {
    a = await fetch(o, { body: s, headers: r, ...n });
  } catch (i) {
    throw new At(i instanceof Error ? i.message : "Network request failed");
  }
  if (!a.ok) {
    let i;
    try {
      i = await a.json();
    } catch {
      i = { error: "bad response" };
    }
    if (a.status === 400 && "code" in i && typeof i.code == "number" && "detail" in i && typeof i.detail == "string")
      throw new Et(i.code, i.detail);
    let c = "HTTP request failed";
    throw "error" in i && typeof i.error == "string" ? c = i.error : "detail" in i && typeof i.detail == "string" && (c = i.detail), new et(c, a.status);
  }
  try {
    return await a.json();
  } catch (i) {
    throw Vt.error("Failed to parse HTTP response", { err: i }), new et("bad response", a.status);
  }
}
async function E(o) {
  return await xe({ ...o, ...Ht });
}
function dt(o, t) {
  return o.state || (t.warn(
    "Field 'state' not found in MeltQuoteResponse. Update NUT-05 of mint: https://github.com/cashubtc/nuts/pull/136)"
  ), typeof o.paid == "boolean" && (o.state = o.paid ? tt.PAID : tt.UNPAID)), o;
}
function Kt(o, t) {
  return o.state || (t.warn(
    "Field 'state' not found in MintQuoteResponse. Update NUT-04 of mint: https://github.com/cashubtc/nuts/pull/141)"
  ), typeof o.paid == "boolean" && (o.state = o.paid ? pt.PAID : pt.UNPAID)), o;
}
function Fe(o, t) {
  return Array.isArray(o?.contact) && o?.contact.length > 0 && (o.contact = o.contact.map((e) => Array.isArray(e) && e.length === 2 && typeof e[0] == "string" && typeof e[1] == "string" ? (t.warn(
    "Mint returned deprecated 'contact' field: Update NUT-06: https://github.com/cashubtc/nuts/pull/117"
  ), { method: e[0], info: e[1] }) : e)), o;
}
class yt {
  constructor(t) {
    this._mintInfo = t, t.nuts[22] && (this._protectedEnpoints = {
      cache: {},
      apiReturn: t.nuts[22].protected_endpoints.map((e) => ({
        method: e.method,
        regex: new RegExp(e.path)
      }))
    });
  }
  isSupported(t) {
    switch (t) {
      case 4:
      case 5:
        return this.checkMintMelt(t);
      case 7:
      case 8:
      case 9:
      case 10:
      case 11:
      case 12:
      case 14:
      case 20:
        return this.checkGenericNut(t);
      case 17:
        return this.checkNut17();
      case 15:
        return this.checkNut15();
      default:
        throw new Error("nut is not supported by cashu-ts");
    }
  }
  requiresBlindAuthToken(t) {
    if (!this._protectedEnpoints)
      return !1;
    if (typeof this._protectedEnpoints.cache[t] == "boolean")
      return this._protectedEnpoints.cache[t];
    const e = this._protectedEnpoints.apiReturn.some((n) => n.regex.test(t));
    return this._protectedEnpoints.cache[t] = e, e;
  }
  checkGenericNut(t) {
    return this._mintInfo.nuts[t]?.supported ? { supported: !0 } : { supported: !1 };
  }
  checkMintMelt(t) {
    const e = this._mintInfo.nuts[t];
    return e && e.methods.length > 0 && !e.disabled ? { disabled: !1, params: e.methods } : { disabled: !0, params: e.methods };
  }
  checkNut17() {
    return this._mintInfo.nuts[17] && this._mintInfo.nuts[17].supported.length > 0 ? { supported: !0, params: this._mintInfo.nuts[17].supported } : { supported: !1 };
  }
  checkNut15() {
    return this._mintInfo.nuts[15] && this._mintInfo.nuts[15].methods.length > 0 ? { supported: !0, params: this._mintInfo.nuts[15].methods } : { supported: !1 };
  }
  get contact() {
    return this._mintInfo.contact;
  }
  get description() {
    return this._mintInfo.description;
  }
  get description_long() {
    return this._mintInfo.description_long;
  }
  get name() {
    return this._mintInfo.name;
  }
  get pubkey() {
    return this._mintInfo.pubkey;
  }
  get nuts() {
    return this._mintInfo.nuts;
  }
  get version() {
    return this._mintInfo.version;
  }
  get motd() {
    return this._mintInfo.motd;
  }
  /**
   * Checks if the mint supports creating BOLT12 offers with a description.
   *
   * @returns True if the mint supports offers with a description, false otherwise.
   */
  get supportsBolt12Description() {
    return this._mintInfo.nuts[4]?.methods.some(
      (t) => t.method === "bolt12" && t.options?.description === !0
    );
  }
}
class I {
  /**
   * @param _mintUrl Requires mint URL to create this object.
   * @param _customRequest If passed, use custom request implementation for network communication
   *   with the mint.
   * @param [authTokenGetter] A function that is called by the CashuMint instance to obtain a NUT-22
   *   BlindedAuthToken (e.g. from a database or localstorage)
   */
  constructor(t, e, n, s) {
    this._mintUrl = t, this._customRequest = e, this._checkNut22 = !1, this._mintUrl = zt(t), this._customRequest = e, n && (this._checkNut22 = !0, this._authTokenGetter = n), this._logger = s?.logger ?? x, De(this._logger);
  }
  //TODO: v3 - refactor CashuMint to take two or less args.
  get mintUrl() {
    return this._mintUrl;
  }
  /**
   * Fetches mints info at the /info endpoint.
   *
   * @param mintUrl
   * @param customRequest
   */
  static async getInfo(t, e, n) {
    const s = n ?? x, a = await (e || E)({
      endpoint: A(t, "/v1/info")
    });
    return Fe(a, s);
  }
  /**
   * Fetches mints info at the /info endpoint.
   */
  async getInfo() {
    return I.getInfo(this._mintUrl, this._customRequest, this._logger);
  }
  async getLazyMintInfo() {
    if (this._mintInfo)
      return this._mintInfo;
    const t = await I.getInfo(this._mintUrl, this._customRequest);
    return this._mintInfo = new yt(t), this._mintInfo;
  }
  /**
   * Performs a swap operation with ecash inputs and outputs.
   *
   * @param mintUrl
   * @param swapPayload Payload containing inputs and outputs.
   * @param customRequest
   * @returns Signed outputs.
   */
  static async swap(t, e, n, s) {
    const r = n || E, a = s ? { "Blind-auth": s } : {}, i = await r({
      endpoint: A(t, "/v1/swap"),
      method: "POST",
      requestBody: e,
      headers: a
    });
    if (!D(i) || !Array.isArray(i?.signatures))
      throw new Error(i.detail ?? "bad response");
    return i;
  }
  /**
   * Performs a swap operation with ecash inputs and outputs.
   *
   * @param swapPayload Payload containing inputs and outputs.
   * @returns Signed outputs.
   */
  async swap(t) {
    const e = await this.handleBlindAuth("/v1/swap");
    return I.swap(this._mintUrl, t, this._customRequest, e);
  }
  /**
   * Requests a new mint quote from the mint.
   *
   * @param mintUrl
   * @param mintQuotePayload Payload for creating a new mint quote.
   * @param customRequest
   * @returns The mint will create and return a new mint quote containing a payment request for the
   *   specified amount and unit.
   */
  static async createMintQuote(t, e, n, s, r) {
    const a = r ?? x, i = n || E, c = s ? { "Blind-auth": s } : {}, h = await i({
      endpoint: A(t, "/v1/mint/quote/bolt11"),
      method: "POST",
      requestBody: e,
      headers: c
    });
    return Kt(h, a);
  }
  /**
   * Requests a new mint quote from the mint.
   *
   * @param mintQuotePayload Payload for creating a new mint quote.
   * @returns The mint will create and return a new mint quote containing a payment request for the
   *   specified amount and unit.
   */
  async createMintQuote(t) {
    const e = await this.handleBlindAuth("/v1/mint/quote/bolt11");
    return I.createMintQuote(
      this._mintUrl,
      t,
      this._customRequest,
      e
    );
  }
  /**
   * Requests a new BOLT12 mint quote from the mint using Lightning Network offers.
   *
   * @param mintUrl The mint's base URL.
   * @param mintQuotePayload Payload containing amount, unit, optional description, and required
   *   pubkey.
   * @param customRequest Optional custom request implementation.
   * @param blindAuthToken Optional authentication token for NUT-22.
   * @returns A mint quote containing a BOLT12 offer.
   */
  static async createMintQuoteBolt12(t, e, n, s) {
    const r = n || E, a = s ? { "Blind-auth": s } : {};
    return await r({
      endpoint: A(t, "/v1/mint/quote/bolt12"),
      method: "POST",
      requestBody: e,
      headers: a
    });
  }
  /**
   * Requests a new BOLT12 mint quote from the mint using Lightning Network offers.
   *
   * @param mintQuotePayload Payload containing amount, unit, optional description, and required
   *   pubkey.
   * @returns A mint quote containing a BOLT12 offer.
   */
  async createMintQuoteBolt12(t) {
    const e = await this.handleBlindAuth("/v1/mint/quote/bolt12");
    return I.createMintQuoteBolt12(
      this._mintUrl,
      t,
      this._customRequest,
      e
    );
  }
  /**
   * Requests a new on-chain mint quote from the mint using Bitcoin on-chain payments.
   *
   * @param mintUrl The mint's base URL.
   * @param mintQuotePayload Payload containing unit and required pubkey for the on-chain quote.
   * @param customRequest Optional custom request implementation.
   * @param blindAuthToken Optional authentication token for NUT-22.
   * @returns A mint quote containing a Bitcoin address for on-chain payments.
   */
  static async createMintQuoteOnchain(t, e, n, s) {
    const r = n || E, a = s ? { "Blind-auth": s } : {};
    return await r({
      endpoint: A(t, "/v1/mint/quote/onchain"),
      method: "POST",
      requestBody: e,
      headers: a
    });
  }
  /**
   * Requests a new on-chain mint quote from the mint using Bitcoin on-chain payments.
   *
   * @param mintQuotePayload Payload containing unit and required pubkey for the on-chain quote.
   * @returns A mint quote containing a Bitcoin address for on-chain payments.
   */
  async createMintQuoteOnchain(t) {
    const e = await this.handleBlindAuth("/v1/mint/quote/onchain");
    return I.createMintQuoteOnchain(
      this._mintUrl,
      t,
      this._customRequest,
      e
    );
  }
  /**
   * Gets an existing mint quote from the mint.
   *
   * @param mintUrl
   * @param quote Quote ID.
   * @param customRequest
   * @returns The mint will create and return a Lightning invoice for the specified amount.
   */
  static async checkMintQuote(t, e, n, s, r) {
    const a = r ?? x, i = n || E, c = s ? { "Blind-auth": s } : {}, h = await i({
      endpoint: A(t, "/v1/mint/quote/bolt11", e),
      method: "GET",
      headers: c
    });
    return Kt(h, a);
  }
  /**
   * Gets an existing mint quote from the mint.
   *
   * @param quote Quote ID.
   * @returns The mint will create and return a Lightning invoice for the specified amount.
   */
  async checkMintQuote(t) {
    const e = await this.handleBlindAuth(`/v1/mint/quote/bolt11/${t}`);
    return I.checkMintQuote(this._mintUrl, t, this._customRequest, e);
  }
  /**
   * Gets an existing BOLT12 mint quote from the mint.
   *
   * @param mintUrl The mint's base URL.
   * @param quote Quote ID to check.
   * @param customRequest Optional custom request implementation.
   * @param blindAuthToken Optional authentication token for NUT-22.
   * @returns Updated quote with current payment and issuance amounts.
   */
  static async checkMintQuoteBolt12(t, e, n, s) {
    const r = n || E, a = s ? { "Blind-auth": s } : {};
    return await r({
      endpoint: A(t, "/v1/mint/quote/bolt12", e),
      method: "GET",
      headers: a
    });
  }
  /**
   * Gets an existing BOLT12 mint quote from the mint.
   *
   * @param quote Quote ID to check.
   * @returns Updated quote with current payment and issuance amounts.
   */
  async checkMintQuoteBolt12(t) {
    const e = await this.handleBlindAuth(`/v1/mint/quote/bolt12/${t}`);
    return I.checkMintQuoteBolt12(
      this._mintUrl,
      t,
      this._customRequest,
      e
    );
  }
  /**
   * Gets an existing on-chain mint quote from the mint.
   *
   * @param mintUrl The mint's base URL.
   * @param quote Quote ID to check.
   * @param customRequest Optional custom request implementation.
   * @param blindAuthToken Optional authentication token for NUT-22.
   * @returns Updated on-chain quote with current payment and issuance amounts.
   */
  static async checkMintQuoteOnchain(t, e, n, s) {
    const r = n || E, a = s ? { "Blind-auth": s } : {};
    return await r({
      endpoint: A(t, "/v1/mint/quote/onchain", e),
      method: "GET",
      headers: a
    });
  }
  /**
   * Gets an existing on-chain mint quote from the mint.
   *
   * @param quote Quote ID to check.
   * @returns Updated on-chain quote with current payment and issuance amounts.
   */
  async checkMintQuoteOnchain(t) {
    const e = await this.handleBlindAuth(`/v1/mint/quote/onchain/${t}`);
    return I.checkMintQuoteOnchain(
      this._mintUrl,
      t,
      this._customRequest,
      e
    );
  }
  /**
   * Mints new tokens by requesting blind signatures on the provided outputs.
   *
   * @param mintUrl
   * @param mintPayload Payload containing the outputs to get blind signatures on.
   * @param customRequest
   * @returns Serialized blinded signatures.
   */
  static async mint(t, e, n, s) {
    const r = n || E, a = s ? { "Blind-auth": s } : {}, i = await r({
      endpoint: A(t, "/v1/mint/bolt11"),
      method: "POST",
      requestBody: e,
      headers: a
    });
    if (!D(i) || !Array.isArray(i?.signatures))
      throw new Error("bad response");
    return i;
  }
  /**
   * Mints new tokens by requesting blind signatures on the provided outputs.
   *
   * @param mintPayload Payload containing the outputs to get blind signatures on.
   * @returns Serialized blinded signatures.
   */
  async mint(t) {
    const e = await this.handleBlindAuth("/v1/mint/bolt11");
    return I.mint(this._mintUrl, t, this._customRequest, e);
  }
  /**
   * Mints new tokens using a BOLT12 quote by requesting blind signatures on the provided outputs.
   *
   * @param mintUrl The mint's base URL.
   * @param mintPayload Payload containing the quote ID and outputs to get blind signatures on.
   * @param customRequest Optional custom request implementation.
   * @param blindAuthToken Optional authentication token for NUT-22.
   * @returns Serialized blinded signatures for the requested outputs.
   */
  static async mintBolt12(t, e, n, s) {
    const r = n || E, a = s ? { "Blind-auth": s } : {}, i = await r({
      endpoint: A(t, "/v1/mint/bolt12"),
      method: "POST",
      requestBody: e,
      headers: a
    });
    if (!D(i) || !Array.isArray(i?.signatures))
      throw new Error("bad response");
    return i;
  }
  /**
   * Mints new tokens using a BOLT12 quote by requesting blind signatures on the provided outputs.
   *
   * @param mintPayload Payload containing the quote ID and outputs to get blind signatures on.
   * @returns Serialized blinded signatures for the requested outputs.
   */
  async mintBolt12(t) {
    const e = await this.handleBlindAuth("/v1/mint/bolt12");
    return I.mintBolt12(this._mintUrl, t, this._customRequest, e);
  }
  /**
   * Mints new tokens using an on-chain quote by requesting blind signatures on the provided outputs.
   *
   * @param mintUrl The mint's base URL.
   * @param mintPayload Payload containing the quote ID and outputs to get blind signatures on.
   * @param customRequest Optional custom request implementation.
   * @param blindAuthToken Optional authentication token for NUT-22.
   * @returns Serialized blinded signatures for the requested outputs.
   */
  static async mintOnchain(t, e, n, s) {
    const r = n || E, a = s ? { "Blind-auth": s } : {}, i = await r({
      endpoint: A(t, "/v1/mint/onchain"),
      method: "POST",
      requestBody: e,
      headers: a
    });
    if (!D(i) || !Array.isArray(i?.signatures))
      throw new Error("bad response");
    return i;
  }
  /**
   * Mints new tokens using an on-chain quote by requesting blind signatures on the provided outputs.
   *
   * @param mintPayload Payload containing the quote ID and outputs to get blind signatures on.
   * @returns Serialized blinded signatures for the requested outputs.
   */
  async mintOnchain(t) {
    const e = await this.handleBlindAuth("/v1/mint/onchain");
    return I.mintOnchain(this._mintUrl, t, this._customRequest, e);
  }
  /**
   * Requests a new melt quote from the mint.
   *
   * @param mintUrl
   * @param MeltQuotePayload
   * @returns
   */
  static async createMeltQuote(t, e, n, s, r) {
    const a = r ?? x, i = n || E, c = s ? { "Blind-auth": s } : {}, h = await i({
      endpoint: A(t, "/v1/melt/quote/bolt11"),
      method: "POST",
      requestBody: e,
      headers: c
    }), u = dt(h, a);
    if (!D(u) || typeof u?.amount != "number" || typeof u?.fee_reserve != "number" || typeof u?.quote != "string")
      throw new Error("bad response");
    return u;
  }
  /**
   * Requests a new melt quote from the mint.
   *
   * @param MeltQuotePayload
   * @returns
   */
  async createMeltQuote(t) {
    const e = await this.handleBlindAuth("/v1/melt/quote/bolt11");
    return I.createMeltQuote(
      this._mintUrl,
      t,
      this._customRequest,
      e
    );
  }
  /**
   * Requests a new BOLT12 melt quote from the mint for paying a Lightning Network offer. For
   * amount-less offers, specify the amount in options.amountless.amount_msat.
   *
   * @param mintUrl The mint's base URL.
   * @param meltQuotePayload Payload containing the BOLT12 offer to pay and unit.
   * @param customRequest Optional custom request implementation.
   * @param blindAuthToken Optional authentication token for NUT-22.
   * @returns Melt quote with amount, fee reserve, and payment state.
   */
  static async createMeltQuoteBolt12(t, e, n, s) {
    const r = n || E, a = s ? { "Blind-auth": s } : {};
    return await r({
      endpoint: A(t, "/v1/melt/quote/bolt12"),
      method: "POST",
      requestBody: e,
      headers: a
    });
  }
  /**
   * Requests a new BOLT12 melt quote from the mint for paying a Lightning Network offer. For
   * amount-less offers, specify the amount in options.amountless.amount_msat.
   *
   * @param meltQuotePayload Payload containing the BOLT12 offer to pay and unit.
   * @returns Melt quote with amount, fee reserve, and payment state.
   */
  async createMeltQuoteBolt12(t) {
    const e = await this.handleBlindAuth("/v1/melt/quote/bolt12");
    return I.createMeltQuoteBolt12(
      this._mintUrl,
      t,
      this._customRequest,
      e
    );
  }
  /**
   * Requests a new on-chain melt quote from the mint for sending Bitcoin to an on-chain address.
   *
   * @param mintUrl The mint's base URL.
   * @param meltQuotePayload Payload containing the Bitcoin address to pay and amount.
   * @param customRequest Optional custom request implementation.
   * @param blindAuthToken Optional authentication token for NUT-22.
   * @returns Melt quote with amount, fee reserve, and payment state for on-chain transaction.
   */
  static async createMeltQuoteOnchain(t, e, n, s) {
    const r = n || E, a = s ? { "Blind-auth": s } : {};
    return await r({
      endpoint: A(t, "/v1/melt/quote/onchain"),
      method: "POST",
      requestBody: e,
      headers: a
    });
  }
  /**
   * Requests a new on-chain melt quote from the mint for sending Bitcoin to an on-chain address.
   *
   * @param meltQuotePayload Payload containing the Bitcoin address to pay and amount.
   * @returns Melt quote with amount, fee reserve, and payment state for on-chain transaction.
   */
  async createMeltQuoteOnchain(t) {
    const e = await this.handleBlindAuth("/v1/melt/quote/onchain");
    return I.createMeltQuoteOnchain(
      this._mintUrl,
      t,
      this._customRequest,
      e
    );
  }
  /**
   * Gets an existing melt quote.
   *
   * @param mintUrl
   * @param quote Quote ID.
   * @returns
   */
  static async checkMeltQuote(t, e, n, s, r) {
    const a = r ?? x, i = n || E, c = s ? { "Blind-auth": s } : {}, h = await i({
      endpoint: A(t, "/v1/melt/quote/bolt11", e),
      method: "GET",
      headers: c
    }), u = dt(h, a);
    if (!D(u) || typeof u?.amount != "number" || typeof u?.fee_reserve != "number" || typeof u?.quote != "string" || typeof u?.state != "string" || !Object.values(tt).includes(u.state))
      throw new Error("bad response");
    return u;
  }
  /**
   * Gets an existing melt quote.
   *
   * @param quote Quote ID.
   * @returns
   */
  async checkMeltQuote(t) {
    const e = await this.handleBlindAuth(`/v1/melt/quote/bolt11/${t}`);
    return I.checkMeltQuote(this._mintUrl, t, this._customRequest, e);
  }
  /**
   * Gets an existing BOLT12 melt quote from the mint. Returns current payment state (UNPAID,
   * PENDING, or PAID) and payment preimage if paid.
   *
   * @param mintUrl The mint's base URL.
   * @param quote Quote ID to check.
   * @param customRequest Optional custom request implementation.
   * @param blindAuthToken Optional authentication token for NUT-22.
   * @returns Updated quote with current payment state and preimage if available.
   */
  static async checkMeltQuoteBolt12(t, e, n, s) {
    const r = n || E, a = s ? { "Blind-auth": s } : {};
    return await r({
      endpoint: A(t, "/v1/melt/quote/bolt12", e),
      method: "GET",
      headers: a
    });
  }
  /**
   * Gets an existing BOLT12 melt quote from the mint. Returns current payment state (UNPAID,
   * PENDING, or PAID) and payment preimage if paid.
   *
   * @param quote Quote ID to check.
   * @returns Updated quote with current payment state and preimage if available.
   */
  async checkMeltQuoteBolt12(t) {
    const e = await this.handleBlindAuth(`/v1/melt/quote/bolt12/${t}`);
    return I.checkMeltQuoteBolt12(
      this._mintUrl,
      t,
      this._customRequest,
      e
    );
  }
  /**
   * Gets an existing on-chain melt quote from the mint. Returns current payment state (UNPAID,
   * PENDING, or PAID) and transaction ID if paid.
   *
   * @param mintUrl The mint's base URL.
   * @param quote Quote ID to check.
   * @param customRequest Optional custom request implementation.
   * @param blindAuthToken Optional authentication token for NUT-22.
   * @returns Updated on-chain quote with current payment state and transaction ID if available.
   */
  static async checkMeltQuoteOnchain(t, e, n, s) {
    const r = n || E, a = s ? { "Blind-auth": s } : {};
    return await r({
      endpoint: A(t, "/v1/melt/quote/onchain", e),
      method: "GET",
      headers: a
    });
  }
  /**
   * Gets an existing on-chain melt quote from the mint. Returns current payment state (UNPAID,
   * PENDING, or PAID) and transaction ID if paid.
   *
   * @param quote Quote ID to check.
   * @returns Updated on-chain quote with current payment state and transaction ID if available.
   */
  async checkMeltQuoteOnchain(t) {
    const e = await this.handleBlindAuth(`/v1/melt/quote/onchain/${t}`);
    return I.checkMeltQuoteOnchain(
      this._mintUrl,
      t,
      this._customRequest,
      e
    );
  }
  /**
   * Requests the mint to pay for a Bolt11 payment request by providing ecash as inputs to be spent.
   * The inputs contain the amount and the fee_reserves for a Lightning payment. The payload can
   * also contain blank outputs in order to receive back overpaid Lightning fees.
   *
   * @param mintUrl
   * @param meltPayload
   * @param customRequest
   * @returns
   */
  static async melt(t, e, n, s, r) {
    const a = r ?? x, i = n || E, c = s ? { "Blind-auth": s } : {}, h = await i({
      endpoint: A(t, "/v1/melt/bolt11"),
      method: "POST",
      requestBody: e,
      headers: c
    }), u = dt(h, a);
    if (!D(u) || typeof u?.state != "string" || !Object.values(tt).includes(u.state))
      throw new Error("bad response");
    return u;
  }
  /**
   * Ask mint to perform a melt operation. This pays a lightning invoice and destroys tokens
   * matching its amount + fees.
   *
   * @param meltPayload
   * @returns
   */
  async melt(t) {
    const e = await this.handleBlindAuth("/v1/melt/bolt11");
    return I.melt(this._mintUrl, t, this._customRequest, e);
  }
  /**
   * Requests the mint to pay a BOLT12 offer by providing ecash inputs to be spent. The inputs must
   * cover the amount plus fee reserves. Optional outputs can be included to receive change for
   * overpaid Lightning fees.
   *
   * @param mintUrl The mint's base URL.
   * @param meltPayload Payload containing quote ID, inputs, and optional outputs for change.
   * @param customRequest Optional custom request implementation.
   * @param blindAuthToken Optional authentication token for NUT-22.
   * @returns Payment result with state and optional change signatures.
   */
  static async meltBolt12(t, e, n, s) {
    const r = n || E, a = s ? { "Blind-auth": s } : {};
    return await r({
      endpoint: A(t, "/v1/melt/bolt12"),
      method: "POST",
      requestBody: e,
      headers: a
    });
  }
  /**
   * Requests the mint to pay a BOLT12 offer by providing ecash inputs to be spent. The inputs must
   * cover the amount plus fee reserves. Optional outputs can be included to receive change for
   * overpaid Lightning fees.
   *
   * @param meltPayload Payload containing quote ID, inputs, and optional outputs for change.
   * @returns Payment result with state and optional change signatures.
   */
  async meltBolt12(t) {
    const e = await this.handleBlindAuth("/v1/melt/bolt12");
    return I.meltBolt12(this._mintUrl, t, this._customRequest, e);
  }
  /**
   * Requests the mint to send Bitcoin to an on-chain address by providing ecash inputs to be spent.
   * The inputs must cover the amount plus fee reserves. Optional outputs can be included to receive
   * change for overpaid transaction fees.
   *
   * @param mintUrl The mint's base URL.
   * @param meltPayload Payload containing quote ID, inputs, and optional outputs for change.
   * @param customRequest Optional custom request implementation.
   * @param blindAuthToken Optional authentication token for NUT-22.
   * @returns Payment result with state and optional change signatures.
   */
  static async meltOnchain(t, e, n, s) {
    const r = n || E, a = s ? { "Blind-auth": s } : {};
    return await r({
      endpoint: A(t, "/v1/melt/onchain"),
      method: "POST",
      requestBody: e,
      headers: a
    });
  }
  /**
   * Requests the mint to send Bitcoin to an on-chain address by providing ecash inputs to be spent.
   * The inputs must cover the amount plus fee reserves. Optional outputs can be included to receive
   * change for overpaid transaction fees.
   *
   * @param meltPayload Payload containing quote ID, inputs, and optional outputs for change.
   * @returns Payment result with state and optional change signatures.
   */
  async meltOnchain(t) {
    const e = await this.handleBlindAuth("/v1/melt/onchain");
    return I.meltOnchain(this._mintUrl, t, this._customRequest, e);
  }
  /**
   * Checks if specific proofs have already been redeemed.
   *
   * @param mintUrl
   * @param checkPayload
   * @param customRequest
   * @returns Redeemed and unredeemed ordered list of booleans.
   */
  static async check(t, e, n) {
    const r = await (n || E)({
      endpoint: A(t, "/v1/checkstate"),
      method: "POST",
      requestBody: e
    });
    if (!D(r) || !Array.isArray(r?.states))
      throw new Error("bad response");
    return r;
  }
  /**
   * Get the mints public keys.
   *
   * @param mintUrl
   * @param keysetId Optional param to get the keys for a specific keyset. If not specified, the
   *   keys from all active keysets are fetched.
   * @param customRequest
   * @returns
   */
  static async getKeys(t, e, n) {
    e && (e = e.replace(/\//g, "_").replace(/\+/g, "-"));
    const r = await (n || E)({
      endpoint: e ? A(t, "/v1/keys", e) : A(t, "/v1/keys")
    });
    if (!D(r) || !Array.isArray(r.keysets))
      throw new Error("bad response");
    return r;
  }
  /**
   * Get the mints public keys.
   *
   * @param keysetId Optional param to get the keys for a specific keyset. If not specified, the
   *   keys from all active keysets are fetched.
   * @returns The mints public keys.
   */
  async getKeys(t, e) {
    return await I.getKeys(
      e || this._mintUrl,
      t,
      this._customRequest
    );
  }
  /**
   * Get the mints keysets in no specific order.
   *
   * @param mintUrl
   * @param customRequest
   * @returns All the mints past and current keysets.
   */
  static async getKeySets(t, e) {
    return (e || E)({ endpoint: A(t, "/v1/keysets") });
  }
  /**
   * Get the mints keysets in no specific order.
   *
   * @returns All the mints past and current keysets.
   */
  async getKeySets() {
    return I.getKeySets(this._mintUrl, this._customRequest);
  }
  /**
   * Checks if specific proofs have already been redeemed.
   *
   * @param checkPayload
   * @returns Redeemed and unredeemed ordered list of booleans.
   */
  async check(t) {
    return I.check(this._mintUrl, t, this._customRequest);
  }
  static async restore(t, e, n) {
    const r = await (n || E)({
      endpoint: A(t, "/v1/restore"),
      method: "POST",
      requestBody: e
    });
    if (!D(r) || !Array.isArray(r?.outputs) || !Array.isArray(r?.signatures))
      throw new Error("bad response");
    return r;
  }
  async restore(t) {
    return I.restore(this._mintUrl, t, this._customRequest);
  }
  /**
   * Tries to establish a websocket connection with the websocket mint url according to NUT-17.
   */
  async connectWebSocket() {
    if (this.ws)
      await this.ws.ensureConnection();
    else {
      const t = new URL(this._mintUrl), e = "v1/ws";
      t.pathname && (t.pathname.endsWith("/") ? t.pathname += e : t.pathname += "/" + e), this.ws = H.getInstance().getConnection(
        `${t.protocol === "https:" ? "wss" : "ws"}://${t.host}${t.pathname}`
      );
      try {
        await this.ws.connect();
      } catch (n) {
        throw this._logger.error("Failed to connect to WebSocket...", { e: n }), new Error("Failed to connect to WebSocket...");
      }
    }
  }
  /**
   * Closes a websocket connection.
   */
  disconnectWebSocket() {
    this.ws && this.ws.close();
  }
  get webSocketConnection() {
    return this.ws;
  }
  async handleBlindAuth(t) {
    if (!this._checkNut22)
      return;
    if ((await this.getLazyMintInfo()).requiresBlindAuthToken(t)) {
      if (!this._authTokenGetter)
        throw new Error("Can not call a protected endpoint without authProofGetter");
      return this._authTokenGetter();
    }
  }
}
class ft {
  constructor(t, e, n) {
    this.amount = t, this.B_ = e, this.id = n;
  }
  getSerializedBlindedMessage() {
    return { amount: this.amount, B_: this.B_.toHex(!0), id: this.id };
  }
}
function mt(o) {
  return typeof o == "function";
}
class Q {
  constructor(t, e, n) {
    this.secret = n, this.blindingFactor = e, this.blindedMessage = t;
  }
  toProof(t, e) {
    let n;
    t.dleq && (n = {
      s: qt(t.dleq.s),
      e: qt(t.dleq.e),
      r: this.blindingFactor
    });
    const s = {
      id: t.id,
      amount: t.amount,
      C_: rt(t.C_)
    }, r = rt(e.keys[t.amount]), a = Zt(s, this.blindingFactor, this.secret, r);
    return {
      ...te(a),
      ...n && {
        dleq: {
          s: X(n.s),
          e: X(n.e),
          r: Ae(n.r ?? BigInt(0))
        }
      }
    };
  }
  static createP2PKData(t, e, n, s) {
    return R(e, n.keys, s).map((a) => this.createSingleP2PKData(t, a, n.id));
  }
  static createSingleP2PKData(t, e, n) {
    const s = Array.isArray(t.pubkey) ? t.pubkey : [t.pubkey], r = Math.max(1, Math.min(t.requiredSignatures || 1, s.length)), a = Math.max(
      1,
      Math.min(t.requiredRefundSignatures || 1, t.refundKeys ? t.refundKeys.length : 1)
    ), i = [
      "P2PK",
      {
        nonce: X(Bt(32)),
        data: s[0],
        // Primary key
        tags: []
      }
    ];
    t.locktime && i[1].tags.push(["locktime", String(t.locktime)]), s.length > 1 && (i[1].tags.push(["pubkeys", ...s.slice(1)]), r > 1 && i[1].tags.push(["n_sigs", String(r)])), t.refundKeys && (i[1].tags.push(["refund", ...t.refundKeys]), a > 1 && i[1].tags.push(["n_sigs_refund", String(a)]));
    const c = JSON.stringify(i), h = new TextEncoder().encode(c), { r: u, B_: f } = ht(h);
    return new Q(
      new ft(e, f, n).getSerializedBlindedMessage(),
      u,
      h
    );
  }
  static createRandomData(t, e, n) {
    return R(t, e.keys, n).map((r) => this.createSingleRandomData(r, e.id));
  }
  static createSingleRandomData(t, e) {
    const n = X(Bt(32)), s = new TextEncoder().encode(n), { r, B_: a } = ht(s);
    return new Q(
      new ft(t, a, e).getSerializedBlindedMessage(),
      r,
      s
    );
  }
  static createDeterministicData(t, e, n, s, r) {
    return R(t, s.keys, r).map(
      (i, c) => this.createSingleDeterministicData(i, e, n + c, s.id)
    );
  }
  static createSingleDeterministicData(t, e, n, s) {
    const r = ee(e, s, n), a = X(r), i = new TextEncoder().encode(a), c = be(ne(e, s, n)), { r: h, B_: u } = ht(i, c);
    return new Q(
      new ft(t, u, s).getSerializedBlindedMessage(),
      h,
      i
    );
  }
}
const Qe = 3, Ne = "sat";
class an {
  /**
   * @param mint Cashu mint instance is used to make api calls.
   * @param options.unit Optionally set unit (default is 'sat')
   * @param options.keys Public keys from the mint (will be fetched from mint if not provided)
   * @param options.keysets Keysets from the mint (will be fetched from mint if not provided)
   * @param options.mintInfo Mint info from the mint (will be fetched from mint if not provided)
   * @param options.denominationTarget Target number proofs per denomination (default: see @constant
   *   DEFAULT_DENOMINATION_TARGET)
   * @param options.bip39seed BIP39 seed for deterministic secrets.
   * @param options.keepFactory A function that will be used by all parts of the library that
   *   produce proofs to be kept (change, etc.). This can lead to poor performance, in which case
   *   the seed should be directly provided.
   */
  constructor(t, e) {
    this._keys = /* @__PURE__ */ new Map(), this._keysets = [], this._seed = void 0, this._unit = Ne, this._mintInfo = void 0, this._denominationTarget = Qe, this.mint = t, this._logger = e?.logger ?? x;
    let n = [];
    if (e?.keys && !Array.isArray(e.keys) ? n = [e.keys] : e?.keys && Array.isArray(e?.keys) && (n = e?.keys), n && n.forEach((s) => this._keys.set(s.id, s)), e?.unit && (this._unit = e?.unit), e?.keysets && (this._keysets = e.keysets), e?.mintInfo && (this._mintInfo = new yt(e.mintInfo)), e?.denominationTarget && (this._denominationTarget = e.denominationTarget), e?.bip39seed) {
      if (e.bip39seed instanceof Uint8Array) {
        this._seed = e.bip39seed;
        return;
      }
      throw new Error("bip39seed must be a valid UInt8Array");
    }
    e?.keepFactory && (this._keepFactory = e.keepFactory);
  }
  get unit() {
    return this._unit;
  }
  get keys() {
    return this._keys;
  }
  get keysetId() {
    if (!this._keysetId)
      throw new Error("No keysetId set");
    return this._keysetId;
  }
  set keysetId(t) {
    this._keysetId = t;
  }
  get keysets() {
    return this._keysets;
  }
  get mintInfo() {
    if (!this._mintInfo)
      throw new Error("Mint info not loaded");
    return this._mintInfo;
  }
  /**
   * Get information about the mint.
   *
   * @returns Mint info.
   */
  async getMintInfo() {
    const t = await this.mint.getInfo();
    return this._mintInfo = new yt(t), this._mintInfo;
  }
  /**
   * Get stored information about the mint or request it if not loaded.
   *
   * @returns Mint info.
   */
  async lazyGetMintInfo() {
    return this._mintInfo ? this._mintInfo : await this.getMintInfo();
  }
  /**
   * Load mint information, keysets and keys. This function can be called if no keysets are passed
   * in the constructor.
   */
  async loadMint() {
    await this.getMintInfo(), await this.getKeySets(), await this.getKeys();
  }
  /**
   * Choose a keyset to activate based on the lowest input fee.
   *
   * Note: this function will filter out deprecated base64 keysets.
   *
   * @param keysets Keysets to choose from.
   * @returns Active keyset.
   */
  getActiveKeyset(t) {
    let e = t.filter((s) => s.active && s.unit === this._unit);
    e = e.filter((s) => s.id.startsWith("00"));
    const n = e.sort(
      (s, r) => (s.input_fee_ppk ?? 0) - (r.input_fee_ppk ?? 0)
    )[0];
    if (!n)
      throw new Error("No active keyset found");
    return n;
  }
  /**
   * Get keysets from the mint with the unit of the wallet.
   *
   * @returns Keysets with wallet's unit.
   */
  async getKeySets() {
    const e = (await this.mint.getKeySets()).keysets.filter((n) => n.unit === this._unit);
    return this._keysets = e, this._keysets;
  }
  /**
   * Get all active keys from the mint and set the keyset with the lowest fees as the active wallet
   * keyset.
   *
   * @returns Keyset.
   */
  async getAllKeys() {
    const t = await this.mint.getKeys();
    return t.keysets.forEach((e) => {
      if (!Tt(e))
        throw new Error(`Couldn't verify keyset ID ${e.id}`);
    }), this._keys = new Map(t.keysets.map((e) => [e.id, e])), this.keysetId = this.getActiveKeyset(this._keysets).id, t.keysets;
  }
  /**
   * Get public keys from the mint. If keys were already fetched, it will return those.
   *
   * If `keysetId` is set, it will fetch and return that specific keyset. Otherwise, we select an
   * active keyset with the unit of the wallet.
   *
   * @param keysetId Optional keysetId to get keys for.
   * @param forceRefresh? If set to true, it will force refresh the keyset from the mint.
   * @returns Keyset.
   */
  async getKeys(t, e) {
    if ((!(this._keysets.length > 0) || e) && await this.getKeySets(), t || (t = this.getActiveKeyset(this._keysets).id), !this._keysets.find((n) => n.id === t) && (await this.getKeySets(), !this._keysets.find((n) => n.id === t)))
      throw new Error(`could not initialize keys. No keyset with id '${t}' found`);
    if (!this._keys.get(t)) {
      const n = await this.mint.getKeys(t);
      if (!Tt(n.keysets[0]))
        throw new Error(`Couldn't verify keyset ID ${n.keysets[0].id}`);
      this._keys.set(t, n.keysets[0]);
    }
    return this.keysetId = t, this._keys.get(t);
  }
  /**
   * Receive an encoded or raw Cashu token (only supports single tokens. It will only process the
   * first token in the token array)
   *
   * @param {string | Token} token - Cashu token, either as string or decoded.
   * @param {ReceiveOptions} [options] - Optional configuration for token processing.
   * @returns New token with newly created proofs, token entries that had errors.
   */
  async receive(t, e) {
    const { requireDleq: n, keysetId: s, outputAmounts: r, counter: a, pubkey: i, privkey: c, outputData: h, p2pk: u } = e || {};
    this._keysets.length === 0 && await this.getKeySets(), typeof t == "string" && (t = Se(t, this._keysets));
    const f = await this.getKeys(s);
    if (n && t.proofs.some((k) => !Gt(k, f)))
      throw new Error("Token contains proofs with invalid DLEQ");
    const d = j(t.proofs) - this.getFeesForProofs(t.proofs);
    let l;
    h ? l = { send: h } : this._keepFactory && (l = { send: this._keepFactory });
    const m = this.createSwapPayload(
      d,
      t.proofs,
      f,
      r,
      a,
      i,
      c,
      l,
      u
    ), { signatures: P } = await this.mint.swap(m.payload), T = m.outputData.map((k, g) => k.toProof(P[g], f)), b = [];
    return m.sortedIndices.forEach((k, g) => {
      b[k] = T[g];
    }), b;
  }
  /**
   * Send proofs of a given amount, by providing at least the required amount of proofs.
   *
   * @param amount Amount to send.
   * @param proofs Array of proofs (accumulated amount of proofs must be >= than amount)
   * @param {SendOptions} [options] - Optional parameters for configuring the send operation.
   * @returns {SendResponse}
   */
  async send(t, e, n) {
    const {
      offline: s,
      includeFees: r,
      includeDleq: a,
      keysetId: i,
      outputAmounts: c,
      pubkey: h,
      privkey: u,
      outputData: f
    } = n || {};
    if (a && (e = e.filter((P) => P.dleq != null)), j(e) < t)
      throw new Error("Not enough funds available to send");
    const { keep: d, send: l } = this.selectProofsToSend(
      e,
      t,
      n?.includeFees
    ), m = r ? this.getFeesForProofs(l) : 0;
    if (!s && (j(l) != t + m || // if the exact amount cannot be selected
    c || h || u || i || f)) {
      const P = await this.swap(t, e, n), { keep: T, send: b } = P, k = P.serialized;
      return { keep: T, send: b, serialized: k };
    }
    if (j(l) < t + m)
      throw new Error("Not enough funds available to send");
    return { keep: d, send: l };
  }
  /**
   * Selects proofs to send based on amount and fee inclusion.
   *
   * @remarks
   * Uses an adapted Randomized Greedy with Local Improvement (RGLI) algorithm, which has a time
   * complexity O(n log n) and space complexity O(n).
   * @param proofs Array of Proof objects available to select from.
   * @param amountToSend The target amount to send.
   * @param includeFees Optional boolean to include fees; Default: false.
   * @returns SendResponse containing proofs to keep and proofs to send.
   * @see https://crypto.ethz.ch/publications/files/Przyda02.pdf
   */
  selectProofsToSend(t, e, n = !1) {
    const u = Re();
    let f = null, d = 1 / 0, l = 0, m = 0;
    const P = (y, p) => y - (n ? Math.ceil(p / 1e3) : 0), T = (y) => {
      const p = [...y];
      for (let _ = p.length - 1; _ > 0; _--) {
        const w = Math.floor(Math.random() * (_ + 1));
        [p[_], p[w]] = [p[w], p[_]];
      }
      return p;
    }, b = (y, p, _) => {
      let w = 0, S = y.length - 1, M = null;
      for (; w <= S; ) {
        const W = Math.floor((w + S) / 2), $ = y[W].exFee;
        (_ ? $ <= p : $ >= p) ? (M = W, _ ? w = W + 1 : S = W - 1) : _ ? S = W - 1 : w = W + 1;
      }
      return _ ? M : w < y.length ? w : null;
    }, k = (y, p) => {
      const _ = p.exFee;
      let w = 0, S = y.length;
      for (; w < S; ) {
        const M = Math.floor((w + S) / 2);
        y[M].exFee < _ ? w = M + 1 : S = M;
      }
      y.splice(w, 0, p);
    }, g = (y, p) => P(y, p) < e ? 1 / 0 : y + p / 1e3 - e;
    let v = 0, N = 0;
    const nt = t.map((y) => {
      const p = this.getProofFeePPK(y), _ = n ? y.amount - p / 1e3 : y.amount, w = { proof: y, exFee: _, ppkfee: p };
      return (!n || _ > 0) && (v += y.amount, N += p), w;
    });
    let q = n ? nt.filter((y) => y.exFee > 0) : nt;
    if (q.sort((y, p) => y.exFee - p.exFee), q.length > 0) {
      let y;
      {
        const p = b(q, e, !1);
        if (p !== null) {
          const _ = q[p].exFee, w = b(q, _, !0);
          if (w === null)
            throw new Error("Unexpected null rightIndex in binary search");
          y = w + 1;
        } else
          y = q.length;
      }
      for (let p = y; p < q.length; p++)
        v -= q[p].proof.amount, N -= q[p].ppkfee;
      q = q.slice(0, y);
    }
    const st = P(v, N);
    if (e <= 0 || e > st)
      return { keep: t, send: [] };
    const J = Math.min(
      Math.ceil(e * (1 + 0 / 100)),
      e + 0,
      st
    );
    for (let y = 0; y < 60; y++) {
      const p = [];
      let _ = 0, w = 0;
      for (const O of T(q)) {
        const U = _ + O.proof.amount, K = w + O.ppkfee, C = P(U, K);
        if (p.push(O), _ = U, w = K, C >= e) break;
      }
      const S = new Set(p), M = q.filter((O) => !S.has(O)), W = T(Array.from({ length: p.length }, (O, U) => U)).slice(
        0,
        5e3
      );
      for (const O of W) {
        const U = P(_, w);
        if (U === e || U >= e && U <= J)
          break;
        const K = p[O], C = _ - K.proof.amount, z = w - K.ppkfee, Jt = P(C, z), Pt = e - Jt, ut = b(M, Pt, !1);
        if (ut !== null) {
          const ot = M[ut];
          (Pt >= 0 || ot.exFee <= K.exFee) && (p[O] = ot, _ = C + ot.proof.amount, w = z + ot.ppkfee, M.splice(ut, 1), k(M, K));
        }
      }
      const $ = g(_, w);
      if ($ < d) {
        this._logger.debug(
          "selectProofsToSend: best solution found in trial #{trial} - amount: {amount}, delta: {delta}",
          { trial: y, amount: _, delta: $ }
        ), f = [...p].sort((U, K) => K.exFee - U.exFee), d = $, l = _, m = w;
        const O = [...f];
        for (; O.length > 1 && d > 0; ) {
          const U = O.pop(), K = _ - U.proof.amount, C = w - U.ppkfee, z = g(K, C);
          if (z == 1 / 0) break;
          z < d && (f = [...O], d = z, l = K, m = C, _ = K, w = C);
        }
      }
      if (f && d < 1 / 0) {
        const O = P(l, m);
        if (O === e || O >= e && O <= J)
          break;
      }
      if (u.elapsed() > 1e3) {
        this._logger.warn("Proof selection took too long. Returning best selection so far.");
        break;
      }
    }
    if (f && d < 1 / 0) {
      const y = f.map((w) => w.proof), p = new Set(y), _ = t.filter((w) => !p.has(w));
      return this._logger.info("Proof selection took {time}ms", { time: u.elapsed() }), { keep: _, send: y };
    }
    return { keep: t, send: [] };
  }
  /**
   * Calculates the fees based on inputs (proofs)
   *
   * @param proofs Input proofs to calculate fees for.
   * @returns Fee amount.
   * @throws Throws an error if the proofs keyset is unknown.
   */
  getFeesForProofs(t) {
    const e = t.reduce((n, s) => n + this.getProofFeePPK(s), 0);
    return Math.ceil(e / 1e3);
  }
  /**
   * Returns the current fee PPK for a proof according to the cached keyset.
   *
   * @param proof {Proof} A single proof.
   * @returns FeePPK {number} The feePPK for the selected proof.
   * @throws Throws an error if the proofs keyset is unknown.
   */
  getProofFeePPK(t) {
    const e = this._keysets.find((n) => n.id === t.id);
    if (!e)
      throw new Error(`Could not get fee. No keyset found for keyset id: ${t.id}`);
    return e?.input_fee_ppk || 0;
  }
  /**
   * Calculates the fees based on inputs for a given keyset.
   *
   * @param nInputs Number of inputs.
   * @param keysetId KeysetId used to lookup `input_fee_ppk`
   * @returns Fee amount.
   */
  getFeesForKeyset(t, e) {
    return Math.floor(
      Math.max(
        (t * (this._keysets.find((s) => s.id === e)?.input_fee_ppk || 0) + 999) / 1e3,
        0
      )
    );
  }
  /**
   * Splits and creates sendable tokens if no amount is specified, the amount is implied by the
   * cumulative amount of all proofs if both amount and preference are set, but the preference
   * cannot fulfill the amount, then we use the default split.
   *
   * @param {SwapOptions} [options] - Optional parameters for configuring the swap operation.
   * @returns Promise of the change- and send-proofs.
   */
  async swap(t, e, n) {
    let { outputAmounts: s } = n || {};
    const { includeFees: r, keysetId: a, counter: i, pubkey: c, privkey: h, proofsWeHave: u, outputData: f, p2pk: d } = n || {}, l = await this.getKeys(a);
    let m = t;
    const P = j(e);
    let T = s?.sendAmounts || R(m, l.keys);
    if (r) {
      let S = this.getFeesForKeyset(T.length, l.id), M = R(S, l.keys);
      for (; this.getFeesForKeyset(T.concat(M).length, l.id) > S; )
        S++, M = R(S, l.keys);
      T = T.concat(M), m += S;
    }
    const { keep: b, send: k } = this.selectProofsToSend(
      e,
      m,
      !0
      // inc. fees
    ), g = j(k) - this.getFeesForProofs(k) - m;
    if (g < 0)
      throw new Error("Not enough balance to send");
    let v;
    if (!s?.keepAmounts && !u)
      v = R(g, l.keys);
    else if (!s?.keepAmounts && u)
      v = vt(
        u,
        g,
        l.keys,
        this._denominationTarget
      );
    else if (s) {
      if (s.keepAmounts?.reduce((S, M) => S + M, 0) != g)
        throw new Error("Keep amounts do not match amount to keep");
      v = s.keepAmounts;
    }
    if (m + this.getFeesForProofs(k) > P)
      throw this._logger.error(
        `Not enough funds available (${P}) for swap amountToSend: ${m} + fee: ${this.getFeesForProofs(
          k
        )} | length: ${k.length}`
      ), new Error("Not enough funds available for swap");
    s = {
      keepAmounts: v,
      sendAmounts: T
    };
    const N = f?.keep || this._keepFactory, nt = f?.send, q = this.createSwapPayload(
      m,
      k,
      l,
      s,
      i,
      c,
      h,
      { keep: N, send: nt },
      d
    ), { signatures: st } = await this.mint.swap(q.payload), J = q.outputData.map((S, M) => S.toProof(st[M], l)), y = [], p = [], _ = Array(q.keepVector.length), w = Array(J.length);
    return q.sortedIndices.forEach((S, M) => {
      _[S] = q.keepVector[M], w[S] = J[M];
    }), w.forEach((S, M) => {
      _[M] ? y.push(S) : p.push(S);
    }), {
      keep: [...y, ...b],
      send: p
    };
  }
  /**
   * Restores batches of deterministic proofs until no more signatures are returned from the mint.
   *
   * @param [gapLimit=300] The amount of empty counters that should be returned before restoring
   *   ends (defaults to 300). Default is `300`
   * @param [batchSize=100] The amount of proofs that should be restored at a time (defaults to
   *   100). Default is `100`
   * @param [counter=0] The counter that should be used as a starting point (defaults to 0). Default
   *   is `0`
   * @param [keysetId] Which keysetId to use for the restoration. If none is passed the instance's
   *   default one will be used.
   */
  async batchRestore(t = 300, e = 100, n = 0, s) {
    const r = Math.ceil(t / e), a = [];
    let i, c = 0;
    for (; c < r; ) {
      const h = await this.restore(n, e, { keysetId: s });
      h.proofs.length > 0 ? (c = 0, a.push(...h.proofs), i = h.lastCounterWithSignature) : c++, n += e;
    }
    return { proofs: a, lastCounterWithSignature: i };
  }
  /**
   * Regenerates.
   *
   * @param start Set starting point for count (first cycle for each keyset should usually be 0)
   * @param count Set number of blinded messages that should be generated.
   * @param options.keysetId Set a custom keysetId to restore from. keysetIds can be loaded with
   *   `CashuMint.getKeySets()`
   */
  async restore(t, e, n) {
    const { keysetId: s } = n || {}, r = await this.getKeys(s);
    if (!this._seed)
      throw new Error("CashuWallet must be initialized with a seed to use restore");
    const a = Array(e).fill(1), i = Q.createDeterministicData(
      a.length,
      this._seed,
      t,
      r,
      a
    ), { outputs: c, signatures: h } = await this.mint.restore({
      outputs: i.map((l) => l.blindedMessage)
    }), u = {};
    c.forEach((l, m) => u[l.B_] = h[m]);
    const f = [];
    let d;
    for (let l = 0; l < i.length; l++) {
      const m = u[i[l].blindedMessage.B_];
      m && (d = t + l, i[l].blindedMessage.amount = m.amount, f.push(i[l].toProof(m, r)));
    }
    return {
      proofs: f,
      lastCounterWithSignature: d
    };
  }
  /**
   * Requests a mint quote from the mint. Response returns a Lightning payment request for the
   * requested given amount and unit.
   *
   * @param amount Amount requesting for mint.
   * @param description Optional description for the mint quote.
   * @param pubkey Optional public key to lock the quote to.
   * @returns The mint will return a mint quote with a Lightning invoice for minting tokens of the
   *   specified amount and unit.
   */
  async createMintQuote(t, e) {
    const n = {
      unit: this._unit,
      amount: t,
      description: e
    }, s = await this.mint.createMintQuote(n);
    return { ...s, amount: s.amount || t, unit: s.unit || this.unit };
  }
  /**
   * Requests a mint quote from the mint that is locked to a public key.
   *
   * @param amount Amount requesting for mint.
   * @param pubkey Public key to lock the quote to.
   * @param description Optional description for the mint quote.
   * @returns The mint will return a mint quote with a Lightning invoice for minting tokens of the
   *   specified amount and unit. The quote will be locked to the specified `pubkey`.
   */
  async createLockedMintQuote(t, e, n) {
    const { supported: s } = (await this.getMintInfo()).isSupported(20);
    if (!s)
      throw new Error("Mint does not support NUT-20");
    const r = {
      unit: this._unit,
      amount: t,
      description: n,
      pubkey: e
    }, a = await this.mint.createMintQuote(r);
    if (typeof a.pubkey != "string")
      throw new Error("Mint returned unlocked mint quote");
    {
      const i = a.pubkey;
      return { ...a, pubkey: i, amount: a.amount || t, unit: a.unit || this.unit };
    }
  }
  /**
   * Requests a mint quote from the mint. Response returns a Lightning BOLT12 offer for the
   * requested given amount and unit.
   *
   * @param pubkey Public key to lock the quote to.
   * @param options.amount BOLT12 offer amount requesting for mint. If not specified, the offer will
   *   be amountless.
   * @param options.description Description for the mint quote.
   * @returns The mint will return a mint quote with a Lightning invoice for minting tokens of the
   *   specified amount and unit.
   */
  async createMintQuoteBolt12(t, e) {
    const n = await this.lazyGetMintInfo();
    if (e?.description && !n.supportsBolt12Description)
      throw new Error("Mint does not support description for bolt12");
    const s = {
      pubkey: t,
      unit: this._unit,
      amount: e?.amount,
      description: e?.description
    };
    return this.mint.createMintQuoteBolt12(s);
  }
  /**
   * Requests a mint quote from the mint. Response returns a Bitcoin address for the
   * requested given amount and unit for on-chain payments.
   *
   * @param pubkey Public key to lock the quote to.
   * @returns The mint will return a mint quote with a Bitcoin address for minting tokens of the
   *   specified amount and unit via on-chain Bitcoin payments.
   */
  async createMintQuoteOnchain(t) {
    const e = {
      unit: this._unit,
      pubkey: t
    };
    return this.mint.createMintQuoteOnchain(e);
  }
  async checkMintQuote(t) {
    const e = typeof t == "string" ? t : t.quote, n = await this.mint.checkMintQuote(e);
    return typeof t == "string" ? n : { ...n, amount: n.amount || t.amount, unit: n.unit || t.unit };
  }
  /**
   * Gets an existing BOLT12 mint quote from the mint.
   *
   * @param quote Quote ID.
   * @returns The latest mint quote for the given quote ID.
   */
  async checkMintQuoteBolt12(t) {
    return this.mint.checkMintQuoteBolt12(t);
  }
  /**
   * Gets an existing on-chain mint quote from the mint.
   *
   * @param quote Quote ID.
   * @returns The latest on-chain mint quote for the given quote ID.
   */
  async checkMintQuoteOnchain(t) {
    return this.mint.checkMintQuoteOnchain(t);
  }
  async mintProofs(t, e, n) {
    return this._mintProofs("bolt11", t, e, n);
  }
  /**
   * Mint proofs for a given mint quote.
   *
   * @param amount Amount to request. This must be less than or equal to the `quote.amountPaid -
   *   quote.amountIssued`
   * @param {string} quote - ID of mint quote.
   * @param {string} privateKey - Private key to unlock the quote.
   * @param {MintProofOptions} [options] - Optional parameters for configuring the Mint Proof
   *   operation.
   * @returns Proofs.
   */
  async mintProofsBolt12(t, e, n, s) {
    return this._mintProofs("bolt12", t, e, { ...s, privateKey: n });
  }
  /**
   * Mint proofs for a given on-chain mint quote.
   *
   * @param amount Amount to request. This must be less than or equal to the `quote.amountPaid -
   *   quote.amountIssued`
   * @param {OnchainMintQuoteResponse} quote - On-chain mint quote response containing the quote details.
   * @param {string} privateKey - Private key to unlock the quote.
   * @param {MintProofOptions} [options] - Optional parameters for configuring the Mint Proof
   *   operation.
   * @returns Proofs.
   */
  async mintProofsOnchain(t, e, n, s) {
    return this._mintProofs("onchain", t, e, { ...s, privateKey: n });
  }
  /**
   * Requests a melt quote from the mint. Response returns amount and fees for a given unit in order
   * to pay a Lightning invoice.
   *
   * @param invoice LN invoice that needs to get a fee estimate.
   * @returns The mint will create and return a melt quote for the invoice with an amount and fee
   *   reserve.
   */
  async createMeltQuote(t) {
    const e = {
      unit: this._unit,
      request: t
    }, n = await this.mint.createMeltQuote(e);
    return {
      ...n,
      unit: n.unit || this.unit,
      request: n.request || t
    };
  }
  /**
   * Requests a melt quote from the mint. Response returns amount and fees for a given unit in order
   * to pay a BOLT12 offer.
   *
   * @param offer BOLT12 offer that needs to get a fee estimate.
   * @param amountMsat Amount in millisatoshis for amount-less offers. If this is defined and the
   *   offer has an amount, they **MUST** be equal.
   * @returns The mint will create and return a melt quote for the offer with an amount and fee
   *   reserve.
   */
  async createMeltQuoteBolt12(t, e) {
    return this.mint.createMeltQuoteBolt12({
      unit: this._unit,
      request: t,
      options: e ? {
        amountless: {
          amount_msat: e
        }
      } : void 0
    });
  }
  /**
   * Requests a melt quote from the mint. Response returns amount and fees for a given unit in order
   * to pay to an on-chain Bitcoin address.
   *
   * @param address Bitcoin address that needs to get a fee estimate.
   * @param amount Amount in satoshis to send to the Bitcoin address.
   * @returns The mint will create and return a melt quote for the on-chain payment with an amount and fee
   *   reserve.
   */
  async createMeltQuoteOnchain(t, e) {
    const n = {
      unit: this._unit,
      request: t,
      amount: e
    };
    return this.mint.createMeltQuoteOnchain(n);
  }
  /**
   * Requests a multi path melt quote from the mint.
   *
   * @param invoice LN invoice that needs to get a fee estimate.
   * @param partialAmount The partial amount of the invoice's total to be paid by this instance.
   * @returns The mint will create and return a melt quote for the invoice with an amount and fee
   *   reserve.
   */
  async createMultiPathMeltQuote(t, e) {
    const { supported: n, params: s } = (await this.lazyGetMintInfo()).isSupported(15);
    if (!n)
      throw new Error("Mint does not support NUT-15");
    if (!s?.some((h) => h.method === "bolt11" && h.unit === this.unit))
      throw new Error(`Mint does not support MPP for bolt11 and ${this.unit}`);
    const a = {
      mpp: {
        amount: e
      }
    }, i = {
      unit: this._unit,
      request: t,
      options: a
    };
    return { ...await this.mint.createMeltQuote(i), request: t, unit: this._unit };
  }
  async checkMeltQuote(t) {
    const e = typeof t == "string" ? t : t.quote, n = await this.mint.checkMeltQuote(e);
    return typeof t == "string" ? n : { ...n, request: t.request, unit: t.unit };
  }
  async checkMeltQuoteBolt12(t) {
    return this.mint.checkMeltQuoteBolt12(t);
  }
  /**
   * Return an existing on-chain melt quote from the mint.
   *
   * @param quote ID of the on-chain melt quote.
   * @returns The mint will return an existing on-chain melt quote.
   */
  async checkMeltQuoteOnchain(t) {
    return this.mint.checkMeltQuoteOnchain(t);
  }
  /**
   * Melt proofs for a melt quote. proofsToSend must be at least amount+fee_reserve form the melt
   * quote. This function does not perform coin selection!. Returns melt quote and change proofs.
   *
   * @param meltQuote ID of the melt quote.
   * @param proofsToSend Proofs to melt.
   * @param {MeltProofOptions} [options] - Optional parameters for configuring the Melting Proof
   *   operation.
   * @returns
   */
  async meltProofs(t, e, n) {
    return this._meltProofs("bolt11", t, e, n);
  }
  /**
   * Melt proofs for a melt quote. proofsToSend must be at least amount+fee_reserve form the melt
   * quote. This function does not perform coin selection!. Returns melt quote and change proofs.
   *
   * @param meltQuote ID of the melt quote.
   * @param proofsToSend Proofs to melt.
   * @param {MeltProofOptions} [options] - Optional parameters for configuring the Melting Proof
   *   operation.
   * @returns
   */
  async meltProofsBolt12(t, e, n) {
    return this._meltProofs("bolt12", t, e, n);
  }
  /**
   * Melt proofs for an on-chain melt quote. proofsToSend must be at least amount+fee_reserve from the melt
   * quote. This function does not perform coin selection!. Returns melt quote and change proofs.
   *
   * @param meltQuote On-chain melt quote response containing the quote details.
   * @param proofsToSend Proofs to melt for the on-chain payment.
   * @param {MeltProofOptions} [options] - Optional parameters for configuring the Melting Proof
   *   operation.
   * @returns Object containing the updated melt quote and any change proofs.
   */
  async meltProofsOnchain(t, e, n) {
    return this._meltProofs("onchain", t, e, n);
  }
  /**
   * Creates a split payload.
   *
   * @param amount Amount to send.
   * @param proofsToSend Proofs to split*
   * @param outputAmounts? Optionally specify the output's amounts to keep and to send.
   * @param counter? Optionally set counter to derive secret deterministically. CashuWallet class
   *   must be initialized with seed phrase to take effect.
   * @param pubkey? Optionally locks ecash to pubkey. Will not be deterministic, even if counter is
   *   set!
   * @param privkey? Will create a signature on the @param proofsToSend secrets if set.
   * @param customOutputData? Optionally specify your own OutputData (blinded messages)
   * @param p2pk? Optionally specify options to lock the proofs according to NUT-11.
   * @returns
   */
  createSwapPayload(t, e, n, s, r, a, i, c, h) {
    const u = e.reduce((g, v) => g + v.amount, 0);
    s && s.sendAmounts && !s.keepAmounts && (s.keepAmounts = R(
      u - t - this.getFeesForProofs(e),
      n.keys
    ));
    const f = u - t - this.getFeesForProofs(e);
    let d = [], l = [];
    if (c?.keep)
      if (mt(c.keep)) {
        const g = c.keep;
        R(f, n.keys).forEach((N) => {
          d.push(g(N, n));
        });
      } else
        d = c.keep;
    else
      d = this.createOutputData(
        f,
        n,
        r,
        void 0,
        s?.keepAmounts,
        void 0,
        this._keepFactory
      );
    if (c?.send)
      if (mt(c.send)) {
        const g = c.send;
        R(t, n.keys).forEach((N) => {
          l.push(g(N, n));
        });
      } else
        l = c.send;
    else
      l = this.createOutputData(
        t,
        n,
        r ? r + d.length : void 0,
        a,
        s?.sendAmounts,
        h
      );
    i && (e = Mt(e, i)), e = at(e), e = e.map((g) => {
      const v = g.witness && typeof g.witness != "string" ? JSON.stringify(g.witness) : g.witness;
      return { ...g, witness: v };
    });
    const m = [...d, ...l], P = m.map((g, v) => v).sort(
      (g, v) => m[g].blindedMessage.amount - m[v].blindedMessage.amount
    ), T = [
      ...Array.from({ length: d.length }, () => !0),
      ...Array.from({ length: l.length }, () => !1)
    ], b = P.map((g) => m[g]), k = P.map((g) => T[g]);
    return {
      payload: {
        inputs: e,
        outputs: b.map((g) => g.blindedMessage)
      },
      outputData: b,
      keepVector: k,
      sortedIndices: P
    };
  }
  /**
   * Get an array of the states of proofs from the mint (as an array of CheckStateEnum's)
   *
   * @param proofs (only the `secret` field is required)
   * @returns
   */
  async checkProofsStates(t) {
    const e = new TextEncoder(), n = t.map((a) => St(e.encode(a.secret)).toHex(!0)), s = 100, r = [];
    for (let a = 0; a < n.length; a += s) {
      const i = n.slice(a, a + s), { states: c } = await this.mint.check({
        Ys: i
      }), h = {};
      c.forEach((u) => {
        h[u.Y] = u;
      });
      for (let u = 0; u < i.length; u++) {
        const f = h[i[u]];
        if (!f)
          throw new Error("Could not find state for proof with Y: " + i[u]);
        r.push(f);
      }
    }
    return r;
  }
  /**
   * Register a callback to be called whenever a mint quote's state changes.
   *
   * @param quoteIds List of mint quote IDs that should be subscribed to.
   * @param callback Callback function that will be called whenever a mint quote state changes.
   * @param errorCallback
   * @returns
   */
  async onMintQuoteUpdates(t, e, n) {
    if (await this.mint.connectWebSocket(), !this.mint.webSocketConnection)
      throw new Error("failed to establish WebSocket connection.");
    const s = this.mint.webSocketConnection.createSubscription(
      { kind: "bolt11_mint_quote", filters: t },
      e,
      n
    );
    return () => {
      this.mint.webSocketConnection?.cancelSubscription(s, e);
    };
  }
  /**
   * Register a callback to be called whenever a melt quote's state changes.
   *
   * @param quoteIds List of melt quote IDs that should be subscribed to.
   * @param callback Callback function that will be called whenever a melt quote state changes.
   * @param errorCallback
   * @returns
   */
  async onMeltQuotePaid(t, e, n) {
    return this.onMeltQuoteUpdates(
      [t],
      (s) => {
        s.state === tt.PAID && e(s);
      },
      n
    );
  }
  /**
   * Register a callback to be called when a single mint quote gets paid.
   *
   * @param quoteId Mint quote id that should be subscribed to.
   * @param callback Callback function that will be called when this mint quote gets paid.
   * @param errorCallback
   * @returns
   */
  async onMintQuotePaid(t, e, n) {
    return this.onMintQuoteUpdates(
      [t],
      (s) => {
        s.state === pt.PAID && e(s);
      },
      n
    );
  }
  /**
   * Register a callback to be called when a single melt quote gets paid.
   *
   * @param quoteId Melt quote id that should be subscribed to.
   * @param callback Callback function that will be called when this melt quote gets paid.
   * @param errorCallback
   * @returns
   */
  async onMeltQuoteUpdates(t, e, n) {
    if (await this.mint.connectWebSocket(), !this.mint.webSocketConnection)
      throw new Error("failed to establish WebSocket connection.");
    const s = this.mint.webSocketConnection.createSubscription(
      { kind: "bolt11_melt_quote", filters: t },
      e,
      n
    );
    return () => {
      this.mint.webSocketConnection?.cancelSubscription(s, e);
    };
  }
  /**
   * Register a callback to be called whenever a subscribed proof state changes.
   *
   * @param proofs List of proofs that should be subscribed to.
   * @param callback Callback function that will be called whenever a proof's state changes.
   * @param errorCallback
   * @returns
   */
  async onProofStateUpdates(t, e, n) {
    if (await this.mint.connectWebSocket(), !this.mint.webSocketConnection)
      throw new Error("failed to establish WebSocket connection.");
    const s = new TextEncoder(), r = {};
    for (let c = 0; c < t.length; c++) {
      const h = St(s.encode(t[c].secret)).toHex(!0);
      r[h] = t[c];
    }
    const a = Object.keys(r), i = this.mint.webSocketConnection.createSubscription(
      { kind: "proof_state", filters: a },
      (c) => {
        e({ ...c, proof: r[c.Y] });
      },
      n
    );
    return () => {
      this.mint.webSocketConnection?.cancelSubscription(i, e);
    };
  }
  /**
   * Creates blinded messages for a according to @param amounts.
   *
   * @param amount Array of amounts to create blinded messages for.
   * @param counter? Optionally set counter to derive secret deterministically. CashuWallet class
   *   must be initialized with seed phrase to take effect.
   * @param pubkey? Optionally locks ecash to pubkey. Will not be deterministic, even if counter is
   *   set!
   * @param outputAmounts? Optionally specify the output's amounts to keep and to send.
   * @param p2pk? Optionally specify options to lock the proofs according to NUT-11.
   * @param factory? Optionally specify a custom function that produces OutputData (blinded
   *   messages)
   * @returns Blinded messages, secrets, rs, and amounts.
   */
  createOutputData(t, e, n, s, r, a, i) {
    let c;
    if (s)
      c = Q.createP2PKData({ pubkey: s }, t, e, r);
    else if (n || n === 0) {
      if (!this._seed)
        throw new Error("cannot create deterministic messages without seed");
      c = Q.createDeterministicData(
        t,
        this._seed,
        n,
        e,
        r
      );
    } else a ? c = Q.createP2PKData(a, t, e, r) : i ? c = R(t, e.keys).map((u) => i(u, e)) : c = Q.createRandomData(t, e, r);
    return c;
  }
  /**
   * Creates NUT-08 blank outputs (fee returns) for a given fee reserve See:
   * https://github.com/cashubtc/nuts/blob/main/08.md.
   *
   * @param amount Amount to cover with blank outputs.
   * @param keysetId Mint keysetId.
   * @param counter? Optionally set counter to derive secret deterministically. CashuWallet class
   *   must be initialized with seed phrase to take effect.
   * @returns Blinded messages, secrets, and rs.
   */
  createBlankOutputs(t, e, n, s) {
    let r = Math.ceil(Math.log2(t)) || 1;
    r < 0 && (r = 0);
    const a = r ? Array(r).fill(1) : [];
    return this.createOutputData(
      a.length,
      e,
      n,
      void 0,
      a,
      void 0,
      s
    );
  }
  /**
   * Mints proofs for a given mint quote created with the bolt11 or bolt12 method.
   *
   * @param method Payment method of the quote.
   * @param amount Amount to mint.
   * @param quote The bolt11 or bolt12 mint quote.
   * @param options Optional parameters for configuring the Mint Proof operation.
   * @returns Proofs.
   */
  async _mintProofs(t, e, n, s) {
    let { outputAmounts: r } = s || {};
    const { counter: a, pubkey: i, p2pk: c, keysetId: h, proofsWeHave: u, outputData: f, privateKey: d } = s || {}, l = await this.getKeys(h);
    !r && u && (r = {
      keepAmounts: vt(u, e, l.keys, this._denominationTarget),
      sendAmounts: []
    });
    let m = [];
    if (f)
      if (mt(f)) {
        const b = R(e, l.keys, r?.keepAmounts);
        for (let k = 0; k < b.length; k++)
          m.push(f(b[k], l));
      } else
        m = f;
    else if (this._keepFactory) {
      const b = R(e, l.keys, r?.keepAmounts);
      for (let k = 0; k < b.length; k++)
        m.push(this._keepFactory(b[k], l));
    } else
      m = this.createOutputData(
        e,
        l,
        a,
        i,
        r?.keepAmounts,
        c
      );
    let P;
    if (typeof n != "string") {
      if (!d)
        throw new Error("Can not sign locked quote without private key");
      const b = m.map((g) => g.blindedMessage), k = Yt(d, n.quote, b);
      P = {
        outputs: b,
        quote: n.quote,
        signature: k
      };
    } else
      P = {
        outputs: m.map((b) => b.blindedMessage),
        quote: n
      };
    if (t === "bolt12") {
      const { signatures: b } = await this.mint.mintBolt12(P);
      return m.map((k, g) => k.toProof(b[g], l));
    }
    if (t === "onchain") {
      const { signatures: b } = await this.mint.mintOnchain(P);
      return m.map((k, g) => k.toProof(b[g], l));
    }
    const { signatures: T } = await this.mint.mint(P);
    return m.map((b, k) => b.toProof(T[k], l));
  }
  /**
   * Melt proofs for a given melt quote created with the bolt11 or bolt12 method.
   *
   * @param method Payment method of the quote.
   * @param meltQuote The bolt11 or bolt12 melt quote.
   * @param proofsToSend Proofs to melt.
   * @param options Optional parameters for configuring the Melting Proof operation.
   * @returns Melt quote and change proofs.
   */
  async _meltProofs(t, e, n, s) {
    const { keysetId: r, counter: a, privkey: i } = s || {}, c = await this.getKeys(r), h = this.createBlankOutputs(
      j(n) - e.amount,
      c,
      a,
      this._keepFactory
    );
    i != null && (n = Mt(n, i)), n = at(n), n = n.map((d) => {
      const l = d.witness && typeof d.witness != "string" ? JSON.stringify(d.witness) : d.witness;
      return { ...d, witness: l };
    });
    const u = {
      quote: e.quote,
      inputs: n,
      outputs: h.map((d) => d.blindedMessage)
    };
    if (t === "bolt12") {
      const d = await this.mint.meltBolt12(u);
      return {
        quote: { ...d, unit: e.unit, request: e.request },
        change: d.change?.map((l, m) => h[m].toProof(l, c)) ?? []
      };
    }
    if (t === "onchain") {
      const d = await this.mint.meltOnchain(u);
      return {
        quote: { ...d, unit: e.unit, request: e.request },
        change: d.change?.map((l, m) => h[m].toProof(l, c)) ?? []
      };
    }
    const f = await this.mint.melt(u);
    return {
      quote: { ...f, unit: e.unit, request: e.request },
      change: f.change?.map((d, l) => h[l].toProof(d, c)) ?? []
    };
  }
}
class Y {
  /**
   * @param _mintUrl Requires mint URL to create this object.
   * @param _customRequest If passed, use custom request implementation for network communication
   *   with the mint.
   */
  constructor(t, e) {
    this._mintUrl = t, this._customRequest = e, this._mintUrl = zt(t), this._customRequest = e;
  }
  get mintUrl() {
    return this._mintUrl;
  }
  /**
   * Mints new Blinded Authentication tokens by requesting blind signatures on the provided outputs.
   *
   * @param mintUrl
   * @param mintPayload Payload containing the outputs to get blind signatures on.
   * @param clearAuthToken A NUT-21 clear auth token.
   * @param customRequest
   * @returns Serialized blinded signatures.
   */
  static async mint(t, e, n, s) {
    const r = s || E, a = {
      "Clear-auth": `${n}`
    }, i = await r({
      endpoint: A(t, "/v1/auth/blind/mint"),
      method: "POST",
      requestBody: e,
      headers: a
    });
    if (!D(i) || !Array.isArray(i?.signatures))
      throw new Error("bad response");
    return i;
  }
  /**
   * Mints new Blinded Authentication tokens by requesting blind signatures on the provided outputs.
   *
   * @param mintPayload Payload containing the outputs to get blind signatures on.
   * @param clearAuthToken A NUT-21 clear auth token.
   * @returns Serialized blinded signatures.
   */
  async mint(t, e) {
    return Y.mint(this._mintUrl, t, e, this._customRequest);
  }
  /**
   * Get the mints public NUT-22 keys.
   *
   * @param mintUrl
   * @param keysetId Optional param to get the keys for a specific keyset. If not specified, the
   *   keys from all active keysets are fetched.
   * @param customRequest
   * @returns
   */
  static async getKeys(t, e, n) {
    const r = await (n || E)({
      endpoint: e ? A(t, "/v1/auth/blind/keys", e) : A(t, "/v1/auth/blind/keys")
    });
    if (!D(r) || !Array.isArray(r.keysets))
      throw new Error("bad response");
    return r;
  }
  /**
   * Get the mints public NUT-22 keys.
   *
   * @param keysetId Optional param to get the keys for a specific keyset. If not specified, the
   *   keys from all active keysets are fetched.
   * @returns The mints public keys.
   */
  async getKeys(t, e) {
    return await Y.getKeys(
      e || this._mintUrl,
      t,
      this._customRequest
    );
  }
  /**
   * Get the mints NUT-22 keysets in no specific order.
   *
   * @param mintUrl
   * @param customRequest
   * @returns All the mints past and current keysets.
   */
  static async getKeySets(t, e) {
    return (e || E)({
      endpoint: A(t, "/v1/auth/blind/keysets")
    });
  }
  /**
   * Get the mints NUT-22 keysets in no specific order.
   *
   * @returns All the mints past and current keysets.
   */
  async getKeySets() {
    return Y.getKeySets(this._mintUrl, this._customRequest);
  }
}
class Le {
  /**
   * @param mint NUT-22 auth mint instance.
   * @param options.keys Public keys from the mint (will be fetched from mint if not provided)
   * @param options.keysets Keysets from the mint (will be fetched from mint if not provided)
   */
  constructor(t, e) {
    this._keys = /* @__PURE__ */ new Map(), this._keysets = [], this._unit = "auth", this.mint = t;
    let n = [];
    e?.keys && !Array.isArray(e.keys) ? n = [e.keys] : e?.keys && Array.isArray(e?.keys) && (n = e?.keys), n && n.forEach((s) => this._keys.set(s.id, s)), e?.keysets && (this._keysets = e.keysets);
  }
  get keys() {
    return this._keys;
  }
  get keysetId() {
    if (!this._keysetId)
      throw new Error("No keysetId set");
    return this._keysetId;
  }
  set keysetId(t) {
    this._keysetId = t;
  }
  get keysets() {
    return this._keysets;
  }
  /**
   * Load mint information, keysets and keys. This function can be called if no keysets are passed
   * in the constructor.
   */
  async loadMint() {
    await this.getKeySets(), await this.getKeys();
  }
  /**
   * Choose a keyset to activate based on the lowest input fee.
   *
   * Note: this function will filter out deprecated base64 keysets.
   *
   * @param keysets Keysets to choose from.
   * @returns Active keyset.
   */
  getActiveKeyset(t) {
    let e = t.filter((s) => s.active);
    e = e.filter((s) => s.id.startsWith("00"));
    const n = e.sort(
      (s, r) => (s.input_fee_ppk ?? 0) - (r.input_fee_ppk ?? 0)
    )[0];
    if (!n)
      throw new Error("No active keyset found");
    return n;
  }
  /**
   * Get keysets from the mint with the unit of the wallet.
   *
   * @returns Keysets with wallet's unit.
   */
  async getKeySets() {
    const e = (await this.mint.getKeySets()).keysets.filter((n) => n.unit === this._unit);
    return this._keysets = e, this._keysets;
  }
  /**
   * Get all active keys from the mint and set the keyset with the lowest fees as the active wallet
   * keyset.
   *
   * @returns Keyset.
   */
  async getAllKeys() {
    const t = await this.mint.getKeys();
    return this._keys = new Map(t.keysets.map((e) => [e.id, e])), this.keysetId = this.getActiveKeyset(this._keysets).id, t.keysets;
  }
  /**
   * Get public keys from the mint. If keys were already fetched, it will return those.
   *
   * If `keysetId` is set, it will fetch and return that specific keyset. Otherwise, we select an
   * active keyset with the unit of the wallet.
   *
   * @param keysetId Optional keysetId to get keys for.
   * @param forceRefresh? If set to true, it will force refresh the keyset from the mint.
   * @returns Keyset.
   */
  async getKeys(t, e) {
    if ((!(this._keysets.length > 0) || e) && await this.getKeySets(), t || (t = this.getActiveKeyset(this._keysets).id), !this._keysets.find((n) => n.id === t) && (await this.getKeySets(), !this._keysets.find((n) => n.id === t)))
      throw new Error(`could not initialize keys. No keyset with id '${t}' found`);
    if (!this._keys.get(t)) {
      const n = await this.mint.getKeys(t);
      this._keys.set(t, n.keysets[0]);
    }
    return this.keysetId = t, this._keys.get(t);
  }
  /**
   * Mint proofs for a given mint quote.
   *
   * @param amount Amount to request.
   * @param clearAuthToken ClearAuthToken to mint.
   * @param options.keysetId? Optionally set keysetId for blank outputs for returned change.
   * @returns Proofs.
   */
  async mintProofs(t, e, n) {
    const s = await this.getKeys(n?.keysetId), r = Q.createRandomData(t, s), a = {
      outputs: r.map((h) => h.blindedMessage)
    }, { signatures: i } = await this.mint.mint(a, e), c = r.map((h, u) => h.toProof(i[u], s));
    if (c.some((h) => !Gt(h, s)))
      throw new Error("Mint returned auth proofs with invalid DLEQ");
    return c;
  }
}
function We(o) {
  const t = {
    id: o.id,
    secret: o.secret,
    C: o.C
  }, e = xt(t);
  return "auth" + "A" + e;
}
async function cn(o, t, e) {
  const n = new Y(t);
  return (await new Le(n).mintProofs(o, e)).map((a) => We(a));
}
export {
  Y as CashuAuthMint,
  Le as CashuAuthWallet,
  I as CashuMint,
  an as CashuWallet,
  on as CheckStateEnum,
  Ut as ConsoleLogger,
  et as HttpResponseError,
  B as LogLevel,
  tt as MeltQuoteState,
  Et as MintOperationError,
  pt as MintQuoteState,
  At as NetworkError,
  Q as OutputData,
  _t as PaymentRequest,
  Ke as PaymentRequestTransportType,
  tn as decodePaymentRequest,
  Me as deriveKeysetId,
  cn as getBlindedAuthToken,
  Se as getDecodedToken,
  nn as getDecodedTokenBinary,
  We as getEncodedAuthToken,
  Ze as getEncodedToken,
  en as getEncodedTokenBinary,
  Pe as getEncodedTokenV4,
  Gt as hasValidDleq,
  sn as injectWebSocketImpl,
  rn as setGlobalRequestOptions
};
//# sourceMappingURL=cashu-ts.es.js.map
