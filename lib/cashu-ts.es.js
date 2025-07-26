import { verifyDLEQProof_reblind as Gt } from "./crypto/client/NUT12.es.js";
import { pointFromHex as ot, hashToCurve as Et } from "./crypto/common.es.js";
import { hexToBytes as Q, bytesToHex as $ } from "@noble/curves/abstract/utils";
import { sha256 as zt } from "@noble/hashes/sha256";
import { Buffer as et } from "buffer";
import { signP2PKProofs as Pt } from "./crypto/client/NUT11.es.js";
import { signMintQuote as Vt } from "./crypto/client/NUT20.es.js";
import { constructProofFromPromise as Jt, serializeProof as Xt, blindMessage as ut } from "./crypto/client.es.js";
import { hexToBytes as St, bytesToHex as J, randomBytes as It } from "@noble/hashes/utils";
import { deriveSecret as Yt, deriveBlindingFactor as Zt } from "./crypto/client/NUT09.es.js";
function te(n) {
  return et.from(n).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function Kt(n) {
  return et.from(n, "base64");
}
function Rt(n) {
  const t = JSON.stringify(n);
  return ne(et.from(t).toString("base64"));
}
function ee(n) {
  const t = et.from(se(n), "base64").toString();
  return JSON.parse(t);
}
function se(n) {
  return n.replace(/-/g, "+").replace(/_/g, "/").split("=")[0];
}
function ne(n) {
  return n.replace(/\+/g, "-").replace(/\//g, "_").split("=")[0];
}
function re(n) {
  return typeof n == "number" || typeof n == "string";
}
function mt(n) {
  const t = [];
  return gt(n, t), new Uint8Array(t);
}
function gt(n, t) {
  if (n === null)
    t.push(246);
  else if (n === void 0)
    t.push(247);
  else if (typeof n == "boolean")
    t.push(n ? 245 : 244);
  else if (typeof n == "number")
    Dt(n, t);
  else if (typeof n == "string")
    Ft(n, t);
  else if (Array.isArray(n))
    ie(n, t);
  else if (n instanceof Uint8Array)
    oe(n, t);
  else if (typeof n == "object")
    ae(n, t);
  else
    throw new Error("Unsupported type");
}
function Dt(n, t) {
  if (n < 24)
    t.push(n);
  else if (n < 256)
    t.push(24, n);
  else if (n < 65536)
    t.push(25, n >> 8, n & 255);
  else if (n < 4294967296)
    t.push(26, n >> 24, n >> 16 & 255, n >> 8 & 255, n & 255);
  else
    throw new Error("Unsupported integer size");
}
function oe(n, t) {
  const e = n.length;
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
  for (let s = 0; s < n.length; s++)
    t.push(n[s]);
}
function Ft(n, t) {
  const e = new TextEncoder().encode(n), s = e.length;
  if (s < 24)
    t.push(96 + s);
  else if (s < 256)
    t.push(120, s);
  else if (s < 65536)
    t.push(121, s >> 8 & 255, s & 255);
  else if (s < 4294967296)
    t.push(
      122,
      s >> 24 & 255,
      s >> 16 & 255,
      s >> 8 & 255,
      s & 255
    );
  else
    throw new Error("String too long to encode");
  for (let r = 0; r < e.length; r++)
    t.push(e[r]);
}
function ie(n, t) {
  const e = n.length;
  if (e < 24)
    t.push(128 | e);
  else if (e < 256)
    t.push(152, e);
  else if (e < 65536)
    t.push(153, e >> 8, e & 255);
  else
    throw new Error("Unsupported array length");
  for (const s of n)
    gt(s, t);
}
function ae(n, t) {
  const e = Object.keys(n);
  Dt(e.length, t), t[t.length - 1] |= 160;
  for (const s of e)
    Ft(s, t), gt(n[s], t);
}
function yt(n) {
  const t = new DataView(n.buffer, n.byteOffset, n.byteLength);
  return it(t, 0).value;
}
function it(n, t) {
  if (t >= n.byteLength)
    throw new Error("Unexpected end of data");
  const e = n.getUint8(t++), s = e >> 5, r = e & 31;
  switch (s) {
    case 0:
      return ce(n, t, r);
    case 1:
      return ue(n, t, r);
    case 2:
      return he(n, t, r);
    case 3:
      return le(n, t, r);
    case 4:
      return de(n, t, r);
    case 5:
      return fe(n, t, r);
    case 7:
      return me(n, t, r);
    default:
      throw new Error(`Unsupported major type: ${s}`);
  }
}
function z(n, t, e) {
  if (e < 24) return { value: e, offset: t };
  if (e === 24) return { value: n.getUint8(t++), offset: t };
  if (e === 25) {
    const s = n.getUint16(t, !1);
    return t += 2, { value: s, offset: t };
  }
  if (e === 26) {
    const s = n.getUint32(t, !1);
    return t += 4, { value: s, offset: t };
  }
  if (e === 27) {
    const s = n.getUint32(t, !1), r = n.getUint32(t + 4, !1);
    return t += 8, { value: s * 2 ** 32 + r, offset: t };
  }
  throw new Error(`Unsupported length: ${e}`);
}
function ce(n, t, e) {
  const { value: s, offset: r } = z(n, t, e);
  return { value: s, offset: r };
}
function ue(n, t, e) {
  const { value: s, offset: r } = z(n, t, e);
  return { value: -1 - s, offset: r };
}
function he(n, t, e) {
  const { value: s, offset: r } = z(n, t, e);
  if (r + s > n.byteLength)
    throw new Error("Byte string length exceeds data length");
  return { value: new Uint8Array(n.buffer, n.byteOffset + r, s), offset: r + s };
}
function le(n, t, e) {
  const { value: s, offset: r } = z(n, t, e);
  if (r + s > n.byteLength)
    throw new Error("String length exceeds data length");
  const o = new Uint8Array(n.buffer, n.byteOffset + r, s);
  return { value: new TextDecoder().decode(o), offset: r + s };
}
function de(n, t, e) {
  const { value: s, offset: r } = z(n, t, e), o = [];
  let i = r;
  for (let a = 0; a < s; a++) {
    const c = it(n, i);
    o.push(c.value), i = c.offset;
  }
  return { value: o, offset: i };
}
function fe(n, t, e) {
  const { value: s, offset: r } = z(n, t, e), o = {};
  let i = r;
  for (let a = 0; a < s; a++) {
    const c = it(n, i);
    if (!re(c.value))
      throw new Error("Invalid key type");
    const u = it(n, c.offset);
    o[c.value] = u.value, i = u.offset;
  }
  return { value: o, offset: i };
}
function pe(n) {
  const t = (n & 31744) >> 10, e = n & 1023, s = n & 32768 ? -1 : 1;
  return t === 0 ? s * 2 ** -14 * (e / 1024) : t === 31 ? e ? NaN : s * (1 / 0) : s * 2 ** (t - 15) * (1 + e / 1024);
}
function me(n, t, e) {
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
  if (e === 24) return { value: n.getUint8(t++), offset: t };
  if (e === 25) {
    const s = pe(n.getUint16(t, !1));
    return t += 2, { value: s, offset: t };
  }
  if (e === 26) {
    const s = n.getFloat32(t, !1);
    return t += 4, { value: s, offset: t };
  }
  if (e === 27) {
    const s = n.getFloat64(t, !1);
    return t += 8, { value: s, offset: t };
  }
  throw new Error(`Unknown simple or float value: ${e}`);
}
class wt {
  constructor(t, e, s, r, o, i, a = !1, c) {
    this.transport = t, this.id = e, this.amount = s, this.unit = r, this.mints = o, this.description = i, this.singleUse = a, this.nut10 = c;
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
    const t = this.toRawRequest(), e = mt(t);
    return "creqA" + et.from(e).toString("base64");
  }
  getTransport(t) {
    return this.transport?.find((e) => e.type === t);
  }
  static fromRawRequest(t) {
    const e = t.t ? t.t.map((r) => ({
      type: r.t,
      target: r.a,
      tags: r.g
    })) : void 0, s = t.nut10 ? {
      kind: t.nut10.k,
      data: t.nut10.d,
      tags: t.nut10.t
    } : void 0;
    return new wt(
      e,
      t.i,
      t.a,
      t.u,
      t.m,
      t.d,
      t.s,
      s
    );
  }
  static fromEncodedRequest(t) {
    if (!t.startsWith("creq"))
      throw new Error("unsupported pr: invalid prefix");
    if (t[4] !== "A")
      throw new Error("unsupported pr version");
    const s = t.slice(5), r = Kt(s), o = yt(r);
    return this.fromRawRequest(o);
  }
}
const ge = "A", ye = "cashu";
function R(n, t, e, s) {
  if (e) {
    const o = Tt(e);
    if (o > n)
      throw new Error(`Split is greater than total amount: ${o} > ${n}`);
    if (e.some((i) => !Ot(i, t)))
      throw new Error("Provided amount preferences do not match the amounts of the mint keyset.");
    n = n - Tt(e);
  } else
    e = [];
  return Ut(t, "desc").forEach((o) => {
    const i = Math.floor(n / o);
    for (let a = 0; a < i; ++a) e?.push(o);
    n %= o;
  }), e.sort((o, i) => o - i);
}
function Mt(n, t, e, s) {
  const r = [], o = n.map((u) => u.amount);
  Ut(e, "asc").forEach((u) => {
    const h = o.filter((p) => p === u).length, l = Math.max(s - h, 0);
    for (let p = 0; p < l && !(r.reduce((d, g) => d + g, 0) + u > t); ++p)
      r.push(u);
  });
  const a = t - r.reduce((u, h) => u + h, 0);
  return a && R(a, e).forEach((h) => {
    r.push(h);
  }), r.sort((u, h) => u - h);
}
function Ut(n, t = "desc") {
  return t == "desc" ? Object.keys(n).map((e) => parseInt(e)).sort((e, s) => s - e) : Object.keys(n).map((e) => parseInt(e)).sort((e, s) => e - s);
}
function Ot(n, t) {
  return n in t;
}
function we(n) {
  return Nt($(n));
}
function Nt(n) {
  return BigInt(`0x${n}`);
}
function ke(n) {
  return n.toString(16).padStart(64, "0");
}
function qt(n) {
  return /^[a-f0-9]*$/i.test(n);
}
function Bt(n) {
  return Array.isArray(n) ? n.some((t) => !qt(t.id)) : qt(n.id);
}
function _e(n, t) {
  t && (n.proofs = at(n.proofs));
  const e = { token: [{ mint: n.mint, proofs: n.proofs }] };
  return n.unit && (e.unit = n.unit), n.memo && (e.memo = n.memo), ye + ge + Rt(e);
}
function Ve(n, t) {
  if (Bt(n.proofs) || t?.version === 3) {
    if (t?.version === 4)
      throw new Error("can not encode to v4 token if proofs contain non-hex keyset id");
    return _e(n, t?.removeDleq);
  }
  return be(n, t?.removeDleq);
}
function be(n, t) {
  if (t && (n.proofs = at(n.proofs)), n.proofs.forEach((c) => {
    if (c.dleq && c.dleq.r == null)
      throw new Error("Missing blinding factor in included DLEQ proof");
  }), Bt(n.proofs))
    throw new Error("can not encode to v4 token if proofs contain non-hex keyset id");
  const s = Lt(n), r = mt(s), o = "cashu", i = "B", a = te(r);
  return o + i + a;
}
function Lt(n) {
  const t = {}, e = n.mint;
  for (let r = 0; r < n.proofs.length; r++) {
    const o = n.proofs[r];
    t[o.id] ? t[o.id].push(o) : t[o.id] = [o];
  }
  const s = {
    m: e,
    u: n.unit || "sat",
    t: Object.keys(t).map(
      (r) => ({
        i: Q(r),
        p: t[r].map(
          (o) => ({
            a: o.amount,
            s: o.secret,
            c: Q(o.C),
            ...o.dleq && {
              d: {
                e: Q(o.dleq.e),
                s: Q(o.dleq.s),
                r: Q(o.dleq.r ?? "00")
              }
            },
            ...o.witness && {
              w: JSON.stringify(o.witness)
            }
          })
        )
      })
    )
  };
  return n.memo && (s.d = n.memo), s;
}
function Ct(n) {
  const t = [];
  n.t.forEach(
    (s) => s.p.forEach((r) => {
      t.push({
        secret: r.s,
        C: $(r.c),
        amount: r.a,
        id: $(s.i),
        ...r.d && {
          dleq: {
            r: $(r.d.r),
            s: $(r.d.s),
            e: $(r.d.e)
          }
        },
        ...r.w && {
          witness: r.w
        }
      });
    })
  );
  const e = { mint: n.m, proofs: t, unit: n.u || "sat" };
  return n.d && (e.memo = n.d), e;
}
function Ae(n) {
  return ["web+cashu://", "cashu://", "cashu:", "cashu"].forEach((e) => {
    n.startsWith(e) && (n = n.slice(e.length));
  }), Ee(n);
}
function Ee(n) {
  const t = n.slice(0, 1), e = n.slice(1);
  if (t === "A") {
    const s = ee(e);
    if (s.token.length > 1)
      throw new Error("Multi entry token are not supported");
    const r = s.token[0], o = {
      mint: r.mint,
      proofs: r.proofs,
      unit: s.unit || "sat"
    };
    return s.memo && (o.memo = s.memo), o;
  } else if (t === "B") {
    const s = Kt(e), r = yt(s);
    return Ct(r);
  }
  throw new Error("Token version is not supported");
}
function Je(n) {
  const t = Object.entries(n).sort((r, o) => +r[0] - +o[0]).map(([, r]) => Q(r)).reduce((r, o) => Pe(r, o), new Uint8Array()), e = zt(t);
  return "00" + Buffer.from(e).toString("hex").slice(0, 14);
}
function Pe(n, t) {
  const e = new Uint8Array(n.length + t.length);
  return e.set(n), e.set(t, n.length), e;
}
function U(n) {
  return typeof n == "object";
}
function v(...n) {
  return n.map((t) => t.replace(/(^\/+|\/+$)/g, "")).join("/");
}
function Qt(n) {
  return n.replace(/\/$/, "");
}
function W(n) {
  return n.reduce((t, e) => t + e.amount, 0);
}
function Xe(n) {
  return wt.fromEncodedRequest(n);
}
class Se {
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
class Ie {
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
    const e = new Se(t);
    return this._size === 0 || !this._last ? (this._first = e, this._last = e) : (this._last.next = e, this._last = e), this._size++, !0;
  }
  dequeue() {
    if (this._size === 0 || !this._first) return null;
    const t = this._first;
    return this._first = t.next, t.next = null, this._size--, t.value;
  }
}
function at(n) {
  return n.map((t) => {
    const e = { ...t };
    return delete e.dleq, e;
  });
}
function Wt(n, t) {
  if (n.dleq == null)
    return !1;
  const e = {
    e: Q(n.dleq.e),
    s: Q(n.dleq.s),
    r: Nt(n.dleq.r ?? "00")
  };
  if (!Ot(n.amount, t.keys))
    throw new Error(`undefined key for amount ${n.amount}`);
  const s = t.keys[n.amount];
  return !!Gt(
    new TextEncoder().encode(n.secret),
    e,
    ot(n.C),
    ot(s)
  );
}
function Me(...n) {
  const t = n.reduce((r, o) => r + o.length, 0), e = new Uint8Array(t);
  let s = 0;
  for (let r = 0; r < n.length; r++)
    e.set(n[r], s), s = s + n[r].length;
  return e;
}
function Ye(n) {
  const t = new TextEncoder(), e = Lt(n), s = mt(e), r = t.encode("craw"), o = t.encode("B");
  return Me(r, o, s);
}
function Ze(n) {
  const t = new TextDecoder(), e = t.decode(n.slice(0, 4)), s = t.decode(new Uint8Array([n[4]]));
  if (e !== "craw" || s !== "B")
    throw new Error("not a valid binary token");
  const r = n.slice(5), o = yt(r);
  return Ct(o);
}
function Tt(n) {
  return n.reduce((t, e) => t + e, 0);
}
let kt;
typeof WebSocket < "u" && (kt = WebSocket);
function ts(n) {
  kt = n;
}
function qe() {
  return kt;
}
const M = {
  FATAL: "FATAL",
  ERROR: "ERROR",
  WARN: "WARN",
  INFO: "INFO",
  DEBUG: "DEBUG",
  TRACE: "TRACE"
}, O = {
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
}, Y = class Y {
  constructor(t = M.INFO) {
    this.minLevel = t;
  }
  logToConsole(t, e, s) {
    if (Y.SEVERITY[t] > Y.SEVERITY[this.minLevel]) return;
    const r = `[${t}] `;
    let o = e;
    const i = /* @__PURE__ */ new Set();
    if (s) {
      const a = Object.fromEntries(
        Object.entries(s).map(([h, l]) => [
          h,
          l instanceof Error ? { message: l.message, stack: l.stack } : l
        ])
      );
      o = e.replace(/\{(\w+)\}/g, (h, l) => a[l] !== void 0 ? (i.add(l), String(a[l])) : h);
      const c = Object.fromEntries(
        Object.entries(a).filter(([h]) => !i.has(h))
      ), u = this.getConsoleMethod(t);
      Object.keys(c).length > 0 ? u(r + o, c) : u(r + o);
    } else
      this.getConsoleMethod(t)(r + o);
  }
  // Note: NOT static as test suite needs to spy on the output
  getConsoleMethod(t) {
    switch (t) {
      case M.FATAL:
      case M.ERROR:
        return console.error;
      case M.WARN:
        return console.warn;
      case M.INFO:
        return console.info;
      case M.DEBUG:
        return console.debug;
      case M.TRACE:
        return console.trace;
      default:
        return console.log;
    }
  }
  // Interface methods
  fatal(t, e) {
    this.logToConsole(M.FATAL, t, e);
  }
  error(t, e) {
    this.logToConsole(M.ERROR, t, e);
  }
  warn(t, e) {
    this.logToConsole(M.WARN, t, e);
  }
  info(t, e) {
    this.logToConsole(M.INFO, t, e);
  }
  debug(t, e) {
    this.logToConsole(M.DEBUG, t, e);
  }
  trace(t, e) {
    this.logToConsole(M.TRACE, t, e);
  }
  log(t, e, s) {
    this.logToConsole(t, e, s);
  }
};
Y.SEVERITY = {
  [M.FATAL]: 0,
  [M.ERROR]: 1,
  [M.WARN]: 2,
  [M.INFO]: 3,
  [M.DEBUG]: 4,
  [M.TRACE]: 5
};
let vt = Y;
function Te() {
  const n = Date.now();
  return {
    elapsed: () => Date.now() - n
  };
}
class G {
  constructor() {
    this.connectionMap = /* @__PURE__ */ new Map();
  }
  static getInstance() {
    return G.instace || (G.instace = new G()), G.instace;
  }
  getConnection(t, e) {
    if (this.connectionMap.has(t))
      return this.connectionMap.get(t);
    const s = new ve(t, e);
    return this.connectionMap.set(t, s), s;
  }
}
class ve {
  constructor(t, e) {
    this.subListeners = {}, this.rpcListeners = {}, this.rpcId = 0, this.onCloseCallbacks = [], this._WS = qe(), this.url = new URL(t), this.messageQueue = new Ie(), this._logger = e ?? O;
  }
  connect() {
    return this.connectionPromise || (this.connectionPromise = new Promise((t, e) => {
      try {
        this.ws = new this._WS(this.url.toString()), this.onCloseCallbacks = [];
      } catch (s) {
        e(s);
        return;
      }
      this.ws.onopen = () => {
        t();
      }, this.ws.onerror = () => {
        e(new Error("Failed to open WebSocket"));
      }, this.ws.onmessage = (s) => {
        this.messageQueue.enqueue(s.data), this.handlingInterval || (this.handlingInterval = setInterval(
          this.handleNextMesage.bind(this),
          0
        ));
      }, this.ws.onclose = (s) => {
        this.connectionPromise = void 0, this.onCloseCallbacks.forEach((r) => r(s));
      };
    })), this.connectionPromise;
  }
  sendRequest(t, e) {
    if (this.ws?.readyState !== 1) {
      if (t === "unsubscribe")
        return;
      throw new Error("Socket not open...");
    }
    const s = this.rpcId;
    this.rpcId++;
    const r = JSON.stringify({ jsonrpc: "2.0", method: t, params: e, id: s });
    this.ws?.send(r);
  }
  closeSubscription(t) {
    this.ws?.send(JSON.stringify(["CLOSE", t]));
  }
  addSubListener(t, e) {
    (this.subListeners[t] = this.subListeners[t] || []).push(e);
  }
  //TODO: Move to RPCManagerClass
  addRpcListener(t, e, s) {
    this.rpcListeners[s] = { callback: t, errorCallback: e };
  }
  //TODO: Move to RPCManagerClass
  removeRpcListener(t) {
    delete this.rpcListeners[t];
  }
  removeListener(t, e) {
    if (this.subListeners[t]) {
      if (this.subListeners[t].length === 1) {
        delete this.subListeners[t];
        return;
      }
      this.subListeners[t] = this.subListeners[t].filter((s) => s !== e);
    }
  }
  async ensureConnection() {
    this.ws?.readyState !== 1 && await this.connect();
  }
  handleNextMesage() {
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
        this.rpcListeners[e.id] && (this.rpcListeners[e.id].errorCallback(e.error), this.removeRpcListener(e.id));
      else if ("method" in e && !("id" in e)) {
        const s = e.params.subId;
        if (!s)
          return;
        if (this.subListeners[s]?.length > 0) {
          const r = e;
          this.subListeners[s].forEach((o) => o(r.params.payload));
        }
      }
    } catch (s) {
      this._logger.error("Error doing handleNextMesage", { e: s });
      return;
    }
  }
  createSubscription(t, e, s) {
    if (this.ws?.readyState !== 1)
      return s(new Error("Socket is not open"));
    const r = (Math.random() + 1).toString(36).substring(7);
    return this.addRpcListener(
      () => {
        this.addSubListener(r, e);
      },
      (o) => {
        s(new Error(o.message));
      },
      this.rpcId
    ), this.sendRequest("subscribe", { ...t, subId: r }), this.rpcId++, r;
  }
  cancelSubscription(t, e) {
    this.removeRpcListener(t), this.removeListener(t, e), this.rpcId++, this.sendRequest("unsubscribe", { subId: t });
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
const es = {
  UNSPENT: "UNSPENT",
  PENDING: "PENDING",
  SPENT: "SPENT"
}, Z = {
  UNPAID: "UNPAID",
  PENDING: "PENDING",
  PAID: "PAID"
}, ft = {
  UNPAID: "UNPAID",
  PAID: "PAID",
  ISSUED: "ISSUED"
};
var xe = /* @__PURE__ */ ((n) => (n.POST = "post", n.NOSTR = "nostr", n))(xe || {});
class tt extends Error {
  constructor(t, e) {
    super(t), this.status = e, this.name = "HttpResponseError", Object.setPrototypeOf(this, tt.prototype);
  }
}
class _t extends Error {
  constructor(t) {
    super(t), this.name = "NetworkError", Object.setPrototypeOf(this, _t.prototype);
  }
}
class bt extends tt {
  constructor(t, e) {
    super(e || "Unknown mint operation error", 400), this.code = t, this.name = "MintOperationError", Object.setPrototypeOf(this, bt.prototype);
  }
}
let jt = {}, Ht = O;
function ss(n) {
  jt = n;
}
function Ke(n) {
  Ht = n;
}
async function Re({
  endpoint: n,
  requestBody: t,
  headers: e,
  ...s
}) {
  const r = t ? JSON.stringify(t) : void 0, o = {
    Accept: "application/json, text/plain, */*",
    ...r ? { "Content-Type": "application/json" } : void 0,
    ...e
  };
  let i;
  try {
    i = await fetch(n, { body: r, headers: o, ...s });
  } catch (a) {
    throw new _t(a instanceof Error ? a.message : "Network request failed");
  }
  if (!i.ok) {
    const a = await i.json().catch(() => ({ error: "bad response" }));
    throw i.status === 400 && "code" in a && "detail" in a ? new bt(a.code, a.detail) : new tt(
      "error" in a ? a.error : a.detail || "HTTP request failed",
      i.status
    );
  }
  try {
    return await i.json();
  } catch (a) {
    throw Ht.error("Failed to parse HTTP response", { err: a }), new tt("bad response", i.status);
  }
}
async function x(n) {
  return await Re({ ...n, ...jt });
}
function ht(n, t) {
  return n.state || (t.warn(
    "Field 'state' not found in MeltQuoteResponse. Update NUT-05 of mint: https://github.com/cashubtc/nuts/pull/136)"
  ), typeof n.paid == "boolean" && (n.state = n.paid ? Z.PAID : Z.UNPAID)), n;
}
function xt(n, t) {
  return n.state || (t.warn(
    "Field 'state' not found in MintQuoteResponse. Update NUT-04 of mint: https://github.com/cashubtc/nuts/pull/141)"
  ), typeof n.paid == "boolean" && (n.state = n.paid ? ft.PAID : ft.UNPAID)), n;
}
function De(n, t) {
  return Array.isArray(n?.contact) && n?.contact.length > 0 && (n.contact = n.contact.map((e) => Array.isArray(e) && e.length === 2 && typeof e[0] == "string" && typeof e[1] == "string" ? (t.warn(
    "Mint returned deprecated 'contact' field: Update NUT-06: https://github.com/cashubtc/nuts/pull/117"
  ), { method: e[0], info: e[1] }) : e)), n;
}
class pt {
  constructor(t) {
    this._mintInfo = t, t.nuts[21]?.protected_endpoints && (this._clearAuthProtectedEndpoints = {
      cache: {},
      apiReturn: t.nuts[21].protected_endpoints.map((e) => ({
        method: e.method,
        regex: new RegExp(e.path)
      }))
    }), t.nuts[22]?.protected_endpoints && (this._blindAuthProtectedEndpoints = {
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
      case 21:
        return this.checkNut21();
      case 22:
        return this.checkNut22();
      default:
        throw new Error("nut is not supported by cashu-ts");
    }
  }
  requiresClearAuthToken(t) {
    if (!this._clearAuthProtectedEndpoints)
      return !1;
    if (typeof this._clearAuthProtectedEndpoints.cache[t] == "boolean")
      return this._clearAuthProtectedEndpoints.cache[t];
    const e = this._clearAuthProtectedEndpoints.apiReturn.some(
      (s) => s.regex.test(t)
    );
    return this._clearAuthProtectedEndpoints.cache[t] = e, e;
  }
  requiresBlindAuthToken(t) {
    if (!this._blindAuthProtectedEndpoints)
      return !1;
    if (typeof this._blindAuthProtectedEndpoints.cache[t] == "boolean")
      return this._blindAuthProtectedEndpoints.cache[t];
    const e = this._blindAuthProtectedEndpoints.apiReturn.some(
      (s) => s.regex.test(t)
    );
    return this._blindAuthProtectedEndpoints.cache[t] = e, e;
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
  checkNut21() {
    return this._mintInfo.nuts[21] ? {
      supported: !0,
      openid_discovery: this._mintInfo.nuts[21].openid_discovery,
      client_id: this._mintInfo.nuts[21].client_id
    } : { supported: !1 };
  }
  checkNut22() {
    return this._mintInfo.nuts[22] ? {
      supported: !0,
      bat_max_mint: this._mintInfo.nuts[22].bat_max_mint
    } : { supported: !1 };
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
}
class K {
  /**
   * @param _mintUrl requires mint URL to create this object
   * @param _customRequest if passed, use custom request implementation for network communication with the mint
   * @param [blindAuthTokenGetter] a function that is called by the CashuMint instance to obtain a NUT-22 BlindedAuthToken (e.g. from a database or localstorage). This function should consume the BAT as they are one-time use tokens.
   * @param [clearAuthTokenGetter] a function that is called by the CashuMint instance to obtain a NUT-21 ClearAuthToken (e.g. from a database or localstorage)
   */
  constructor(t, e, s, r, o) {
    this._mintUrl = t, this._customRequest = e, this._mintUrl = Qt(t), this._customRequest = e, this._blindAuthTokenGetter = s, this._clearAuthTokenGetter = r, this._logger = o?.logger ?? O, Ke(this._logger);
  }
  //TODO: v3 - refactor CashuMint to take two or less args.
  get mintUrl() {
    return this._mintUrl;
  }
  /**
   * fetches mints info at the /info endpoint
   * @param mintUrl
   * @param customRequest
   */
  static async getInfo(t, e, s) {
    const r = s ?? O, i = await (e || x)({
      endpoint: v(t, "/v1/info")
    });
    return De(i, r);
  }
  /**
   * fetches mints info at the /info endpoint
   */
  async getInfo() {
    return K.getInfo(this._mintUrl, this._customRequest, this._logger);
  }
  async getLazyMintInfo() {
    if (this._mintInfo)
      return this._mintInfo;
    const t = await K.getInfo(this._mintUrl, this._customRequest);
    return this._mintInfo = new pt(t), this._mintInfo;
  }
  /**
   * Performs a swap operation with ecash inputs and outputs.
   * @param mintUrl
   * @param swapPayload payload containing inputs and outputs
   * @param customRequest
   * @param headers Authentication headers for protected endpoints
   * @returns signed outputs
   */
  static async swap(t, e, s, r) {
    const i = await (s || x)({
      endpoint: v(t, "/v1/swap"),
      method: "POST",
      requestBody: e,
      headers: r || {}
    });
    if (!U(i) || !Array.isArray(i?.signatures))
      throw new Error(i.detail ?? "bad response");
    return i;
  }
  /**
   * Performs a swap operation with ecash inputs and outputs.
   * @param swapPayload payload containing inputs and outputs
   * @returns signed outputs
   */
  async swap(t) {
    const e = await this.getAuthHeaders("/v1/swap");
    return K.swap(this._mintUrl, t, this._customRequest, e);
  }
  /**
   * Requests a new mint quote from the mint.
   * @param mintUrl
   * @param mintQuotePayload Payload for creating a new mint quote
   * @param customRequest
   * @param headers Authentication headers for protected endpoints
   * @returns the mint will create and return a new mint quote containing a payment request for the specified amount and unit
   */
  static async createMintQuote(t, e, s, r, o) {
    const i = o ?? O, c = await (s || x)({
      endpoint: v(t, "/v1/mint/quote/bolt11"),
      method: "POST",
      requestBody: e,
      headers: r || {}
    });
    return xt(c, i);
  }
  /**
   * Requests a new mint quote from the mint.
   * @param mintQuotePayload Payload for creating a new mint quote
   * @returns the mint will create and return a new mint quote containing a payment request for the specified amount and unit
   */
  async createMintQuote(t) {
    const e = await this.getAuthHeaders("/v1/mint/quote/bolt11");
    return K.createMintQuote(
      this._mintUrl,
      t,
      this._customRequest,
      e,
      this._logger
    );
  }
  /**
   * Gets an existing mint quote from the mint.
   * @param mintUrl
   * @param quote Quote ID
   * @param customRequest
   * @param headers Authentication headers for protected endpoints
   * @returns the mint will create and return a Lightning invoice for the specified amount
   */
  static async checkMintQuote(t, e, s, r, o) {
    const i = o ?? O, c = await (s || x)({
      endpoint: v(t, "/v1/mint/quote/bolt11", e),
      method: "GET",
      headers: r || {}
    });
    return xt(c, i);
  }
  /**
   * Gets an existing mint quote from the mint.
   * @param quote Quote ID
   * @returns the mint will create and return a Lightning invoice for the specified amount
   */
  async checkMintQuote(t) {
    const e = await this.getAuthHeaders(`/v1/mint/quote/bolt11/${t}`);
    return K.checkMintQuote(
      this._mintUrl,
      t,
      this._customRequest,
      e,
      this._logger
    );
  }
  /**
   * Mints new tokens by requesting blind signatures on the provided outputs.
   * @param mintUrl
   * @param mintPayload Payload containing the outputs to get blind signatures on
   * @param customRequest
   * @param headers Authentication headers for protected endpoints
   * @returns serialized blinded signatures
   */
  static async mint(t, e, s, r) {
    const i = await (s || x)({
      endpoint: v(t, "/v1/mint/bolt11"),
      method: "POST",
      requestBody: e,
      headers: r || {}
    });
    if (!U(i) || !Array.isArray(i?.signatures))
      throw new Error("bad response");
    return i;
  }
  /**
   * Mints new tokens by requesting blind signatures on the provided outputs.
   * @param mintPayload Payload containing the outputs to get blind signatures on
   * @returns serialized blinded signatures
   */
  async mint(t) {
    const e = await this.getAuthHeaders("/v1/mint/bolt11");
    return K.mint(this._mintUrl, t, this._customRequest, e);
  }
  /**
   * Requests a new melt quote from the mint.
   * @param mintUrl
   * @param MeltQuotePayload
   * @param customRequest
   * @param headers Authentication headers for protected endpoints
   * @returns
   */
  static async createMeltQuote(t, e, s, r, o) {
    const i = o ?? O, c = await (s || x)({
      endpoint: v(t, "/v1/melt/quote/bolt11"),
      method: "POST",
      requestBody: e,
      headers: r || {}
    }), u = ht(c, i);
    if (!U(u) || typeof u?.amount != "number" || typeof u?.fee_reserve != "number" || typeof u?.quote != "string")
      throw new Error("bad response");
    return u;
  }
  /**
   * Requests a new melt quote from the mint.
   * @param MeltQuotePayload
   * @returns
   */
  async createMeltQuote(t) {
    const e = await this.getAuthHeaders("/v1/melt/quote/bolt11");
    return K.createMeltQuote(
      this._mintUrl,
      t,
      this._customRequest,
      e,
      this._logger
    );
  }
  /**
   * Gets an existing melt quote.
   * @param mintUrl
   * @param quote Quote ID
   * @param customRequest
   * @param headers Authentication headers for protected endpoints
   * @returns
   */
  static async checkMeltQuote(t, e, s, r, o) {
    const i = o ?? O, c = await (s || x)({
      endpoint: v(t, "/v1/melt/quote/bolt11", e),
      method: "GET",
      headers: r || {}
    }), u = ht(c, i);
    if (!U(u) || typeof u?.amount != "number" || typeof u?.fee_reserve != "number" || typeof u?.quote != "string" || typeof u?.state != "string" || !Object.values(Z).includes(u.state))
      throw new Error("bad response");
    return u;
  }
  /**
   * Gets an existing melt quote.
   * @param quote Quote ID
   * @returns
   */
  async checkMeltQuote(t) {
    const e = await this.getAuthHeaders(`/v1/melt/quote/bolt11/${t}`);
    return K.checkMeltQuote(
      this._mintUrl,
      t,
      this._customRequest,
      e,
      this._logger
    );
  }
  /**
   * Requests the mint to pay for a Bolt11 payment request by providing ecash as inputs to be spent. The inputs contain the amount and the fee_reserves for a Lightning payment. The payload can also contain blank outputs in order to receive back overpaid Lightning fees.
   * @param mintUrl
   * @param meltPayload
   * @param customRequest
   * @param headers Authentication headers for protected endpoints
   * @returns
   */
  static async melt(t, e, s, r, o) {
    const i = o ?? O, c = await (s || x)({
      endpoint: v(t, "/v1/melt/bolt11"),
      method: "POST",
      requestBody: e,
      headers: r || {}
    }), u = ht(c, i);
    if (!U(u) || typeof u?.state != "string" || !Object.values(Z).includes(u.state))
      throw new Error("bad response");
    return u;
  }
  /**
   * Ask mint to perform a melt operation. This pays a lightning invoice and destroys tokens matching its amount + fees
   * @param meltPayload
   * @returns
   */
  async melt(t) {
    const e = await this.getAuthHeaders("/v1/melt/bolt11");
    return K.melt(this._mintUrl, t, this._customRequest, e, this._logger);
  }
  /**
   * Checks if specific proofs have already been redeemed
   * @param mintUrl
   * @param checkPayload
   * @param customRequest
   * @returns redeemed and unredeemed ordered list of booleans
   */
  static async check(t, e, s, r) {
    const i = await (s || x)({
      endpoint: v(t, "/v1/checkstate"),
      method: "POST",
      requestBody: e,
      headers: r || {}
    });
    if (!U(i) || !Array.isArray(i?.states))
      throw new Error("bad response");
    return i;
  }
  /**
   * Get the mints public keys
   * @param mintUrl
   * @param keysetId optional param to get the keys for a specific keyset. If not specified, the keys from all active keysets are fetched
   * @param customRequest
   * @returns
   */
  static async getKeys(t, e, s) {
    e && (e = e.replace(/\//g, "_").replace(/\+/g, "-"));
    const o = await (s || x)({
      endpoint: e ? v(t, "/v1/keys", e) : v(t, "/v1/keys")
    });
    if (!U(o) || !Array.isArray(o.keysets))
      throw new Error("bad response");
    return o;
  }
  /**
   * Get the mints public keys
   * @param keysetId optional param to get the keys for a specific keyset. If not specified, the keys from all active keysets are fetched
   * @returns the mints public keys
   */
  async getKeys(t, e) {
    return await K.getKeys(
      e || this._mintUrl,
      t,
      this._customRequest
    );
  }
  /**
   * Get the mints keysets in no specific order
   * @param mintUrl
   * @param customRequest
   * @returns all the mints past and current keysets.
   */
  static async getKeySets(t, e) {
    return (e || x)({ endpoint: v(t, "/v1/keysets") });
  }
  /**
   * Get the mints keysets in no specific order
   * @returns all the mints past and current keysets.
   */
  async getKeySets() {
    return K.getKeySets(this._mintUrl, this._customRequest);
  }
  /**
   * Checks if specific proofs have already been redeemed
   * @param checkPayload
   * @returns redeemed and unredeemed ordered list of booleans
   */
  async check(t) {
    const e = await this.getAuthHeaders("/v1/checkstate");
    return K.check(this._mintUrl, t, this._customRequest, e);
  }
  static async restore(t, e, s, r) {
    const i = await (s || x)({
      endpoint: v(t, "/v1/restore"),
      method: "POST",
      requestBody: e,
      headers: r || {}
    });
    if (!U(i) || !Array.isArray(i?.outputs) || !Array.isArray(i?.signatures))
      throw new Error("bad response");
    return i;
  }
  async restore(t) {
    const e = await this.getAuthHeaders("/v1/restore");
    return K.restore(this._mintUrl, t, this._customRequest, e);
  }
  /**
   * Tries to establish a websocket connection with the websocket mint url according to NUT-17
   */
  async connectWebSocket() {
    if (this.ws)
      await this.ws.ensureConnection();
    else {
      const t = new URL(this._mintUrl), e = "v1/ws";
      t.pathname && (t.pathname.endsWith("/") ? t.pathname += e : t.pathname += "/" + e), this.ws = G.getInstance().getConnection(
        `${t.protocol === "https:" ? "wss" : "ws"}://${t.host}${t.pathname}`
      );
      try {
        await this.ws.connect();
      } catch (s) {
        throw this._logger.error("Failed to connect to WebSocket...", { e: s }), new Error("Failed to connect to WebSocket...");
      }
    }
  }
  /**
   * Closes a websocket connection
   */
  disconnectWebSocket() {
    this.ws && this.ws.close();
  }
  get webSocketConnection() {
    return this.ws;
  }
  async getAuthHeaders(t) {
    const e = {}, s = await this.getLazyMintInfo();
    if (s.requiresClearAuthToken(t)) {
      if (!this._clearAuthTokenGetter)
        throw new Error("Can not call a protected endpoint without clearAuthTokenGetter");
      const r = await this._clearAuthTokenGetter();
      e["Clear-auth"] = r;
    }
    if (s.requiresBlindAuthToken(t)) {
      if (!this._blindAuthTokenGetter)
        throw new Error("Can not call a protected endpoint without blindAuthTokenGetter");
      const r = await this._blindAuthTokenGetter();
      e["Blind-auth"] = r;
    }
    return e;
  }
}
class lt {
  constructor(t, e, s) {
    this.amount = t, this.B_ = e, this.id = s;
  }
  getSerializedBlindedMessage() {
    return { amount: this.amount, B_: this.B_.toHex(!0), id: this.id };
  }
}
function dt(n) {
  return typeof n == "function";
}
class N {
  constructor(t, e, s) {
    this.secret = s, this.blindingFactor = e, this.blindedMessage = t;
  }
  toProof(t, e) {
    let s;
    t.dleq && (s = {
      s: St(t.dleq.s),
      e: St(t.dleq.e),
      r: this.blindingFactor
    });
    const r = {
      id: t.id,
      amount: t.amount,
      C_: ot(t.C_),
      dleq: s
    }, o = ot(e.keys[t.amount]), i = Jt(r, this.blindingFactor, this.secret, o);
    return {
      ...Xt(i),
      ...s && {
        dleq: {
          s: J(s.s),
          e: J(s.e),
          r: ke(s.r ?? BigInt(0))
        }
      }
    };
  }
  static createP2PKData(t, e, s, r) {
    return R(e, s.keys, r).map((i) => this.createSingleP2PKData(t, i, s.id));
  }
  static createSingleP2PKData(t, e, s) {
    const r = Array.isArray(t.pubkey) ? t.pubkey : [t.pubkey], o = Math.max(1, Math.min(t.requiredSignatures || 1, r.length)), i = Math.max(
      1,
      Math.min(t.requiredRefundSignatures || 1, t.refundKeys ? t.refundKeys.length : 1)
    ), a = [
      "P2PK",
      {
        nonce: J(It(32)),
        data: r[0],
        // Primary key
        tags: []
      }
    ];
    t.locktime && a[1].tags.push(["locktime", String(t.locktime)]), r.length > 1 && (a[1].tags.push(["pubkeys", ...r.slice(1)]), o > 1 && a[1].tags.push(["n_sigs", String(o)])), t.refundKeys && (a[1].tags.push(["refund", ...t.refundKeys]), i > 1 && a[1].tags.push(["n_sigs_refund", String(i)]));
    const c = JSON.stringify(a), u = new TextEncoder().encode(c), { r: h, B_: l } = ut(u);
    return new N(
      new lt(e, l, s).getSerializedBlindedMessage(),
      h,
      u
    );
  }
  static createRandomData(t, e, s) {
    return R(t, e.keys, s).map((o) => this.createSingleRandomData(o, e.id));
  }
  static createSingleRandomData(t, e) {
    const s = J(It(32)), r = new TextEncoder().encode(s), { r: o, B_: i } = ut(r);
    return new N(
      new lt(t, i, e).getSerializedBlindedMessage(),
      o,
      r
    );
  }
  static createDeterministicData(t, e, s, r, o) {
    return R(t, r.keys, o).map(
      (a, c) => this.createSingleDeterministicData(a, e, s + c, r.id)
    );
  }
  static createSingleDeterministicData(t, e, s, r) {
    const o = Yt(e, r, s), i = J(o), a = new TextEncoder().encode(i), c = we(Zt(e, r, s)), { r: u, B_: h } = ut(a, c);
    return new N(
      new lt(t, h, r).getSerializedBlindedMessage(),
      u,
      a
    );
  }
}
const Fe = 3, Ue = "sat";
class ns {
  /**
   * @param mint Cashu mint instance is used to make api calls
   * @param options.unit optionally set unit (default is 'sat')
   * @param options.keys public keys from the mint (will be fetched from mint if not provided)
   * @param options.keysets keysets from the mint (will be fetched from mint if not provided)
   * @param options.mintInfo mint info from the mint (will be fetched from mint if not provided)
   * @param options.denominationTarget target number proofs per denomination (default: see @constant DEFAULT_DENOMINATION_TARGET)
   * @param options.bip39seed BIP39 seed for deterministic secrets.
   * @param options.keepFactory A function that will be used by all parts of the library that produce proofs to be kept (change, etc.).
   * This can lead to poor performance, in which case the seed should be directly provided
   */
  constructor(t, e) {
    this._keys = /* @__PURE__ */ new Map(), this._keysets = [], this._seed = void 0, this._unit = Ue, this._mintInfo = void 0, this._denominationTarget = Fe, this.mint = t, this._logger = e?.logger ?? O;
    let s = [];
    if (e?.keys && !Array.isArray(e.keys) ? s = [e.keys] : e?.keys && Array.isArray(e?.keys) && (s = e?.keys), s && s.forEach((r) => this._keys.set(r.id, r)), e?.unit && (this._unit = e?.unit), e?.keysets && (this._keysets = e.keysets), e?.mintInfo && (this._mintInfo = new pt(e.mintInfo)), e?.denominationTarget && (this._denominationTarget = e.denominationTarget), e?.bip39seed) {
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
   * Get information about the mint
   * @returns mint info
   */
  async getMintInfo() {
    const t = await this.mint.getInfo();
    return this._mintInfo = new pt(t), this._mintInfo;
  }
  /**
   * Get stored information about the mint or request it if not loaded.
   * @returns mint info
   */
  async lazyGetMintInfo() {
    return this._mintInfo ? this._mintInfo : await this.getMintInfo();
  }
  /**
   * Load mint information, keysets and keys. This function can be called if no keysets are passed in the constructor
   */
  async loadMint() {
    await this.getMintInfo(), await this.getKeySets(), await this.getKeys();
  }
  /**
   * Choose a keyset to activate based on the lowest input fee
   *
   * Note: this function will filter out deprecated base64 keysets
   *
   * @param keysets keysets to choose from
   * @returns active keyset
   */
  getActiveKeyset(t) {
    let e = t.filter((r) => r.active && r.unit === this._unit);
    e = e.filter((r) => r.id.startsWith("00"));
    const s = e.sort(
      (r, o) => (r.input_fee_ppk ?? 0) - (o.input_fee_ppk ?? 0)
    )[0];
    if (!s)
      throw new Error("No active keyset found");
    return s;
  }
  /**
   * Get keysets from the mint with the unit of the wallet
   * @returns keysets with wallet's unit
   */
  async getKeySets() {
    const e = (await this.mint.getKeySets()).keysets.filter((s) => s.unit === this._unit);
    return this._keysets = e, this._keysets;
  }
  /**
   * Get all active keys from the mint and set the keyset with the lowest fees as the active wallet keyset.
   * @returns keyset
   */
  async getAllKeys() {
    const t = await this.mint.getKeys();
    return this._keys = new Map(t.keysets.map((e) => [e.id, e])), this.keysetId = this.getActiveKeyset(this._keysets).id, t.keysets;
  }
  /**
   * Get public keys from the mint. If keys were already fetched, it will return those.
   *
   * If `keysetId` is set, it will fetch and return that specific keyset.
   * Otherwise, we select an active keyset with the unit of the wallet.
   *
   * @param keysetId optional keysetId to get keys for
   * @param forceRefresh? if set to true, it will force refresh the keyset from the mint
   * @returns keyset
   */
  async getKeys(t, e) {
    if ((!(this._keysets.length > 0) || e) && await this.getKeySets(), t || (t = this.getActiveKeyset(this._keysets).id), !this._keysets.find((s) => s.id === t) && (await this.getKeySets(), !this._keysets.find((s) => s.id === t)))
      throw new Error(`could not initialize keys. No keyset with id '${t}' found`);
    if (!this._keys.get(t)) {
      const s = await this.mint.getKeys(t);
      this._keys.set(t, s.keysets[0]);
    }
    return this.keysetId = t, this._keys.get(t);
  }
  /**
   * Receive an encoded or raw Cashu token (only supports single tokens. It will only process the first token in the token array)
   * @param {(string|Token)} token - Cashu token, either as string or decoded
   * @param {ReceiveOptions} [options] - Optional configuration for token processing
   * @returns New token with newly created proofs, token entries that had errors
   */
  async receive(t, e) {
    const { requireDleq: s, keysetId: r, outputAmounts: o, counter: i, pubkey: a, privkey: c, outputData: u, p2pk: h } = e || {};
    typeof t == "string" && (t = Ae(t));
    const l = await this.getKeys(r);
    if (s && t.proofs.some((S) => !Wt(S, l)))
      throw new Error("Token contains proofs with invalid DLEQ");
    const p = W(t.proofs) - this.getFeesForProofs(t.proofs);
    let d;
    u ? d = { send: u } : this._keepFactory && (d = { send: this._keepFactory });
    const g = this.createSwapPayload(
      p,
      t.proofs,
      l,
      o,
      i,
      a,
      c,
      d,
      h
    ), { signatures: P } = await this.mint.swap(g.payload), _ = g.outputData.map((S, k) => S.toProof(P[k], l)), A = [];
    return g.sortedIndices.forEach((S, k) => {
      A[S] = _[k];
    }), A;
  }
  /**
   * Send proofs of a given amount, by providing at least the required amount of proofs
   * @param amount amount to send
   * @param proofs array of proofs (accumulated amount of proofs must be >= than amount)
   * @param {SendOptions} [options] - Optional parameters for configuring the send operation
   * @returns {SendResponse}
   */
  async send(t, e, s) {
    const {
      offline: r,
      includeFees: o,
      includeDleq: i,
      keysetId: a,
      outputAmounts: c,
      pubkey: u,
      privkey: h,
      outputData: l
    } = s || {};
    if (i && (e = e.filter((P) => P.dleq != null)), W(e) < t)
      throw new Error("Not enough funds available to send");
    const { keep: p, send: d } = this.selectProofsToSend(
      e,
      t,
      s?.includeFees
    ), g = o ? this.getFeesForProofs(d) : 0;
    if (!r && (W(d) != t + g || // if the exact amount cannot be selected
    c || u || h || a || l)) {
      const P = await this.swap(t, e, s);
      let { keep: _, send: A } = P;
      const S = P.serialized;
      return { keep: _, send: A, serialized: S };
    }
    if (W(d) < t + g)
      throw new Error("Not enough funds available to send");
    return { keep: p, send: d };
  }
  /**
   * Selects proofs to send based on amount and fee inclusion.
   * @remarks Uses an adapted Randomized Greedy with Local Improvement (RGLI)
   * algorithm, which has a time complexity O(n log n) and space complexity O(n).
   * @see https://crypto.ethz.ch/publications/files/Przyda02.pdf
   * @param proofs Array of Proof objects available to select from
   * @param amountToSend The target amount to send
   * @param includeFees Optional boolean to include fees; Default: false
   * @returns SendResponse containing proofs to keep and proofs to send
   */
  selectProofsToSend(t, e, s = !1) {
    const h = Te();
    let l = null, p = 1 / 0, d = 0, g = 0;
    const P = (m, f) => m - (s ? Math.ceil(f / 1e3) : 0), _ = (m) => {
      const f = [...m];
      for (let y = f.length - 1; y > 0; y--) {
        const w = Math.floor(Math.random() * (y + 1));
        [f[y], f[w]] = [f[w], f[y]];
      }
      return f;
    }, A = (m, f, y) => {
      let w = 0, b = m.length - 1, E = null;
      for (; w <= b; ) {
        const L = Math.floor((w + b) / 2), j = m[L].exFee;
        (y ? j <= f : j >= f) ? (E = L, y ? w = L + 1 : b = L - 1) : y ? b = L - 1 : w = L + 1;
      }
      return y ? E : w < m.length ? w : null;
    }, S = (m, f) => {
      const y = f.exFee;
      let w = 0, b = m.length;
      for (; w < b; ) {
        const E = Math.floor((w + b) / 2);
        m[E].exFee < y ? w = E + 1 : b = E;
      }
      m.splice(w, 0, f);
    }, k = (m, f) => P(m, f) < e ? 1 / 0 : m + f / 1e3 - e;
    let q = 0, B = 0;
    const st = t.map((m) => {
      const f = this.getProofFeePPK(m), y = s ? m.amount - f / 1e3 : m.amount, w = { proof: m, exFee: y, ppkfee: f };
      return (!s || y > 0) && (q += m.amount, B += f), w;
    });
    let I = s ? st.filter((m) => m.exFee > 0) : st;
    if (I.sort((m, f) => m.exFee - f.exFee), I.length > 0) {
      let m;
      {
        const f = A(I, e, !1);
        if (f !== null) {
          const y = I[f].exFee;
          m = A(I, y, !0) + 1;
        } else
          m = I.length;
      }
      for (let f = m; f < I.length; f++)
        q -= I[f].proof.amount, B -= I[f].ppkfee;
      I = I.slice(0, m);
    }
    const nt = P(q, B);
    if (e <= 0 || e > nt)
      return { keep: t, send: [] };
    const V = Math.min(
      Math.ceil(e * (1 + 0 / 100)),
      e + 0,
      nt
    );
    for (let m = 0; m < 60; m++) {
      let f = [], y = 0, w = 0;
      for (const T of _(I)) {
        const D = y + T.proof.amount, F = w + T.ppkfee, C = P(D, F);
        if (f.push(T), y = D, w = F, C >= e) break;
      }
      const b = new Set(f);
      let E = I.filter((T) => !b.has(T));
      const L = _(Array.from({ length: f.length }, (T, D) => D)).slice(
        0,
        5e3
      );
      for (const T of L) {
        const D = P(y, w);
        if (D === e || D >= e && D <= V)
          break;
        const F = f[T], C = y - F.proof.amount, H = w - F.ppkfee, $t = P(C, H), At = e - $t, ct = A(E, At, !1);
        if (ct !== null) {
          const rt = E[ct];
          (At >= 0 || rt.exFee <= F.exFee) && (f[T] = rt, y = C + rt.proof.amount, w = H + rt.ppkfee, E.splice(ct, 1), S(E, F));
        }
      }
      const j = k(y, w);
      if (j < p) {
        this._logger.debug(
          "selectProofsToSend: best solution found in trial #{trial} - amount: {amount}, delta: {delta}",
          { trial: m, amount: y, delta: j }
        ), l = [...f].sort((D, F) => F.exFee - D.exFee), p = j, d = y, g = w;
        let T = [...l];
        for (; T.length > 1 && p > 0; ) {
          const D = T.pop(), F = y - D.proof.amount, C = w - D.ppkfee, H = k(F, C);
          if (H == 1 / 0) break;
          H < p && (l = [...T], p = H, d = F, g = C, y = F, w = C);
        }
      }
      if (l && p < 1 / 0) {
        const T = P(d, g);
        if (T === e || T >= e && T <= V)
          break;
      }
      if (h.elapsed() > 1e3) {
        this._logger.warn("Proof selection took too long. Returning best selection so far.");
        break;
      }
    }
    if (l && p < 1 / 0) {
      const m = l.map((w) => w.proof), f = new Set(m), y = t.filter((w) => !f.has(w));
      return this._logger.info("Proof selection took {time}ms", { time: h.elapsed() }), { keep: y, send: m };
    }
    return { keep: t, send: [] };
  }
  /**
   * calculates the fees based on inputs (proofs)
   * @param proofs input proofs to calculate fees for
   * @returns fee amount
   * @throws throws an error if the proofs keyset is unknown
   */
  getFeesForProofs(t) {
    const e = t.reduce((s, r) => s + this.getProofFeePPK(r), 0);
    return Math.ceil(e / 1e3);
  }
  /**
   * Returns the current fee PPK for a proof according to the cached keyset
   * @param proof {Proof} A single proof
   * @returns feePPK {number} The feePPK for the selected proof
   * @throws throws an error if the proofs keyset is unknown
   */
  getProofFeePPK(t) {
    const e = this._keysets.find((s) => s.id === t.id);
    if (!e)
      throw new Error(`Could not get fee. No keyset found for keyset id: ${t.id}`);
    return e?.input_fee_ppk || 0;
  }
  /**
   * calculates the fees based on inputs for a given keyset
   * @param nInputs number of inputs
   * @param keysetId keysetId used to lookup `input_fee_ppk`
   * @returns fee amount
   */
  getFeesForKeyset(t, e) {
    return Math.floor(
      Math.max(
        (t * (this._keysets.find((r) => r.id === e)?.input_fee_ppk || 0) + 999) / 1e3,
        0
      )
    );
  }
  /**
   * Splits and creates sendable tokens
   * if no amount is specified, the amount is implied by the cumulative amount of all proofs
   * if both amount and preference are set, but the preference cannot fulfill the amount, then we use the default split
   *  @param {SwapOptions} [options] - Optional parameters for configuring the swap operation
   * @returns promise of the change- and send-proofs
   */
  async swap(t, e, s) {
    let { outputAmounts: r } = s || {};
    const { includeFees: o, keysetId: i, counter: a, pubkey: c, privkey: u, proofsWeHave: h, outputData: l, p2pk: p } = s || {}, d = await this.getKeys(i);
    let g = t;
    const P = W(e);
    let _ = r?.sendAmounts || R(g, d.keys);
    if (o) {
      let b = this.getFeesForKeyset(_.length, d.id), E = R(b, d.keys);
      for (; this.getFeesForKeyset(_.concat(E).length, d.id) > b; )
        b++, E = R(b, d.keys);
      _ = _.concat(E), g += b;
    }
    const { keep: A, send: S } = this.selectProofsToSend(
      e,
      g,
      !0
      // inc. fees
    ), k = W(S) - this.getFeesForProofs(S) - g;
    if (k < 0)
      throw new Error("Not enough balance to send");
    let q;
    if (!r?.keepAmounts && !h)
      q = R(k, d.keys);
    else if (!r?.keepAmounts && h)
      q = Mt(
        h,
        k,
        d.keys,
        this._denominationTarget
      );
    else if (r) {
      if (r.keepAmounts?.reduce((b, E) => b + E, 0) != k)
        throw new Error("Keep amounts do not match amount to keep");
      q = r.keepAmounts;
    }
    if (g + this.getFeesForProofs(S) > P)
      throw this._logger.error(
        `Not enough funds available (${P}) for swap amountToSend: ${g} + fee: ${this.getFeesForProofs(
          S
        )} | length: ${S.length}`
      ), new Error("Not enough funds available for swap");
    r = {
      keepAmounts: q,
      sendAmounts: _
    };
    const B = l?.keep || this._keepFactory, st = l?.send, I = this.createSwapPayload(
      g,
      S,
      d,
      r,
      a,
      c,
      u,
      { keep: B, send: st },
      p
    ), { signatures: nt } = await this.mint.swap(I.payload), V = I.outputData.map((b, E) => b.toProof(nt[E], d)), m = [], f = [], y = Array(I.keepVector.length), w = Array(V.length);
    return I.sortedIndices.forEach((b, E) => {
      y[b] = I.keepVector[E], w[b] = V[E];
    }), w.forEach((b, E) => {
      y[E] ? m.push(b) : f.push(b);
    }), {
      keep: [...m, ...A],
      send: f
    };
  }
  /**
   * Restores batches of deterministic proofs until no more signatures are returned from the mint
   * @param [gapLimit=300] the amount of empty counters that should be returned before restoring ends (defaults to 300)
   * @param [batchSize=100] the amount of proofs that should be restored at a time (defaults to 100)
   * @param [counter=0] the counter that should be used as a starting point (defaults to 0)
   * @param [keysetId] which keysetId to use for the restoration. If none is passed the instance's default one will be used
   */
  async batchRestore(t = 300, e = 100, s = 0, r) {
    const o = Math.ceil(t / e), i = [];
    let a, c = 0;
    for (; c < o; ) {
      const u = await this.restore(s, e, { keysetId: r });
      u.proofs.length > 0 ? (c = 0, i.push(...u.proofs), a = u.lastCounterWithSignature) : c++, s += e;
    }
    return { proofs: i, lastCounterWithSignature: a };
  }
  /**
   * Regenerates
   * @param start set starting point for count (first cycle for each keyset should usually be 0)
   * @param count set number of blinded messages that should be generated
   * @param options.keysetId set a custom keysetId to restore from. keysetIds can be loaded with `CashuMint.getKeySets()`
   */
  async restore(t, e, s) {
    const { keysetId: r } = s || {}, o = await this.getKeys(r);
    if (!this._seed)
      throw new Error("CashuWallet must be initialized with a seed to use restore");
    const i = Array(e).fill(1), a = N.createDeterministicData(
      i.length,
      this._seed,
      t,
      o,
      i
    ), { outputs: c, signatures: u } = await this.mint.restore({
      outputs: a.map((d) => d.blindedMessage)
    }), h = {};
    c.forEach((d, g) => h[d.B_] = u[g]);
    const l = [];
    let p;
    for (let d = 0; d < a.length; d++) {
      const g = h[a[d].blindedMessage.B_];
      g && (p = t + d, a[d].blindedMessage.amount = g.amount, l.push(a[d].toProof(g, o)));
    }
    return {
      proofs: l,
      lastCounterWithSignature: p
    };
  }
  /**
   * Requests a mint quote form the mint. Response returns a Lightning payment request for the requested given amount and unit.
   * @param amount Amount requesting for mint.
   * @param description optional description for the mint quote
   * @param pubkey optional public key to lock the quote to
   * @returns the mint will return a mint quote with a Lightning invoice for minting tokens of the specified amount and unit
   */
  async createMintQuote(t, e) {
    const s = {
      unit: this._unit,
      amount: t,
      description: e
    }, r = await this.mint.createMintQuote(s);
    return { ...r, amount: r.amount || t, unit: r.unit || this.unit };
  }
  /**
   * Requests a mint quote from the mint that is locked to a public key.
   * @param amount Amount requesting for mint.
   * @param pubkey public key to lock the quote to
   * @param description optional description for the mint quote
   * @returns the mint will return a mint quote with a Lightning invoice for minting tokens of the specified amount and unit.
   * The quote will be locked to the specified `pubkey`.
   */
  async createLockedMintQuote(t, e, s) {
    const { supported: r } = (await this.getMintInfo()).isSupported(20);
    if (!r)
      throw new Error("Mint does not support NUT-20");
    const o = {
      unit: this._unit,
      amount: t,
      description: s,
      pubkey: e
    }, i = await this.mint.createMintQuote(o);
    if (typeof i.pubkey != "string")
      throw new Error("Mint returned unlocked mint quote");
    {
      const a = i.pubkey;
      return { ...i, pubkey: a, amount: i.amount || t, unit: i.unit || this.unit };
    }
  }
  async checkMintQuote(t) {
    const e = typeof t == "string" ? t : t.quote, s = await this.mint.checkMintQuote(e);
    return typeof t == "string" ? s : { ...s, amount: s.amount || t.amount, unit: s.unit || t.unit };
  }
  async mintProofs(t, e, s) {
    let { outputAmounts: r } = s || {};
    const { counter: o, pubkey: i, p2pk: a, keysetId: c, proofsWeHave: u, outputData: h, privateKey: l } = s || {}, p = await this.getKeys(c);
    !r && u && (r = {
      keepAmounts: Mt(u, t, p.keys, this._denominationTarget),
      sendAmounts: []
    });
    let d = [];
    if (h)
      if (dt(h)) {
        const _ = R(t, p.keys, r?.keepAmounts);
        for (let A = 0; A < _.length; A++)
          d.push(h(_[A], p));
      } else
        d = h;
    else if (this._keepFactory) {
      const _ = R(t, p.keys, r?.keepAmounts);
      for (let A = 0; A < _.length; A++)
        d.push(this._keepFactory(_[A], p));
    } else
      d = this.createOutputData(
        t,
        p,
        o,
        i,
        r?.keepAmounts,
        a
      );
    let g;
    if (typeof e != "string") {
      if (!l)
        throw new Error("Can not sign locked quote without private key");
      const _ = d.map((S) => S.blindedMessage), A = Vt(l, e.quote, _);
      g = {
        outputs: _,
        quote: e.quote,
        signature: A
      };
    } else
      g = {
        outputs: d.map((_) => _.blindedMessage),
        quote: e
      };
    const { signatures: P } = await this.mint.mint(g);
    return d.map((_, A) => _.toProof(P[A], p));
  }
  /**
   * Requests a melt quote from the mint. Response returns amount and fees for a given unit in order to pay a Lightning invoice.
   * @param invoice LN invoice that needs to get a fee estimate
   * @returns the mint will create and return a melt quote for the invoice with an amount and fee reserve
   */
  async createMeltQuote(t) {
    const e = {
      unit: this._unit,
      request: t
    }, s = await this.mint.createMeltQuote(e);
    return {
      ...s,
      unit: s.unit || this.unit,
      request: s.request || t
    };
  }
  /**
   * Requests a multi path melt quote from the mint.
   * @param invoice LN invoice that needs to get a fee estimate
   * @param partialAmount the partial amount of the invoice's total to be paid by this instance
   * @returns the mint will create and return a melt quote for the invoice with an amount and fee reserve
   */
  async createMultiPathMeltQuote(t, e) {
    const { supported: s, params: r } = (await this.lazyGetMintInfo()).isSupported(15);
    if (!s)
      throw new Error("Mint does not support NUT-15");
    if (!r?.some((u) => u.method === "bolt11" && u.unit === this.unit))
      throw new Error(`Mint does not support MPP for bolt11 and ${this.unit}`);
    const i = {
      mpp: {
        amount: e
      }
    }, a = {
      unit: this._unit,
      request: t,
      options: i
    };
    return { ...await this.mint.createMeltQuote(a), request: t, unit: this._unit };
  }
  async checkMeltQuote(t) {
    const e = typeof t == "string" ? t : t.quote, s = await this.mint.checkMeltQuote(e);
    return typeof t == "string" ? s : { ...s, request: t.request, unit: t.unit };
  }
  /**
   * Melt proofs for a melt quote. proofsToSend must be at least amount+fee_reserve form the melt quote. This function does not perform coin selection!.
   * Returns melt quote and change proofs
   * @param meltQuote ID of the melt quote
   * @param proofsToSend proofs to melt
   * @param {MeltProofOptions} [options] - Optional parameters for configuring the Melting Proof operation
   * @returns
   */
  async meltProofs(t, e, s) {
    const { keysetId: r, counter: o, privkey: i } = s || {}, a = await this.getKeys(r), c = this.createBlankOutputs(
      W(e) - t.amount,
      a,
      o,
      this._keepFactory
    );
    i != null && (e = Pt(e, i)), e = at(e), e = e.map((l) => {
      const p = l.witness && typeof l.witness != "string" ? JSON.stringify(l.witness) : l.witness;
      return { ...l, witness: p };
    });
    const u = {
      quote: t.quote,
      inputs: e,
      outputs: c.map((l) => l.blindedMessage)
    }, h = await this.mint.melt(u);
    return {
      quote: { ...h, unit: t.unit, request: t.request },
      change: h.change?.map((l, p) => c[p].toProof(l, a)) ?? []
    };
  }
  /**
   * Creates a split payload
   * @param amount amount to send
   * @param proofsToSend proofs to split*
   * @param outputAmounts? optionally specify the output's amounts to keep and to send.
   * @param counter? optionally set counter to derive secret deterministically. CashuWallet class must be initialized with seed phrase to take effect
   * @param pubkey? optionally locks ecash to pubkey. Will not be deterministic, even if counter is set!
   * @param privkey? will create a signature on the @param proofsToSend secrets if set
   * @param customOutputData? optionally specify your own OutputData (blinded messages)
   * @param p2pk? optionally specify options to lock the proofs according to NUT-11
   * @returns
   */
  createSwapPayload(t, e, s, r, o, i, a, c, u) {
    const h = e.reduce((k, q) => k + q.amount, 0);
    r && r.sendAmounts && !r.keepAmounts && (r.keepAmounts = R(
      h - t - this.getFeesForProofs(e),
      s.keys
    ));
    const l = h - t - this.getFeesForProofs(e);
    let p = [], d = [];
    if (c?.keep)
      if (dt(c.keep)) {
        const k = c.keep;
        R(l, s.keys).forEach((B) => {
          p.push(k(B, s));
        });
      } else
        p = c.keep;
    else
      p = this.createOutputData(
        l,
        s,
        o,
        void 0,
        r?.keepAmounts,
        void 0,
        this._keepFactory
      );
    if (c?.send)
      if (dt(c.send)) {
        const k = c.send;
        R(t, s.keys).forEach((B) => {
          d.push(k(B, s));
        });
      } else
        d = c.send;
    else
      d = this.createOutputData(
        t,
        s,
        o ? o + p.length : void 0,
        i,
        r?.sendAmounts,
        u
      );
    a && (e = Pt(e, a)), e = at(e), e = e.map((k) => {
      const q = k.witness && typeof k.witness != "string" ? JSON.stringify(k.witness) : k.witness;
      return { ...k, witness: q };
    });
    const g = [...p, ...d], P = g.map((k, q) => q).sort(
      (k, q) => g[k].blindedMessage.amount - g[q].blindedMessage.amount
    ), _ = [
      ...Array(p.length).fill(!0),
      ...Array(d.length).fill(!1)
    ], A = P.map((k) => g[k]), S = P.map((k) => _[k]);
    return {
      payload: {
        inputs: e,
        outputs: A.map((k) => k.blindedMessage)
      },
      outputData: A,
      keepVector: S,
      sortedIndices: P
    };
  }
  /**
   * Get an array of the states of proofs from the mint (as an array of CheckStateEnum's)
   * @param proofs (only the `secret` field is required)
   * @returns
   */
  async checkProofsStates(t) {
    const e = new TextEncoder(), s = t.map((i) => Et(e.encode(i.secret)).toHex(!0)), r = 100, o = [];
    for (let i = 0; i < s.length; i += r) {
      const a = s.slice(i, i + r), { states: c } = await this.mint.check({
        Ys: a
      }), u = {};
      c.forEach((h) => {
        u[h.Y] = h;
      });
      for (let h = 0; h < a.length; h++) {
        const l = u[a[h]];
        if (!l)
          throw new Error("Could not find state for proof with Y: " + a[h]);
        o.push(l);
      }
    }
    return o;
  }
  /**
   * Register a callback to be called whenever a mint quote's state changes
   * @param quoteIds List of mint quote IDs that should be subscribed to
   * @param callback Callback function that will be called whenever a mint quote state changes
   * @param errorCallback
   * @returns
   */
  async onMintQuoteUpdates(t, e, s) {
    if (await this.mint.connectWebSocket(), !this.mint.webSocketConnection)
      throw new Error("failed to establish WebSocket connection.");
    const r = this.mint.webSocketConnection.createSubscription(
      { kind: "bolt11_mint_quote", filters: t },
      e,
      s
    );
    return () => {
      this.mint.webSocketConnection?.cancelSubscription(r, e);
    };
  }
  /**
   * Register a callback to be called whenever a melt quote's state changes
   * @param quoteIds List of melt quote IDs that should be subscribed to
   * @param callback Callback function that will be called whenever a melt quote state changes
   * @param errorCallback
   * @returns
   */
  async onMeltQuotePaid(t, e, s) {
    return this.onMeltQuoteUpdates(
      [t],
      (r) => {
        r.state === Z.PAID && e(r);
      },
      s
    );
  }
  /**
   * Register a callback to be called when a single mint quote gets paid
   * @param quoteId Mint quote id that should be subscribed to
   * @param callback Callback function that will be called when this mint quote gets paid
   * @param errorCallback
   * @returns
   */
  async onMintQuotePaid(t, e, s) {
    return this.onMintQuoteUpdates(
      [t],
      (r) => {
        r.state === ft.PAID && e(r);
      },
      s
    );
  }
  /**
   * Register a callback to be called when a single melt quote gets paid
   * @param quoteId Melt quote id that should be subscribed to
   * @param callback Callback function that will be called when this melt quote gets paid
   * @param errorCallback
   * @returns
   */
  async onMeltQuoteUpdates(t, e, s) {
    if (await this.mint.connectWebSocket(), !this.mint.webSocketConnection)
      throw new Error("failed to establish WebSocket connection.");
    const r = this.mint.webSocketConnection.createSubscription(
      { kind: "bolt11_melt_quote", filters: t },
      e,
      s
    );
    return () => {
      this.mint.webSocketConnection?.cancelSubscription(r, e);
    };
  }
  /**
   * Register a callback to be called whenever a subscribed proof state changes
   * @param proofs List of proofs that should be subscribed to
   * @param callback Callback function that will be called whenever a proof's state changes
   * @param errorCallback
   * @returns
   */
  async onProofStateUpdates(t, e, s) {
    if (await this.mint.connectWebSocket(), !this.mint.webSocketConnection)
      throw new Error("failed to establish WebSocket connection.");
    const r = new TextEncoder(), o = {};
    for (let c = 0; c < t.length; c++) {
      const u = Et(r.encode(t[c].secret)).toHex(!0);
      o[u] = t[c];
    }
    const i = Object.keys(o), a = this.mint.webSocketConnection.createSubscription(
      { kind: "proof_state", filters: i },
      (c) => {
        e({ ...c, proof: o[c.Y] });
      },
      s
    );
    return () => {
      this.mint.webSocketConnection?.cancelSubscription(a, e);
    };
  }
  /**
   * Creates blinded messages for a according to @param amounts
   * @param amount array of amounts to create blinded messages for
   * @param counter? optionally set counter to derive secret deterministically. CashuWallet class must be initialized with seed phrase to take effect
   * @param pubkey? optionally locks ecash to pubkey. Will not be deterministic, even if counter is set!
   * @param outputAmounts? optionally specify the output's amounts to keep and to send.
   * @param p2pk? optionally specify options to lock the proofs according to NUT-11
   * @param factory? optionally specify a custom function that produces OutputData (blinded messages)
   * @returns blinded messages, secrets, rs, and amounts
   */
  createOutputData(t, e, s, r, o, i, a) {
    let c;
    if (r)
      c = N.createP2PKData({ pubkey: r }, t, e, o);
    else if (s || s === 0) {
      if (!this._seed)
        throw new Error("cannot create deterministic messages without seed");
      c = N.createDeterministicData(
        t,
        this._seed,
        s,
        e,
        o
      );
    } else i ? c = N.createP2PKData(i, t, e, o) : a ? c = R(t, e.keys).map((h) => a(h, e)) : c = N.createRandomData(t, e, o);
    return c;
  }
  /**
   * Creates NUT-08 blank outputs (fee returns) for a given fee reserve
   * See: https://github.com/cashubtc/nuts/blob/main/08.md
   * @param amount amount to cover with blank outputs
   * @param keysetId mint keysetId
   * @param counter? optionally set counter to derive secret deterministically. CashuWallet class must be initialized with seed phrase to take effect
   * @returns blinded messages, secrets, and rs
   */
  createBlankOutputs(t, e, s, r) {
    let o = Math.ceil(Math.log2(t)) || 1;
    o < 0 && (o = 0);
    const i = o ? Array(o).fill(1) : [];
    return this.createOutputData(
      i.length,
      e,
      s,
      void 0,
      i,
      void 0,
      r
    );
  }
}
class X {
  /**
   * @param _mintUrl requires mint URL to create this object
   * @param _customRequest if passed, use custom request implementation for network communication with the mint
   */
  constructor(t, e) {
    this._mintUrl = t, this._customRequest = e, this._mintUrl = Qt(t), this._customRequest = e;
  }
  get mintUrl() {
    return this._mintUrl;
  }
  /**
   * Mints new Blinded Authentication tokens by requesting blind signatures on the provided outputs.
   * @param mintUrl
   * @param mintPayload Payload containing the outputs to get blind signatures on
   * @param clearAuthToken A NUT-21 clear auth token
   * @param customRequest
   * @returns serialized blinded signatures
   */
  static async mint(t, e, s, r) {
    const o = r || x, i = {
      "Clear-auth": `${s}`
    }, a = await o({
      endpoint: v(t, "/v1/auth/blind/mint"),
      method: "POST",
      requestBody: e,
      headers: i
    });
    if (!U(a) || !Array.isArray(a?.signatures))
      throw new Error("bad response");
    return a;
  }
  /**
   * Mints new Blinded Authentication tokens by requesting blind signatures on the provided outputs.
   * @param mintPayload Payload containing the outputs to get blind signatures on
   * @param clearAuthToken A NUT-21 clear auth token
   * @returns serialized blinded signatures
   */
  async mint(t, e) {
    return X.mint(this._mintUrl, t, e, this._customRequest);
  }
  /**
   * Get the mints public NUT-22 keys
   * @param mintUrl
   * @param keysetId optional param to get the keys for a specific keyset. If not specified, the keys from all active keysets are fetched
   * @param customRequest
   * @returns
   */
  static async getKeys(t, e, s) {
    const o = await (s || x)({
      endpoint: e ? v(t, "/v1/auth/blind/keys", e) : v(t, "/v1/auth/blind/keys")
    });
    if (!U(o) || !Array.isArray(o.keysets))
      throw new Error("bad response");
    return o;
  }
  /**
   * Get the mints public NUT-22 keys
   * @param keysetId optional param to get the keys for a specific keyset. If not specified, the keys from all active keysets are fetched
   * @returns the mints public keys
   */
  async getKeys(t, e) {
    return await X.getKeys(
      e || this._mintUrl,
      t,
      this._customRequest
    );
  }
  /**
   * Get the mints NUT-22 keysets in no specific order
   * @param mintUrl
   * @param customRequest
   * @returns all the mints past and current keysets.
   */
  static async getKeySets(t, e) {
    return (e || x)({
      endpoint: v(t, "/v1/auth/blind/keysets")
    });
  }
  /**
   * Get the mints NUT-22 keysets in no specific order
   * @returns all the mints past and current keysets.
   */
  async getKeySets() {
    return X.getKeySets(this._mintUrl, this._customRequest);
  }
}
class Oe {
  /**
   * @param mint NUT-22 auth mint instance
   * @param options.keys public keys from the mint (will be fetched from mint if not provided)
   * @param options.keysets keysets from the mint (will be fetched from mint if not provided)
   */
  constructor(t, e) {
    this._keys = /* @__PURE__ */ new Map(), this._keysets = [], this._unit = "auth", this.mint = t;
    let s = [];
    e?.keys && !Array.isArray(e.keys) ? s = [e.keys] : e?.keys && Array.isArray(e?.keys) && (s = e?.keys), s && s.forEach((r) => this._keys.set(r.id, r)), e?.keysets && (this._keysets = e.keysets);
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
   * Load mint information, keysets and keys. This function can be called if no keysets are passed in the constructor
   */
  async loadMint() {
    await this.getKeySets(), await this.getKeys();
  }
  /**
   * Choose a keyset to activate based on the lowest input fee
   *
   * Note: this function will filter out deprecated base64 keysets
   *
   * @param keysets keysets to choose from
   * @returns active keyset
   */
  getActiveKeyset(t) {
    let e = t.filter((r) => r.active);
    e = e.filter((r) => r.id.startsWith("00"));
    const s = e.sort(
      (r, o) => (r.input_fee_ppk ?? 0) - (o.input_fee_ppk ?? 0)
    )[0];
    if (!s)
      throw new Error("No active keyset found");
    return s;
  }
  /**
   * Get keysets from the mint with the unit of the wallet
   * @returns keysets with wallet's unit
   */
  async getKeySets() {
    const e = (await this.mint.getKeySets()).keysets.filter((s) => s.unit === this._unit);
    return this._keysets = e, this._keysets;
  }
  /**
   * Get all active keys from the mint and set the keyset with the lowest fees as the active wallet keyset.
   * @returns keyset
   */
  async getAllKeys() {
    const t = await this.mint.getKeys();
    return this._keys = new Map(t.keysets.map((e) => [e.id, e])), this.keysetId = this.getActiveKeyset(this._keysets).id, t.keysets;
  }
  /**
   * Get public keys from the mint. If keys were already fetched, it will return those.
   *
   * If `keysetId` is set, it will fetch and return that specific keyset.
   * Otherwise, we select an active keyset with the unit of the wallet.
   *
   * @param keysetId optional keysetId to get keys for
   * @param forceRefresh? if set to true, it will force refresh the keyset from the mint
   * @returns keyset
   */
  async getKeys(t, e) {
    if ((!(this._keysets.length > 0) || e) && await this.getKeySets(), t || (t = this.getActiveKeyset(this._keysets).id), !this._keysets.find((s) => s.id === t) && (await this.getKeySets(), !this._keysets.find((s) => s.id === t)))
      throw new Error(`could not initialize keys. No keyset with id '${t}' found`);
    if (!this._keys.get(t)) {
      const s = await this.mint.getKeys(t);
      this._keys.set(t, s.keysets[0]);
    }
    return this.keysetId = t, this._keys.get(t);
  }
  /**
   * Mint proofs for a given mint quote
   * @param amount amount to request
   * @param clearAuthToken clearAuthToken to mint
   * @param options.keysetId? optionally set keysetId for blank outputs for returned change.
   * @returns proofs
   */
  async mintProofs(t, e, s) {
    const r = await this.getKeys(s?.keysetId), o = N.createRandomData(t, r), i = {
      outputs: o.map((u) => u.blindedMessage)
    }, { signatures: a } = await this.mint.mint(i, e), c = o.map((u, h) => u.toProof(a[h], r));
    if (c.some((u) => !Wt(u, r)))
      throw new Error("Mint returned auth proofs with invalid DLEQ");
    return c;
  }
}
function Ne(n) {
  const t = {
    id: n.id,
    secret: n.secret,
    C: n.C
  }, e = Rt(t);
  return "auth" + "A" + e;
}
async function rs(n, t, e) {
  const s = new X(t);
  return (await new Oe(s).mintProofs(n, e)).map((i) => Ne(i));
}
export {
  X as CashuAuthMint,
  Oe as CashuAuthWallet,
  K as CashuMint,
  ns as CashuWallet,
  es as CheckStateEnum,
  vt as ConsoleLogger,
  tt as HttpResponseError,
  M as LogLevel,
  Z as MeltQuoteState,
  bt as MintOperationError,
  ft as MintQuoteState,
  _t as NetworkError,
  N as OutputData,
  wt as PaymentRequest,
  xe as PaymentRequestTransportType,
  Xe as decodePaymentRequest,
  Je as deriveKeysetId,
  rs as getBlindedAuthToken,
  Ae as getDecodedToken,
  Ze as getDecodedTokenBinary,
  Ne as getEncodedAuthToken,
  Ve as getEncodedToken,
  Ye as getEncodedTokenBinary,
  be as getEncodedTokenV4,
  Wt as hasValidDleq,
  ts as injectWebSocketImpl,
  ss as setGlobalRequestOptions
};
//# sourceMappingURL=cashu-ts.es.js.map
