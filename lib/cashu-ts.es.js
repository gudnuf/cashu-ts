import { verifyDLEQProof_reblind as pe } from "@cashu/crypto/modules/client/NUT12";
import { pointFromHex as B, hashToCurve as ie } from "@cashu/crypto/modules/common";
import { hexToBytes as M, bytesToHex as D } from "@noble/curves/abstract/utils";
import { sha256 as me } from "@noble/hashes/sha256";
import { Buffer as R } from "buffer";
import { constructProofFromPromise as qe, serializeProof as V, blindMessage as C } from "@cashu/crypto/modules/client";
import { getSignedProofs as ce } from "@cashu/crypto/modules/client/NUT11";
import { schnorr as ve } from "@noble/curves/secp256k1";
import { hexToBytes as G, bytesToHex as F, randomBytes as ae } from "@noble/hashes/utils";
import { deriveSecret as Me, deriveBlindingFactor as Te } from "@cashu/crypto/modules/client/NUT09";
function Ue(s) {
  return R.from(s).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function ye(s) {
  return R.from(s, "base64");
}
function De(s) {
  const e = JSON.stringify(s);
  return Be(R.from(e).toString("base64"));
}
function Fe(s) {
  const e = R.from(xe(s), "base64").toString();
  return JSON.parse(e);
}
function xe(s) {
  return s.replace(/-/g, "+").replace(/_/g, "/").split("=")[0];
}
function Be(s) {
  return s.replace(/\+/g, "-").replace(/\//g, "_").split("=")[0];
}
function Ne(s) {
  return typeof s == "number" || typeof s == "string";
}
function J(s) {
  const e = [];
  return Y(s, e), new Uint8Array(e);
}
function Y(s, e) {
  if (s === null)
    e.push(246);
  else if (s === void 0)
    e.push(247);
  else if (typeof s == "boolean")
    e.push(s ? 245 : 244);
  else if (typeof s == "number")
    ge(s, e);
  else if (typeof s == "string")
    we(s, e);
  else if (Array.isArray(s))
    Ke(s, e);
  else if (s instanceof Uint8Array)
    Oe(s, e);
  else if (typeof s == "object")
    Re(s, e);
  else
    throw new Error("Unsupported type");
}
function ge(s, e) {
  if (s < 24)
    e.push(s);
  else if (s < 256)
    e.push(24, s);
  else if (s < 65536)
    e.push(25, s >> 8, s & 255);
  else if (s < 4294967296)
    e.push(26, s >> 24, s >> 16 & 255, s >> 8 & 255, s & 255);
  else
    throw new Error("Unsupported integer size");
}
function Oe(s, e) {
  const t = s.length;
  if (t < 24)
    e.push(64 + t);
  else if (t < 256)
    e.push(88, t);
  else if (t < 65536)
    e.push(89, t >> 8 & 255, t & 255);
  else if (t < 4294967296)
    e.push(
      90,
      t >> 24 & 255,
      t >> 16 & 255,
      t >> 8 & 255,
      t & 255
    );
  else
    throw new Error("Byte string too long to encode");
  for (let n = 0; n < s.length; n++)
    e.push(s[n]);
}
function we(s, e) {
  const t = new TextEncoder().encode(s), n = t.length;
  if (n < 24)
    e.push(96 + n);
  else if (n < 256)
    e.push(120, n);
  else if (n < 65536)
    e.push(121, n >> 8 & 255, n & 255);
  else if (n < 4294967296)
    e.push(
      122,
      n >> 24 & 255,
      n >> 16 & 255,
      n >> 8 & 255,
      n & 255
    );
  else
    throw new Error("String too long to encode");
  for (let r = 0; r < t.length; r++)
    e.push(t[r]);
}
function Ke(s, e) {
  const t = s.length;
  if (t < 24)
    e.push(128 | t);
  else if (t < 256)
    e.push(152, t);
  else if (t < 65536)
    e.push(153, t >> 8, t & 255);
  else
    throw new Error("Unsupported array length");
  for (const n of s)
    Y(n, e);
}
function Re(s, e) {
  const t = Object.keys(s);
  ge(t.length, e), e[e.length - 1] |= 160;
  for (const n of t)
    we(n, e), Y(s[n], e);
}
function X(s) {
  const e = new DataView(s.buffer, s.byteOffset, s.byteLength);
  return L(e, 0).value;
}
function L(s, e) {
  if (e >= s.byteLength)
    throw new Error("Unexpected end of data");
  const t = s.getUint8(e++), n = t >> 5, r = t & 31;
  switch (n) {
    case 0:
      return Qe(s, e, r);
    case 1:
      return Le(s, e, r);
    case 2:
      return We(s, e, r);
    case 3:
      return je(s, e, r);
    case 4:
      return Ce(s, e, r);
    case 5:
      return He(s, e, r);
    case 7:
      return ze(s, e, r);
    default:
      throw new Error(`Unsupported major type: ${n}`);
  }
}
function O(s, e, t) {
  if (t < 24) return { value: t, offset: e };
  if (t === 24) return { value: s.getUint8(e++), offset: e };
  if (t === 25) {
    const n = s.getUint16(e, !1);
    return e += 2, { value: n, offset: e };
  }
  if (t === 26) {
    const n = s.getUint32(e, !1);
    return e += 4, { value: n, offset: e };
  }
  if (t === 27) {
    const n = s.getUint32(e, !1), r = s.getUint32(e + 4, !1);
    return e += 8, { value: n * 2 ** 32 + r, offset: e };
  }
  throw new Error(`Unsupported length: ${t}`);
}
function Qe(s, e, t) {
  const { value: n, offset: r } = O(s, e, t);
  return { value: n, offset: r };
}
function Le(s, e, t) {
  const { value: n, offset: r } = O(s, e, t);
  return { value: -1 - n, offset: r };
}
function We(s, e, t) {
  const { value: n, offset: r } = O(s, e, t);
  if (r + n > s.byteLength)
    throw new Error("Byte string length exceeds data length");
  return { value: new Uint8Array(s.buffer, s.byteOffset + r, n), offset: r + n };
}
function je(s, e, t) {
  const { value: n, offset: r } = O(s, e, t);
  if (r + n > s.byteLength)
    throw new Error("String length exceeds data length");
  const o = new Uint8Array(s.buffer, s.byteOffset + r, n);
  return { value: new TextDecoder().decode(o), offset: r + n };
}
function Ce(s, e, t) {
  const { value: n, offset: r } = O(s, e, t), o = [];
  let i = r;
  for (let c = 0; c < n; c++) {
    const a = L(s, i);
    o.push(a.value), i = a.offset;
  }
  return { value: o, offset: i };
}
function He(s, e, t) {
  const { value: n, offset: r } = O(s, e, t), o = {};
  let i = r;
  for (let c = 0; c < n; c++) {
    const a = L(s, i);
    if (!Ne(a.value))
      throw new Error("Invalid key type");
    const h = L(s, a.offset);
    o[a.value] = h.value, i = h.offset;
  }
  return { value: o, offset: i };
}
function $e(s) {
  const e = (s & 31744) >> 10, t = s & 1023, n = s & 32768 ? -1 : 1;
  return e === 0 ? n * 2 ** -14 * (t / 1024) : e === 31 ? t ? NaN : n * (1 / 0) : n * 2 ** (e - 15) * (1 + t / 1024);
}
function ze(s, e, t) {
  if (t < 24)
    switch (t) {
      case 20:
        return { value: !1, offset: e };
      case 21:
        return { value: !0, offset: e };
      case 22:
        return { value: null, offset: e };
      case 23:
        return { value: void 0, offset: e };
      default:
        throw new Error(`Unknown simple value: ${t}`);
    }
  if (t === 24) return { value: s.getUint8(e++), offset: e };
  if (t === 25) {
    const n = $e(s.getUint16(e, !1));
    return e += 2, { value: n, offset: e };
  }
  if (t === 26) {
    const n = s.getFloat32(e, !1);
    return e += 4, { value: n, offset: e };
  }
  if (t === 27) {
    const n = s.getFloat64(e, !1);
    return e += 8, { value: n, offset: e };
  }
  throw new Error(`Unknown simple or float value: ${t}`);
}
class Z {
  constructor(e, t, n, r, o, i, c = !1) {
    this.transport = e, this.id = t, this.amount = n, this.unit = r, this.mints = o, this.description = i, this.singleUse = c;
  }
  toEncodedRequest() {
    const e = {
      t: this.transport.map((r) => ({ t: r.type, a: r.target, g: r.tags }))
    };
    this.id && (e.i = this.id), this.amount && (e.a = this.amount), this.unit && (e.u = this.unit), this.mints && (e.m = this.mints), this.description && (e.d = this.description), this.singleUse && (e.s = this.singleUse);
    const t = J(e);
    return "creqA" + R.from(t).toString("base64");
  }
  getTransport(e) {
    return this.transport.find((t) => t.type === e);
  }
  static fromEncodedRequest(e) {
    if (!e.startsWith("creq"))
      throw new Error("unsupported pr: invalid prefix");
    if (e[4] !== "A")
      throw new Error("unsupported pr version");
    const n = e.slice(5), r = ye(n), o = X(r), i = o.t.map((c) => ({ type: c.t, target: c.a, tags: c.g }));
    return new Z(
      i,
      o.i,
      o.a,
      o.u,
      o.m,
      o.d,
      o.s
    );
  }
}
const Ve = "A", Ge = "cashu";
function S(s, e, t, n) {
  if (t) {
    const o = de(t);
    if (o > s)
      throw new Error(`Split is greater than total amount: ${o} > ${s}`);
    if (t.some((i) => !be(i, e)))
      throw new Error("Provided amount preferences do not match the amounts of the mint keyset.");
    s = s - de(t);
  } else
    t = [];
  return ke(e, "desc").forEach((o) => {
    const i = Math.floor(s / o);
    for (let c = 0; c < i; ++c) t?.push(o);
    s %= o;
  }), t.sort((o, i) => o - i);
}
function ue(s, e, t, n) {
  const r = [], o = s.map((h) => h.amount);
  ke(t, "asc").forEach((h) => {
    const d = o.filter((m) => m === h).length, f = Math.max(n - d, 0);
    for (let m = 0; m < f && !(r.reduce((u, l) => u + l, 0) + h > e); ++m)
      r.push(h);
  });
  const c = e - r.reduce((h, d) => h + d, 0);
  return c && S(c, t).forEach((d) => {
    r.push(d);
  }), r.sort((h, d) => h - d);
}
function ke(s, e = "desc") {
  return e == "desc" ? Object.keys(s).map((t) => parseInt(t)).sort((t, n) => n - t) : Object.keys(s).map((t) => parseInt(t)).sort((t, n) => t - n);
}
function be(s, e) {
  return s in e;
}
function Je(s) {
  return _e(D(s));
}
function _e(s) {
  return BigInt(`0x${s}`);
}
function Ye(s) {
  return s.toString(16).padStart(64, "0");
}
function he(s) {
  return /^[a-f0-9]*$/i.test(s);
}
function Ee(s) {
  return Array.isArray(s) ? s.some((e) => !he(e.id)) : he(s.id);
}
function Xe(s) {
  const e = { token: [{ mint: s.mint, proofs: s.proofs }] };
  return s.unit && (e.unit = s.unit), s.memo && (e.memo = s.memo), Ge + Ve + De(e);
}
function vt(s, e) {
  if (Ee(s.proofs) || e?.version === 3) {
    if (e?.version === 4)
      throw new Error("can not encode to v4 token if proofs contain non-hex keyset id");
    return Xe(s);
  }
  return Ze(s);
}
function Ze(s) {
  if (s.proofs.forEach((c) => {
    if (c.dleq && c.dleq.r == null)
      throw new Error("Missing blinding factor in included DLEQ proof");
  }), Ee(s.proofs))
    throw new Error("can not encode to v4 token if proofs contain non-hex keyset id");
  const t = Pe(s), n = J(t), r = "cashu", o = "B", i = Ue(n);
  return r + o + i;
}
function Pe(s) {
  const e = {}, t = s.mint;
  for (let r = 0; r < s.proofs.length; r++) {
    const o = s.proofs[r];
    e[o.id] ? e[o.id].push(o) : e[o.id] = [o];
  }
  const n = {
    m: t,
    u: s.unit || "sat",
    t: Object.keys(e).map(
      (r) => ({
        i: M(r),
        p: e[r].map(
          (o) => ({
            a: o.amount,
            s: o.secret,
            c: M(o.C),
            ...o.dleq && {
              d: {
                e: M(o.dleq.e),
                s: M(o.dleq.s),
                r: M(o.dleq.r ?? "00")
              }
            }
          })
        )
      })
    )
  };
  return s.memo && (n.d = s.memo), n;
}
function Se(s) {
  const e = [];
  s.t.forEach(
    (n) => n.p.forEach((r) => {
      e.push({
        secret: r.s,
        C: D(r.c),
        amount: r.a,
        id: D(n.i),
        ...r.d && {
          dleq: {
            r: D(r.d.r),
            s: D(r.d.s),
            e: D(r.d.e)
          }
        }
      });
    })
  );
  const t = { mint: s.m, proofs: e, unit: s.u || "sat" };
  return s.d && (t.memo = s.d), t;
}
function et(s) {
  return ["web+cashu://", "cashu://", "cashu:", "cashu"].forEach((t) => {
    s.startsWith(t) && (s = s.slice(t.length));
  }), tt(s);
}
function tt(s) {
  const e = s.slice(0, 1), t = s.slice(1);
  if (e === "A") {
    const n = Fe(t);
    if (n.token.length > 1)
      throw new Error("Multi entry token are not supported");
    const r = n.token[0], o = {
      mint: r.mint,
      proofs: r.proofs,
      unit: n.unit || "sat"
    };
    return n.memo && (o.memo = n.memo), o;
  } else if (e === "B") {
    const n = ye(t), r = X(n);
    return Se(r);
  }
  throw new Error("Token version is not supported");
}
function Mt(s) {
  const e = Object.entries(s).sort((r, o) => +r[0] - +o[0]).map(([, r]) => M(r)).reduce((r, o) => st(r, o), new Uint8Array()), t = me(e);
  return "00" + Buffer.from(t).toString("hex").slice(0, 14);
}
function st(s, e) {
  const t = new Uint8Array(s.length + e.length);
  return t.set(s), t.set(e, s.length), t;
}
function v(s) {
  return typeof s == "object";
}
function E(...s) {
  return s.map((e) => e.replace(/(^\/+|\/+$)/g, "")).join("/");
}
function nt(s) {
  return s.replace(/\/$/, "");
}
function U(s) {
  return s.reduce((e, t) => e + t.amount, 0);
}
function Tt(s) {
  return Z.fromEncodedRequest(s);
}
class rt {
  get value() {
    return this._value;
  }
  set value(e) {
    this._value = e;
  }
  get next() {
    return this._next;
  }
  set next(e) {
    this._next = e;
  }
  constructor(e) {
    this._value = e, this._next = null;
  }
}
class ot {
  get first() {
    return this._first;
  }
  set first(e) {
    this._first = e;
  }
  get last() {
    return this._last;
  }
  set last(e) {
    this._last = e;
  }
  get size() {
    return this._size;
  }
  set size(e) {
    this._size = e;
  }
  constructor() {
    this._first = null, this._last = null, this._size = 0;
  }
  enqueue(e) {
    const t = new rt(e);
    return this._size === 0 || !this._last ? (this._first = t, this._last = t) : (this._last.next = t, this._last = t), this._size++, !0;
  }
  dequeue() {
    if (this._size === 0 || !this._first) return null;
    const e = this._first;
    return this._first = e.next, e.next = null, this._size--, e.value;
  }
}
function Q(s) {
  return s.map((e) => {
    const t = { ...e };
    return delete t.dleq, delete t.dleqValid, t;
  });
}
function it(s, e) {
  if (s.dleq == null)
    return !1;
  const t = {
    e: M(s.dleq.e),
    s: M(s.dleq.s),
    r: _e(s.dleq.r ?? "00")
  };
  if (!be(s.amount, e.keys))
    throw new Error(`undefined key for amount ${s.amount}`);
  const n = e.keys[s.amount];
  return !!pe(
    new TextEncoder().encode(s.secret),
    t,
    B(s.C),
    B(n)
  );
}
function ct(...s) {
  const e = s.reduce((r, o) => r + o.length, 0), t = new Uint8Array(e);
  let n = 0;
  for (let r = 0; r < s.length; r++)
    t.set(s[r], n), n = n + s[r].length;
  return t;
}
function Ut(s) {
  const e = new TextEncoder(), t = Pe(s), n = J(t), r = e.encode("craw"), o = e.encode("B");
  return ct(r, o, n);
}
function Dt(s) {
  const e = new TextDecoder(), t = e.decode(s.slice(0, 4)), n = e.decode(new Uint8Array([s[4]]));
  if (t !== "craw" || n !== "B")
    throw new Error("not a valid binary token");
  const r = s.slice(5), o = X(r);
  return Se(o);
}
function de(s) {
  return s.reduce((e, t) => e + t, 0);
}
let ee;
typeof WebSocket < "u" && (ee = WebSocket);
function Ft(s) {
  ee = s;
}
function at() {
  return ee;
}
class x {
  constructor() {
    this.connectionMap = /* @__PURE__ */ new Map();
  }
  static getInstance() {
    return x.instace || (x.instace = new x()), x.instace;
  }
  getConnection(e) {
    if (this.connectionMap.has(e))
      return this.connectionMap.get(e);
    const t = new ut(e);
    return this.connectionMap.set(e, t), t;
  }
}
class ut {
  constructor(e) {
    this.subListeners = {}, this.rpcListeners = {}, this.rpcId = 0, this._WS = at(), this.url = new URL(e), this.messageQueue = new ot();
  }
  connect() {
    return this.connectionPromise || (this.connectionPromise = new Promise((e, t) => {
      try {
        this.ws = new this._WS(this.url);
      } catch (n) {
        t(n);
        return;
      }
      this.ws.onopen = () => {
        e();
      }, this.ws.onerror = () => {
        t(new Error("Failed to open WebSocket"));
      }, this.ws.onmessage = (n) => {
        this.messageQueue.enqueue(n.data), this.handlingInterval || (this.handlingInterval = setInterval(
          this.handleNextMesage.bind(this),
          0
        ));
      }, this.ws.onclose = () => {
        this.connectionPromise = void 0;
      };
    })), this.connectionPromise;
  }
  sendRequest(e, t) {
    if (this.ws?.readyState !== 1)
      throw new Error("Socket not open...");
    const n = this.rpcId;
    this.rpcId++;
    const r = JSON.stringify({ jsonrpc: "2.0", method: e, params: t, id: n });
    this.ws?.send(r);
  }
  closeSubscription(e) {
    this.ws?.send(JSON.stringify(["CLOSE", e]));
  }
  addSubListener(e, t) {
    (this.subListeners[e] = this.subListeners[e] || []).push(t);
  }
  //TODO: Move to RPCManagerClass
  addRpcListener(e, t, n) {
    this.rpcListeners[n] = { callback: e, errorCallback: t };
  }
  //TODO: Move to RPCManagerClass
  removeRpcListener(e) {
    delete this.rpcListeners[e];
  }
  removeListener(e, t) {
    if (this.subListeners[e].length === 1) {
      delete this.subListeners[e];
      return;
    }
    this.subListeners[e] = this.subListeners[e].filter((n) => n !== t);
  }
  async ensureConnection() {
    this.ws?.readyState !== 1 && await this.connect();
  }
  handleNextMesage() {
    if (this.messageQueue.size === 0) {
      clearInterval(this.handlingInterval), this.handlingInterval = void 0;
      return;
    }
    const e = this.messageQueue.dequeue();
    let t;
    try {
      if (t = JSON.parse(e), "result" in t && t.id != null)
        this.rpcListeners[t.id] && (this.rpcListeners[t.id].callback(), this.removeRpcListener(t.id));
      else if ("error" in t && t.id != null)
        this.rpcListeners[t.id] && (this.rpcListeners[t.id].errorCallback(t.error), this.removeRpcListener(t.id));
      else if ("method" in t && !("id" in t)) {
        const n = t.params.subId;
        if (!n)
          return;
        if (this.subListeners[n]?.length > 0) {
          const r = t;
          this.subListeners[n].forEach((o) => o(r.params.payload));
        }
      }
    } catch (n) {
      console.error(n);
      return;
    }
  }
  createSubscription(e, t, n) {
    if (this.ws?.readyState !== 1)
      return n(new Error("Socket is not open"));
    const r = (Math.random() + 1).toString(36).substring(7);
    return this.addRpcListener(
      () => {
        this.addSubListener(r, t);
      },
      (o) => {
        n(new Error(o.message));
      },
      this.rpcId
    ), this.sendRequest("subscribe", { ...e, subId: r }), this.rpcId++, r;
  }
  cancelSubscription(e, t) {
    this.removeListener(e, t), this.rpcId++, this.sendRequest("unsubscribe", { subId: e });
  }
  get activeSubscriptions() {
    return Object.keys(this.subListeners);
  }
  close() {
    this.ws && this.ws?.close();
  }
}
var ht = /* @__PURE__ */ ((s) => (s.UNSPENT = "UNSPENT", s.PENDING = "PENDING", s.SPENT = "SPENT", s))(ht || {}), N = /* @__PURE__ */ ((s) => (s.UNPAID = "UNPAID", s.PENDING = "PENDING", s.PAID = "PAID", s))(N || {}), W = /* @__PURE__ */ ((s) => (s.UNPAID = "UNPAID", s.PAID = "PAID", s.ISSUED = "ISSUED", s))(W || {}), dt = /* @__PURE__ */ ((s) => (s.POST = "post", s.NOSTR = "nostr", s))(dt || {});
class j extends Error {
  constructor(e, t) {
    super(e), this.status = t, this.name = "HttpResponseError", Object.setPrototypeOf(this, j.prototype);
  }
}
let Ie = {};
function xt(s) {
  Ie = s;
}
async function lt({
  endpoint: s,
  requestBody: e,
  headers: t,
  ...n
}) {
  const r = e ? JSON.stringify(e) : void 0, o = {
    Accept: "application/json, text/plain, */*",
    ...r ? { "Content-Type": "application/json" } : void 0,
    ...t
  }, i = await fetch(s, { body: r, headers: o, ...n });
  if (!i.ok) {
    const { error: c, detail: a } = await i.json().catch(() => ({ error: "bad response" }));
    throw new j(c || a || "bad response", i.status);
  }
  try {
    return await i.json();
  } catch (c) {
    throw console.error("Failed to parse HTTP response", c), new j("bad response", i.status);
  }
}
async function A(s) {
  return await lt({ ...s, ...Ie });
}
function H(s) {
  return s.state || (console.warn(
    "Field 'state' not found in MeltQuoteResponse. Update NUT-05 of mint: https://github.com/cashubtc/nuts/pull/136)"
  ), typeof s.paid == "boolean" && (s.state = s.paid ? N.PAID : N.UNPAID)), s;
}
function le(s) {
  return s.state || (console.warn(
    "Field 'state' not found in MintQuoteResponse. Update NUT-04 of mint: https://github.com/cashubtc/nuts/pull/141)"
  ), typeof s.paid == "boolean" && (s.state = s.paid ? W.PAID : W.UNPAID)), s;
}
function ft(s) {
  return Array.isArray(s?.contact) && s?.contact.length > 0 && (s.contact = s.contact.map((e) => Array.isArray(e) && e.length === 2 && typeof e[0] == "string" && typeof e[1] == "string" ? (console.warn(
    "Mint returned deprecated 'contact' field: Update NUT-06: https://github.com/cashubtc/nuts/pull/117"
  ), { method: e[0], info: e[1] }) : e)), s;
}
class P {
  /**
   * @param _mintUrl requires mint URL to create this object
   * @param _customRequest if passed, use custom request implementation for network communication with the mint
   */
  constructor(e, t) {
    this._mintUrl = e, this._customRequest = t, this._mintUrl = nt(e), this._customRequest = t;
  }
  get mintUrl() {
    return this._mintUrl;
  }
  /**
   * fetches mints info at the /info endpoint
   * @param mintUrl
   * @param customRequest
   */
  static async getInfo(e, t) {
    const r = await (t || A)({
      endpoint: E(e, "/v1/info")
    });
    return ft(r);
  }
  /**
   * fetches mints info at the /info endpoint
   */
  async getInfo() {
    return P.getInfo(this._mintUrl, this._customRequest);
  }
  /**
   * Performs a swap operation with ecash inputs and outputs.
   * @param mintUrl
   * @param swapPayload payload containing inputs and outputs
   * @param customRequest
   * @returns signed outputs
   */
  static async swap(e, t, n) {
    const o = await (n || A)({
      endpoint: E(e, "/v1/swap"),
      method: "POST",
      requestBody: t
    });
    if (!v(o) || !Array.isArray(o?.signatures))
      throw new Error(o.detail ?? "bad response");
    return o;
  }
  /**
   * Performs a swap operation with ecash inputs and outputs.
   * @param swapPayload payload containing inputs and outputs
   * @returns signed outputs
   */
  async swap(e) {
    return P.swap(this._mintUrl, e, this._customRequest);
  }
  /**
   * Requests a new mint quote from the mint.
   * @param mintUrl
   * @param mintQuotePayload Payload for creating a new mint quote
   * @param customRequest
   * @returns the mint will create and return a new mint quote containing a payment request for the specified amount and unit
   */
  static async createMintQuote(e, t, n) {
    const o = await (n || A)({
      endpoint: E(e, "/v1/mint/quote/bolt11"),
      method: "POST",
      requestBody: t
    });
    return le(o);
  }
  /**
   * Requests a new mint quote from the mint.
   * @param mintQuotePayload Payload for creating a new mint quote
   * @returns the mint will create and return a new mint quote containing a payment request for the specified amount and unit
   */
  async createMintQuote(e) {
    return P.createMintQuote(this._mintUrl, e, this._customRequest);
  }
  /**
   * Gets an existing mint quote from the mint.
   * @param mintUrl
   * @param quote Quote ID
   * @param customRequest
   * @returns the mint will create and return a Lightning invoice for the specified amount
   */
  static async checkMintQuote(e, t, n) {
    const o = await (n || A)({
      endpoint: E(e, "/v1/mint/quote/bolt11", t),
      method: "GET"
    });
    return le(o);
  }
  /**
   * Gets an existing mint quote from the mint.
   * @param quote Quote ID
   * @returns the mint will create and return a Lightning invoice for the specified amount
   */
  async checkMintQuote(e) {
    return P.checkMintQuote(this._mintUrl, e, this._customRequest);
  }
  /**
   * Mints new tokens by requesting blind signatures on the provided outputs.
   * @param mintUrl
   * @param mintPayload Payload containing the outputs to get blind signatures on
   * @param customRequest
   * @returns serialized blinded signatures
   */
  static async mint(e, t, n) {
    const o = await (n || A)({
      endpoint: E(e, "/v1/mint/bolt11"),
      method: "POST",
      requestBody: t
    });
    if (!v(o) || !Array.isArray(o?.signatures))
      throw new Error("bad response");
    return o;
  }
  /**
   * Mints new tokens by requesting blind signatures on the provided outputs.
   * @param mintPayload Payload containing the outputs to get blind signatures on
   * @returns serialized blinded signatures
   */
  async mint(e) {
    return P.mint(this._mintUrl, e, this._customRequest);
  }
  /**
   * Requests a new melt quote from the mint.
   * @param mintUrl
   * @param MeltQuotePayload
   * @returns
   */
  static async createMeltQuote(e, t, n) {
    const o = await (n || A)({
      endpoint: E(e, "/v1/melt/quote/bolt11"),
      method: "POST",
      requestBody: t
    }), i = H(o);
    if (!v(i) || typeof i?.amount != "number" || typeof i?.fee_reserve != "number" || typeof i?.quote != "string")
      throw new Error("bad response");
    return i;
  }
  /**
   * Requests a new melt quote from the mint.
   * @param MeltQuotePayload
   * @returns
   */
  async createMeltQuote(e) {
    return P.createMeltQuote(this._mintUrl, e, this._customRequest);
  }
  /**
   * Gets an existing melt quote.
   * @param mintUrl
   * @param quote Quote ID
   * @returns
   */
  static async checkMeltQuote(e, t, n) {
    const o = await (n || A)({
      endpoint: E(e, "/v1/melt/quote/bolt11", t),
      method: "GET"
    }), i = H(o);
    if (!v(i) || typeof i?.amount != "number" || typeof i?.fee_reserve != "number" || typeof i?.quote != "string" || typeof i?.state != "string" || !Object.values(N).includes(i.state))
      throw new Error("bad response");
    return i;
  }
  /**
   * Gets an existing melt quote.
   * @param quote Quote ID
   * @returns
   */
  async checkMeltQuote(e) {
    return P.checkMeltQuote(this._mintUrl, e, this._customRequest);
  }
  /**
   * Requests the mint to pay for a Bolt11 payment request by providing ecash as inputs to be spent. The inputs contain the amount and the fee_reserves for a Lightning payment. The payload can also contain blank outputs in order to receive back overpaid Lightning fees.
   * @param mintUrl
   * @param meltPayload
   * @param customRequest
   * @returns
   */
  static async melt(e, t, n) {
    const o = await (n || A)({
      endpoint: E(e, "/v1/melt/bolt11"),
      method: "POST",
      requestBody: t
    }), i = H(o);
    if (!v(i) || typeof i?.state != "string" || !Object.values(N).includes(i.state))
      throw new Error("bad response");
    return i;
  }
  /**
   * Ask mint to perform a melt operation. This pays a lightning invoice and destroys tokens matching its amount + fees
   * @param meltPayload
   * @returns
   */
  async melt(e) {
    return P.melt(this._mintUrl, e, this._customRequest);
  }
  /**
   * Checks if specific proofs have already been redeemed
   * @param mintUrl
   * @param checkPayload
   * @param customRequest
   * @returns redeemed and unredeemed ordered list of booleans
   */
  static async check(e, t, n) {
    const o = await (n || A)({
      endpoint: E(e, "/v1/checkstate"),
      method: "POST",
      requestBody: t
    });
    if (!v(o) || !Array.isArray(o?.states))
      throw new Error("bad response");
    return o;
  }
  /**
   * Get the mints public keys
   * @param mintUrl
   * @param keysetId optional param to get the keys for a specific keyset. If not specified, the keys from all active keysets are fetched
   * @param customRequest
   * @returns
   */
  static async getKeys(e, t, n) {
    t && (t = t.replace(/\//g, "_").replace(/\+/g, "-"));
    const o = await (n || A)({
      endpoint: t ? E(e, "/v1/keys", t) : E(e, "/v1/keys")
    });
    if (!v(o) || !Array.isArray(o.keysets))
      throw new Error("bad response");
    return o;
  }
  /**
   * Get the mints public keys
   * @param keysetId optional param to get the keys for a specific keyset. If not specified, the keys from all active keysets are fetched
   * @returns the mints public keys
   */
  async getKeys(e, t) {
    return await P.getKeys(
      t || this._mintUrl,
      e,
      this._customRequest
    );
  }
  /**
   * Get the mints keysets in no specific order
   * @param mintUrl
   * @param customRequest
   * @returns all the mints past and current keysets.
   */
  static async getKeySets(e, t) {
    return (t || A)({ endpoint: E(e, "/v1/keysets") });
  }
  /**
   * Get the mints keysets in no specific order
   * @returns all the mints past and current keysets.
   */
  async getKeySets() {
    return P.getKeySets(this._mintUrl, this._customRequest);
  }
  /**
   * Checks if specific proofs have already been redeemed
   * @param checkPayload
   * @returns redeemed and unredeemed ordered list of booleans
   */
  async check(e) {
    return P.check(this._mintUrl, e, this._customRequest);
  }
  static async restore(e, t, n) {
    const o = await (n || A)({
      endpoint: E(e, "/v1/restore"),
      method: "POST",
      requestBody: t
    });
    if (!v(o) || !Array.isArray(o?.outputs) || !Array.isArray(o?.signatures))
      throw new Error("bad response");
    return o;
  }
  async restore(e) {
    return P.restore(this._mintUrl, e, this._customRequest);
  }
  /**
   * Tries to establish a websocket connection with the websocket mint url according to NUT-17
   */
  async connectWebSocket() {
    if (this.ws)
      await this.ws.ensureConnection();
    else {
      const e = new URL(this._mintUrl), t = "v1/ws";
      e.pathname && (e.pathname.endsWith("/") ? e.pathname += t : e.pathname += "/" + t), this.ws = x.getInstance().getConnection(
        `${e.protocol === "https:" ? "wss" : "ws"}://${e.host}${e.pathname}`
      );
      try {
        await this.ws.connect();
      } catch (n) {
        throw console.log(n), new Error("Failed to connect to WebSocket...");
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
}
class fe {
  constructor(e) {
    this._mintInfo = e;
  }
  isSupported(e) {
    switch (e) {
      case 4:
      case 5:
        return this.checkMintMelt(e);
      case 7:
      case 8:
      case 9:
      case 10:
      case 11:
      case 12:
      case 14:
      case 20:
        return this.checkGenericNut(e);
      case 17:
        return this.checkNut17();
      case 15:
        return this.checkNut15();
      default:
        throw new Error("nut is not supported by cashu-ts");
    }
  }
  checkGenericNut(e) {
    return this._mintInfo.nuts[e]?.supported ? { supported: !0 } : { supported: !1 };
  }
  checkMintMelt(e) {
    const t = this._mintInfo.nuts[e];
    return t && t.methods.length > 0 && !t.disabled ? { disabled: !1, params: t.methods } : { disabled: !0, params: t.methods };
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
}
function pt(s, e) {
  let t = s;
  for (const r of e)
    t += r.B_;
  const n = new TextEncoder().encode(t);
  return me(n);
}
function mt(s, e, t) {
  const n = pt(e, t), r = G(s), o = ve.sign(n, r);
  return F(o);
}
class $ {
  constructor(e, t, n) {
    this.amount = e, this.B_ = t, this.id = n;
  }
  getSerializedBlindedMessage() {
    return { amount: this.amount, B_: this.B_.toHex(!0), id: this.id };
  }
}
function z(s) {
  return typeof s == "function";
}
class q {
  constructor(e, t, n) {
    this.secret = n, this.blindingFactor = t, this.blindedMessage = e;
  }
  toProof(e, t) {
    let n;
    e.dleq && (n = {
      s: G(e.dleq.s),
      e: G(e.dleq.e),
      r: this.blindingFactor
    });
    const r = {
      id: e.id,
      amount: e.amount,
      C_: B(e.C_),
      dleq: n
    }, o = B(t.keys[e.amount]), i = qe(r, this.blindingFactor, this.secret, o);
    return {
      ...V(i),
      ...n && {
        dleqValid: pe(this.secret, n, i.C, o)
      },
      ...n && {
        dleq: {
          s: F(n.s),
          e: F(n.e),
          r: Ye(n.r ?? BigInt(0))
        }
      }
    };
  }
  static createP2PKData(e, t, n, r) {
    return S(t, n.keys, r).map((i) => this.createSingleP2PKData(e, i, n.id));
  }
  static createSingleP2PKData(e, t, n) {
    const r = [
      "P2PK",
      {
        nonce: F(ae(32)),
        data: e.pubkey,
        tags: []
      }
    ];
    e.locktime && r[1].tags.push(["locktime", e.locktime]), e.refundKeys && r[1].tags.push(["refund", e.refundKeys]);
    const o = JSON.stringify(r), i = new TextEncoder().encode(o), { r: c, B_: a } = C(i);
    return new q(
      new $(t, a, n).getSerializedBlindedMessage(),
      c,
      i
    );
  }
  static createRandomData(e, t, n) {
    return S(e, t.keys, n).map((o) => this.createSingleRandomData(o, t.id));
  }
  static createSingleRandomData(e, t) {
    const n = F(ae(32)), r = new TextEncoder().encode(n), { r: o, B_: i } = C(r);
    return new q(
      new $(e, i, t).getSerializedBlindedMessage(),
      o,
      r
    );
  }
  static createDeterministicData(e, t, n, r, o) {
    return S(e, r.keys, o).map(
      (c, a) => this.createSingleDeterministicData(c, t, n + a, r.id)
    );
  }
  static createSingleDeterministicData(e, t, n, r) {
    const o = Me(t, r, n), i = F(o), c = new TextEncoder().encode(i), a = Je(Te(t, r, n)), { r: h, B_: d } = C(c, a);
    return new q(
      new $(e, d, r).getSerializedBlindedMessage(),
      h,
      c
    );
  }
}
const yt = 3, gt = "sat";
class Bt {
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
  constructor(e, t) {
    this._keys = /* @__PURE__ */ new Map(), this._keysets = [], this._seed = void 0, this._unit = gt, this._mintInfo = void 0, this._denominationTarget = yt, this.mint = e;
    let n = [];
    if (t?.keys && !Array.isArray(t.keys) ? n = [t.keys] : t?.keys && Array.isArray(t?.keys) && (n = t?.keys), n && n.forEach((r) => this._keys.set(r.id, r)), t?.unit && (this._unit = t?.unit), t?.keysets && (this._keysets = t.keysets), t?.mintInfo && (this._mintInfo = new fe(t.mintInfo)), t?.denominationTarget && (this._denominationTarget = t.denominationTarget), t?.bip39seed) {
      if (t.bip39seed instanceof Uint8Array) {
        this._seed = t.bip39seed;
        return;
      }
      throw new Error("bip39seed must be a valid UInt8Array");
    }
    t?.keepFactory && (this._keepFactory = t.keepFactory);
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
  set keysetId(e) {
    this._keysetId = e;
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
    const e = await this.mint.getInfo();
    return this._mintInfo = new fe(e), this._mintInfo;
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
  getActiveKeyset(e) {
    let t = e.filter((r) => r.active);
    t = t.filter((r) => r.id.startsWith("00"));
    const n = t.sort(
      (r, o) => (r.input_fee_ppk ?? 0) - (o.input_fee_ppk ?? 0)
    )[0];
    if (!n)
      throw new Error("No active keyset found");
    return n;
  }
  /**
   * Get keysets from the mint with the unit of the wallet
   * @returns keysets with wallet's unit
   */
  async getKeySets() {
    const t = (await this.mint.getKeySets()).keysets.filter((n) => n.unit === this._unit);
    return this._keysets = t, this._keysets;
  }
  /**
   * Get all active keys from the mint and set the keyset with the lowest fees as the active wallet keyset.
   * @returns keyset
   */
  async getAllKeys() {
    const e = await this.mint.getKeys();
    return this._keys = new Map(e.keysets.map((t) => [t.id, t])), this.keysetId = this.getActiveKeyset(this._keysets).id, e.keysets;
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
  async getKeys(e, t) {
    if ((!(this._keysets.length > 0) || t) && await this.getKeySets(), e || (e = this.getActiveKeyset(this._keysets).id), !this._keysets.find((n) => n.id === e) && (await this.getKeySets(), !this._keysets.find((n) => n.id === e)))
      throw new Error(`could not initialize keys. No keyset with id '${e}' found`);
    if (!this._keys.get(e)) {
      const n = await this.mint.getKeys(e);
      this._keys.set(e, n.keysets[0]);
    }
    return this.keysetId = e, this._keys.get(e);
  }
  /**
   * Receive an encoded or raw Cashu token (only supports single tokens. It will only process the first token in the token array)
   * @param {(string|Token)} token - Cashu token, either as string or decoded
   * @param {ReceiveOptions} [options] - Optional configuration for token processing
   * @returns New token with newly created proofs, token entries that had errors
   */
  async receive(e, t) {
    const { requireDleq: n, keysetId: r, outputAmounts: o, counter: i, pubkey: c, privkey: a, outputData: h, p2pk: d } = t || {};
    typeof e == "string" && (e = et(e));
    const f = await this.getKeys(r);
    if (n && e.proofs.some((k) => !it(k, f)))
      throw new Error("Token contains proofs with invalid DLEQ");
    const m = U(e.proofs) - this.getFeesForProofs(e.proofs);
    let u;
    h ? u = { send: h } : this._keepFactory && (u = { send: this._keepFactory });
    const l = this.createSwapPayload(
      m,
      e.proofs,
      f,
      o,
      i,
      c,
      a,
      u,
      d
    ), { signatures: w } = await this.mint.swap(l.payload), y = l.outputData.map((k, p) => k.toProof(w[p], f)), g = [];
    return l.sortedIndices.forEach((k, p) => {
      g[k] = y[p];
    }), g;
  }
  /**
   * Send proofs of a given amount, by providing at least the required amount of proofs
   * @param amount amount to send
   * @param proofs array of proofs (accumulated amount of proofs must be >= than amount)
   * @param {SendOptions} [options] - Optional parameters for configuring the send operation
   * @returns {SendResponse}
   */
  async send(e, t, n) {
    const {
      proofsWeHave: r,
      offline: o,
      includeFees: i,
      includeDleq: c,
      keysetId: a,
      outputAmounts: h,
      pubkey: d,
      privkey: f,
      outputData: m
    } = n || {};
    if (c && (t = t.filter((y) => y.dleq != null)), U(t) < e)
      throw new Error("Not enough funds available to send");
    const { keep: u, send: l } = this.selectProofsToSend(
      t,
      e,
      n?.includeFees
    ), w = i ? this.getFeesForProofs(l) : 0;
    if (!o && (U(l) != e + w || // if the exact amount cannot be selected
    h || d || f || a || m)) {
      const { keep: y, send: g } = this.selectProofsToSend(
        t,
        e,
        !0
      );
      r?.push(...y);
      const k = await this.swap(e, g, n);
      let { keep: p, send: _ } = k;
      const T = k.serialized;
      return p = y.concat(p), c || (_ = Q(_)), { keep: p, send: _, serialized: T };
    }
    if (U(l) < e + w)
      throw new Error("Not enough funds available to send");
    return c ? { keep: u, send: l } : { keep: u, send: Q(l) };
  }
  selectProofsToSend(e, t, n) {
    const r = e.sort((u, l) => u.amount - l.amount), o = r.filter((u) => u.amount <= t).sort((u, l) => l.amount - u.amount), c = r.filter((u) => u.amount > t).sort((u, l) => u.amount - l.amount)[0];
    if (!o.length && c)
      return {
        keep: e.filter((u) => u.secret !== c.secret),
        send: [c]
      };
    if (!o.length && !c)
      return { keep: e, send: [] };
    let a = t, h = [o[0]];
    const d = [], f = n ? this.getFeesForProofs(h) : 0;
    if (a -= h[0].amount - f / 1e3, a > 0) {
      const { keep: u, send: l } = this.selectProofsToSend(
        o.slice(1),
        a,
        n
      );
      h.push(...l), d.push(...u);
    }
    const m = n ? this.getFeesForProofs(h) : 0;
    return U(h) < t + m && c && (h = [c]), {
      keep: e.filter((u) => !h.includes(u)),
      send: h
    };
  }
  /**
   * calculates the fees based on inputs (proofs)
   * @param proofs input proofs to calculate fees for
   * @returns fee amount
   */
  getFeesForProofs(e) {
    if (!this._keysets.length)
      throw new Error("Could not calculate fees. No keysets found");
    return new Set(e.map((r) => r.id)).forEach((r) => {
      if (!this._keysets.find((o) => o.id === r))
        throw new Error(`Could not calculate fees. No keyset found with id: ${r}`);
    }), Math.floor(
      Math.max(
        (e.reduce(
          (r, o) => r + (this._keysets.find((i) => i.id === o.id)?.input_fee_ppk || 0),
          0
        ) + 999) / 1e3,
        0
      )
    );
  }
  /**
   * calculates the fees based on inputs for a given keyset
   * @param nInputs number of inputs
   * @param keysetId keysetId used to lookup `input_fee_ppk`
   * @returns fee amount
   */
  getFeesForKeyset(e, t) {
    return Math.floor(
      Math.max(
        (e * (this._keysets.find((r) => r.id === t)?.input_fee_ppk || 0) + 999) / 1e3,
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
  async swap(e, t, n) {
    let { outputAmounts: r } = n || {};
    const { includeFees: o, keysetId: i, counter: c, pubkey: a, privkey: h, proofsWeHave: d, outputData: f, p2pk: m } = n || {}, u = await this.getKeys(i), l = t;
    let w = e;
    const y = U(t);
    let g = y - w - this.getFeesForProofs(l), k = r?.sendAmounts || S(w, u.keys);
    if (o) {
      let b = this.getFeesForKeyset(k.length, u.id), I = S(b, u.keys);
      for (; this.getFeesForKeyset(k.concat(I).length, u.id) > b; )
        b++, I = S(b, u.keys);
      k = k.concat(I), w += b, g -= b;
    }
    let p;
    if (!r?.keepAmounts && d)
      p = ue(
        d,
        g,
        u.keys,
        this._denominationTarget
      );
    else if (r) {
      if (r.keepAmounts?.reduce((b, I) => b + I, 0) != g)
        throw new Error("Keep amounts do not match amount to keep");
      p = r.keepAmounts;
    }
    if (w + this.getFeesForProofs(l) > y)
      throw console.error(
        `Not enough funds available (${y}) for swap amountToSend: ${w} + fee: ${this.getFeesForProofs(
          l
        )} | length: ${l.length}`
      ), new Error("Not enough funds available for swap");
    if (w + this.getFeesForProofs(l) + g != y)
      throw new Error("Amounts do not match for swap");
    r = {
      keepAmounts: p,
      sendAmounts: k
    };
    const _ = f?.keep || this._keepFactory, T = f?.send, K = this.createSwapPayload(
      w,
      l,
      u,
      r,
      c,
      a,
      h,
      { keep: _, send: T },
      m
    ), { signatures: Ae } = await this.mint.swap(K.payload), te = K.outputData.map((b, I) => b.toProof(Ae[I], u)), se = [], ne = [], re = Array(K.keepVector.length), oe = Array(te.length);
    return K.sortedIndices.forEach((b, I) => {
      re[b] = K.keepVector[I], oe[b] = te[I];
    }), oe.forEach((b, I) => {
      re[I] ? se.push(b) : ne.push(b);
    }), {
      keep: se,
      send: ne
    };
  }
  /**
   * Restores batches of deterministic proofs until no more signatures are returned from the mint
   * @param [gapLimit=300] the amount of empty counters that should be returned before restoring ends (defaults to 300)
   * @param [batchSize=100] the amount of proofs that should be restored at a time (defaults to 100)
   * @param [counter=0] the counter that should be used as a starting point (defaults to 0)
   * @param [keysetId] which keysetId to use for the restoration. If none is passed the instance's default one will be used
   */
  async batchRestore(e = 300, t = 100, n = 0, r) {
    const o = Math.ceil(e / t), i = [];
    let c, a = 0;
    for (; a < o; ) {
      const h = await this.restore(n, t, { keysetId: r });
      h.proofs.length > 0 ? (a = 0, i.push(...h.proofs), c = h.lastCounterWithSignature) : a++, n += t;
    }
    return { proofs: i, lastCounterWithSignature: c };
  }
  /**
   * Regenerates
   * @param start set starting point for count (first cycle for each keyset should usually be 0)
   * @param count set number of blinded messages that should be generated
   * @param options.keysetId set a custom keysetId to restore from. keysetIds can be loaded with `CashuMint.getKeySets()`
   */
  async restore(e, t, n) {
    const { keysetId: r } = n || {}, o = await this.getKeys(r);
    if (!this._seed)
      throw new Error("CashuWallet must be initialized with a seed to use restore");
    const i = Array(t).fill(1), c = q.createDeterministicData(
      i.length,
      this._seed,
      e,
      o,
      i
    ), { outputs: a, signatures: h } = await this.mint.restore({
      outputs: c.map((u) => u.blindedMessage)
    }), d = {};
    a.forEach((u, l) => d[u.B_] = h[l]);
    const f = [];
    let m;
    for (let u = 0; u < c.length; u++) {
      const l = d[c[u].blindedMessage.B_];
      l && (m = e + u, c[u].blindedMessage.amount = l.amount, f.push(c[u].toProof(l, o)));
    }
    return {
      proofs: f,
      lastCounterWithSignature: m
    };
  }
  /**
   * Requests a mint quote form the mint. Response returns a Lightning payment request for the requested given amount and unit.
   * @param amount Amount requesting for mint.
   * @param description optional description for the mint quote
   * @param pubkey optional public key to lock the quote to
   * @returns the mint will return a mint quote with a Lightning invoice for minting tokens of the specified amount and unit
   */
  async createMintQuote(e, t) {
    const n = {
      unit: this._unit,
      amount: e,
      description: t
    };
    return await this.mint.createMintQuote(n);
  }
  /**
   * Requests a mint quote from the mint that is locked to a public key.
   * @param amount Amount requesting for mint.
   * @param pubkey public key to lock the quote to
   * @param description optional description for the mint quote
   * @returns the mint will return a mint quote with a Lightning invoice for minting tokens of the specified amount and unit.
   * The quote will be locked to the specified `pubkey`.
   */
  async createLockedMintQuote(e, t, n) {
    const { supported: r } = (await this.getMintInfo()).isSupported(20);
    if (!r)
      throw new Error("Mint does not support NUT-20");
    const o = {
      unit: this._unit,
      amount: e,
      description: n,
      pubkey: t
    }, i = await this.mint.createMintQuote(o);
    if (!i.pubkey)
      throw new Error("Mint returned unlocked mint quote");
    return i;
  }
  /**
   * Gets an existing mint quote from the mint.
   * @param quote Quote ID
   * @returns the mint will create and return a Lightning invoice for the specified amount
   */
  async checkMintQuote(e) {
    return await this.mint.checkMintQuote(e);
  }
  async mintProofs(e, t, n) {
    let { outputAmounts: r } = n || {};
    const { counter: o, pubkey: i, p2pk: c, keysetId: a, proofsWeHave: h, outputData: d, privateKey: f } = n || {}, m = await this.getKeys(a);
    !r && h && (r = {
      keepAmounts: ue(h, e, m.keys, this._denominationTarget),
      sendAmounts: []
    });
    let u = [];
    if (d)
      if (z(d)) {
        const y = S(e, m.keys, r?.keepAmounts);
        for (let g = 0; g < y.length; g++)
          u.push(d(y[g], m));
      } else
        u = d;
    else if (this._keepFactory) {
      const y = S(e, m.keys, r?.keepAmounts);
      for (let g = 0; g < y.length; g++)
        u.push(this._keepFactory(y[g], m));
    } else
      u = this.createOutputData(
        e,
        m,
        o,
        i,
        r?.keepAmounts,
        c
      );
    let l;
    if (typeof t != "string") {
      if (!f)
        throw new Error("Can not sign locked quote without private key");
      const y = u.map((k) => k.blindedMessage), g = mt(f, t.quote, y);
      l = {
        outputs: y,
        quote: t.quote,
        signature: g
      };
    } else
      l = {
        outputs: u.map((y) => y.blindedMessage),
        quote: t
      };
    const { signatures: w } = await this.mint.mint(l);
    return u.map((y, g) => y.toProof(w[g], m));
  }
  /**
   * Requests a melt quote from the mint. Response returns amount and fees for a given unit in order to pay a Lightning invoice.
   * @param invoice LN invoice that needs to get a fee estimate
   * @returns the mint will create and return a melt quote for the invoice with an amount and fee reserve
   */
  async createMeltQuote(e) {
    const t = {
      unit: this._unit,
      request: e
    };
    return await this.mint.createMeltQuote(t);
  }
  /**
   * Requests a multi path melt quote from the mint.
   * @param invoice LN invoice that needs to get a fee estimate
   * @param partialAmount the partial amount of the invoice's total to be paid by this instance
   * @returns the mint will create and return a melt quote for the invoice with an amount and fee reserve
   */
  async createMultiPathMeltQuote(e, t) {
    const { supported: n, params: r } = (await this.lazyGetMintInfo()).isSupported(15);
    if (!n)
      throw new Error("Mint does not support NUT-15");
    if (!r?.some((h) => h.method === "bolt11" && h.unit === this.unit))
      throw new Error(`Mint does not support MPP for bolt11 and ${this.unit}`);
    const i = {
      mpp: {
        amount: t
      }
    }, c = {
      unit: this._unit,
      request: e,
      options: i
    };
    return await this.mint.createMeltQuote(c);
  }
  /**
   * Return an existing melt quote from the mint.
   * @param quote ID of the melt quote
   * @returns the mint will return an existing melt quote
   */
  async checkMeltQuote(e) {
    return await this.mint.checkMeltQuote(e);
  }
  /**
   * Melt proofs for a melt quote. proofsToSend must be at least amount+fee_reserve form the melt quote. This function does not perform coin selection!.
   * Returns melt quote and change proofs
   * @param meltQuote ID of the melt quote
   * @param proofsToSend proofs to melt
   * @param {MeltProofOptions} [options] - Optional parameters for configuring the Melting Proof operation
   * @returns
   */
  async meltProofs(e, t, n) {
    const { keysetId: r, counter: o, privkey: i } = n || {}, c = await this.getKeys(r), a = this.createBlankOutputs(
      U(t) - e.amount,
      c,
      o,
      this._keepFactory
    );
    i != null && (t = ce(
      t.map((f) => ({
        amount: f.amount,
        C: B(f.C),
        id: f.id,
        secret: new TextEncoder().encode(f.secret)
      })),
      i
    ).map((f) => V(f))), t = Q(t);
    const h = {
      quote: e.quote,
      inputs: t,
      outputs: a.map((f) => f.blindedMessage)
    }, d = await this.mint.melt(h);
    return {
      quote: d,
      change: d.change?.map((f, m) => a[m].toProof(f, c)) ?? []
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
   * @returns
   */
  createSwapPayload(e, t, n, r, o, i, c, a, h) {
    const d = t.reduce((p, _) => p + _.amount, 0);
    r && r.sendAmounts && !r.keepAmounts && (r.keepAmounts = S(
      d - e - this.getFeesForProofs(t),
      n.keys
    ));
    const f = d - e - this.getFeesForProofs(t);
    let m = [], u = [];
    if (a?.keep)
      if (z(a.keep)) {
        const p = a.keep;
        S(f, n.keys).forEach((T) => {
          m.push(p(T, n));
        });
      } else
        m = a.keep;
    else
      m = this.createOutputData(
        f,
        n,
        o,
        void 0,
        r?.keepAmounts,
        void 0,
        this._keepFactory
      );
    if (a?.send)
      if (z(a.send)) {
        const p = a.send;
        S(e, n.keys).forEach((T) => {
          u.push(p(T, n));
        });
      } else
        u = a.send;
    else
      u = this.createOutputData(
        e,
        n,
        o ? o + m.length : void 0,
        i,
        r?.sendAmounts,
        h
      );
    c && (t = ce(
      t.map((p) => ({
        amount: p.amount,
        C: B(p.C),
        id: p.id,
        secret: new TextEncoder().encode(p.secret)
      })),
      c
    ).map((p) => V(p))), t = Q(t);
    const l = [...m, ...u], w = l.map((p, _) => _).sort(
      (p, _) => l[p].blindedMessage.amount - l[_].blindedMessage.amount
    ), y = [
      ...Array(m.length).fill(!0),
      ...Array(u.length).fill(!1)
    ], g = w.map((p) => l[p]), k = w.map((p) => y[p]);
    return {
      payload: {
        inputs: t,
        outputs: g.map((p) => p.blindedMessage)
      },
      outputData: g,
      keepVector: k,
      sortedIndices: w
    };
  }
  /**
   * Get an array of the states of proofs from the mint (as an array of CheckStateEnum's)
   * @param proofs (only the `secret` field is required)
   * @returns
   */
  async checkProofsStates(e) {
    const t = new TextEncoder(), n = e.map((i) => ie(t.encode(i.secret)).toHex(!0)), r = 100, o = [];
    for (let i = 0; i < n.length; i += r) {
      const c = n.slice(i, i + r), { states: a } = await this.mint.check({
        Ys: c
      }), h = {};
      a.forEach((d) => {
        h[d.Y] = d;
      });
      for (let d = 0; d < c.length; d++) {
        const f = h[c[d]];
        if (!f)
          throw new Error("Could not find state for proof with Y: " + c[d]);
        o.push(f);
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
  async onMintQuoteUpdates(e, t, n) {
    if (await this.mint.connectWebSocket(), !this.mint.webSocketConnection)
      throw new Error("failed to establish WebSocket connection.");
    const r = this.mint.webSocketConnection.createSubscription(
      { kind: "bolt11_mint_quote", filters: e },
      t,
      n
    );
    return () => {
      this.mint.webSocketConnection?.cancelSubscription(r, t);
    };
  }
  /**
   * Register a callback to be called whenever a melt quote's state changes
   * @param quoteIds List of melt quote IDs that should be subscribed to
   * @param callback Callback function that will be called whenever a melt quote state changes
   * @param errorCallback
   * @returns
   */
  async onMeltQuotePaid(e, t, n) {
    return this.onMeltQuoteUpdates(
      [e],
      (r) => {
        r.state === N.PAID && t(r);
      },
      n
    );
  }
  /**
   * Register a callback to be called when a single mint quote gets paid
   * @param quoteId Mint quote id that should be subscribed to
   * @param callback Callback function that will be called when this mint quote gets paid
   * @param errorCallback
   * @returns
   */
  async onMintQuotePaid(e, t, n) {
    return this.onMintQuoteUpdates(
      [e],
      (r) => {
        r.state === W.PAID && t(r);
      },
      n
    );
  }
  /**
   * Register a callback to be called when a single melt quote gets paid
   * @param quoteId Melt quote id that should be subscribed to
   * @param callback Callback function that will be called when this melt quote gets paid
   * @param errorCallback
   * @returns
   */
  async onMeltQuoteUpdates(e, t, n) {
    if (await this.mint.connectWebSocket(), !this.mint.webSocketConnection)
      throw new Error("failed to establish WebSocket connection.");
    const r = this.mint.webSocketConnection.createSubscription(
      { kind: "bolt11_melt_quote", filters: e },
      t,
      n
    );
    return () => {
      this.mint.webSocketConnection?.cancelSubscription(r, t);
    };
  }
  /**
   * Register a callback to be called whenever a subscribed proof state changes
   * @param proofs List of proofs that should be subscribed to
   * @param callback Callback function that will be called whenever a proof's state changes
   * @param errorCallback
   * @returns
   */
  async onProofStateUpdates(e, t, n) {
    if (await this.mint.connectWebSocket(), !this.mint.webSocketConnection)
      throw new Error("failed to establish WebSocket connection.");
    const r = new TextEncoder(), o = {};
    for (let a = 0; a < e.length; a++) {
      const h = ie(r.encode(e[a].secret)).toHex(!0);
      o[h] = e[a];
    }
    const i = Object.keys(o), c = this.mint.webSocketConnection.createSubscription(
      { kind: "proof_state", filters: i },
      (a) => {
        t({ ...a, proof: o[a.Y] });
      },
      n
    );
    return () => {
      this.mint.webSocketConnection?.cancelSubscription(c, t);
    };
  }
  /**
   * Creates blinded messages for a according to @param amounts
   * @param amount array of amounts to create blinded messages for
   * @param counter? optionally set counter to derive secret deterministically. CashuWallet class must be initialized with seed phrase to take effect
   * @param keyksetId? override the keysetId derived from the current mintKeys with a custom one. This should be a keyset that was fetched from the `/keysets` endpoint
   * @param pubkey? optionally locks ecash to pubkey. Will not be deterministic, even if counter is set!
   * @returns blinded messages, secrets, rs, and amounts
   */
  createOutputData(e, t, n, r, o, i, c) {
    let a;
    if (r)
      a = q.createP2PKData({ pubkey: r }, e, t, o);
    else if (n || n === 0) {
      if (!this._seed)
        throw new Error("cannot create deterministic messages without seed");
      a = q.createDeterministicData(
        e,
        this._seed,
        n,
        t,
        o
      );
    } else i ? a = q.createP2PKData(i, e, t, o) : c ? a = S(e, t.keys).map((d) => c(d, t)) : a = q.createRandomData(e, t, o);
    return a;
  }
  /**
   * Creates NUT-08 blank outputs (fee returns) for a given fee reserve
   * See: https://github.com/cashubtc/nuts/blob/main/08.md
   * @param amount amount to cover with blank outputs
   * @param keysetId mint keysetId
   * @param counter? optionally set counter to derive secret deterministically. CashuWallet class must be initialized with seed phrase to take effect
   * @returns blinded messages, secrets, and rs
   */
  createBlankOutputs(e, t, n, r) {
    let o = Math.ceil(Math.log2(e)) || 1;
    o < 0 && (o = 0);
    const i = o ? Array(o).fill(1) : [];
    return this.createOutputData(e, t, n, void 0, i, void 0, r);
  }
}
export {
  P as CashuMint,
  Bt as CashuWallet,
  ht as CheckStateEnum,
  N as MeltQuoteState,
  W as MintQuoteState,
  q as OutputData,
  Z as PaymentRequest,
  dt as PaymentRequestTransportType,
  Tt as decodePaymentRequest,
  Mt as deriveKeysetId,
  et as getDecodedToken,
  Dt as getDecodedTokenBinary,
  vt as getEncodedToken,
  Ut as getEncodedTokenBinary,
  Ze as getEncodedTokenV4,
  Ft as injectWebSocketImpl,
  xt as setGlobalRequestOptions
};
//# sourceMappingURL=cashu-ts.es.js.map
