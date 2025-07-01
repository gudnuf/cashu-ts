import { verifyDLEQProof_reblind as Kt } from "./crypto/client/NUT12.es.js";
import { pointFromHex as L, hashToCurve as ct } from "./crypto/common.es.js";
import { hexToBytes as M, bytesToHex as U } from "@noble/curves/abstract/utils";
import { sha256 as Tt } from "@noble/hashes/sha256";
import { Buffer as Q } from "buffer";
import { signP2PKProofs as ut } from "./crypto/client/NUT11.es.js";
import { signMintQuote as Ut } from "./crypto/client/NUT20.es.js";
import { constructProofFromPromise as Dt, serializeProof as xt, blindMessage as H } from "./crypto/client.es.js";
import { hexToBytes as ht, bytesToHex as O, randomBytes as dt } from "@noble/hashes/utils";
import { deriveSecret as Nt, deriveBlindingFactor as Ot } from "./crypto/client/NUT09.es.js";
function Ft(n) {
  return Q.from(n).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function yt(n) {
  return Q.from(n, "base64");
}
function gt(n) {
  const t = JSON.stringify(n);
  return Qt(Q.from(t).toString("base64"));
}
function Bt(n) {
  const t = Q.from(Rt(n), "base64").toString();
  return JSON.parse(t);
}
function Rt(n) {
  return n.replace(/-/g, "+").replace(/_/g, "/").split("=")[0];
}
function Qt(n) {
  return n.replace(/\+/g, "-").replace(/\//g, "_").split("=")[0];
}
function Lt(n) {
  return typeof n == "number" || typeof n == "string";
}
function J(n) {
  const t = [];
  return Y(n, t), new Uint8Array(t);
}
function Y(n, t) {
  if (n === null)
    t.push(246);
  else if (n === void 0)
    t.push(247);
  else if (typeof n == "boolean")
    t.push(n ? 245 : 244);
  else if (typeof n == "number")
    wt(n, t);
  else if (typeof n == "string")
    kt(n, t);
  else if (Array.isArray(n))
    Ct(n, t);
  else if (n instanceof Uint8Array)
    Wt(n, t);
  else if (typeof n == "object")
    Ht(n, t);
  else
    throw new Error("Unsupported type");
}
function wt(n, t) {
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
function Wt(n, t) {
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
function kt(n, t) {
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
function Ct(n, t) {
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
    Y(s, t);
}
function Ht(n, t) {
  const e = Object.keys(n);
  wt(e.length, t), t[t.length - 1] |= 160;
  for (const s of e)
    kt(s, t), Y(n[s], t);
}
function X(n) {
  const t = new DataView(n.buffer, n.byteOffset, n.byteLength);
  return W(t, 0).value;
}
function W(n, t) {
  if (t >= n.byteLength)
    throw new Error("Unexpected end of data");
  const e = n.getUint8(t++), s = e >> 5, r = e & 31;
  switch (s) {
    case 0:
      return jt(n, t, r);
    case 1:
      return $t(n, t, r);
    case 2:
      return zt(n, t, r);
    case 3:
      return Gt(n, t, r);
    case 4:
      return Vt(n, t, r);
    case 5:
      return Jt(n, t, r);
    case 7:
      return Xt(n, t, r);
    default:
      throw new Error(`Unsupported major type: ${s}`);
  }
}
function x(n, t, e) {
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
function jt(n, t, e) {
  const { value: s, offset: r } = x(n, t, e);
  return { value: s, offset: r };
}
function $t(n, t, e) {
  const { value: s, offset: r } = x(n, t, e);
  return { value: -1 - s, offset: r };
}
function zt(n, t, e) {
  const { value: s, offset: r } = x(n, t, e);
  if (r + s > n.byteLength)
    throw new Error("Byte string length exceeds data length");
  return { value: new Uint8Array(n.buffer, n.byteOffset + r, s), offset: r + s };
}
function Gt(n, t, e) {
  const { value: s, offset: r } = x(n, t, e);
  if (r + s > n.byteLength)
    throw new Error("String length exceeds data length");
  const i = new Uint8Array(n.buffer, n.byteOffset + r, s);
  return { value: new TextDecoder().decode(i), offset: r + s };
}
function Vt(n, t, e) {
  const { value: s, offset: r } = x(n, t, e), i = [];
  let a = r;
  for (let o = 0; o < s; o++) {
    const c = W(n, a);
    i.push(c.value), a = c.offset;
  }
  return { value: i, offset: a };
}
function Jt(n, t, e) {
  const { value: s, offset: r } = x(n, t, e), i = {};
  let a = r;
  for (let o = 0; o < s; o++) {
    const c = W(n, a);
    if (!Lt(c.value))
      throw new Error("Invalid key type");
    const u = W(n, c.offset);
    i[c.value] = u.value, a = u.offset;
  }
  return { value: i, offset: a };
}
function Yt(n) {
  const t = (n & 31744) >> 10, e = n & 1023, s = n & 32768 ? -1 : 1;
  return t === 0 ? s * 2 ** -14 * (e / 1024) : t === 31 ? e ? NaN : s * (1 / 0) : s * 2 ** (t - 15) * (1 + e / 1024);
}
function Xt(n, t, e) {
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
    const s = Yt(n.getUint16(t, !1));
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
class Z {
  constructor(t, e, s, r, i, a, o = !1, c) {
    this.transport = t, this.id = e, this.amount = s, this.unit = r, this.mints = i, this.description = a, this.singleUse = o, this.nut10 = c;
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
    const t = this.toRawRequest(), e = J(t);
    return "creqA" + Q.from(e).toString("base64");
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
    return new Z(
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
    const s = t.slice(5), r = yt(s), i = X(r);
    return this.fromRawRequest(i);
  }
}
const Zt = "A", te = "cashu";
function S(n, t, e, s) {
  if (e) {
    const i = pt(e);
    if (i > n)
      throw new Error(`Split is greater than total amount: ${i} > ${n}`);
    if (e.some((a) => !bt(a, t)))
      throw new Error("Provided amount preferences do not match the amounts of the mint keyset.");
    n = n - pt(e);
  } else
    e = [];
  return _t(t, "desc").forEach((i) => {
    const a = Math.floor(n / i);
    for (let o = 0; o < a; ++o) e?.push(i);
    n %= i;
  }), e.sort((i, a) => i - a);
}
function lt(n, t, e, s) {
  const r = [], i = n.map((u) => u.amount);
  _t(e, "asc").forEach((u) => {
    const d = i.filter((p) => p === u).length, f = Math.max(s - d, 0);
    for (let p = 0; p < f && !(r.reduce((h, l) => h + l, 0) + u > t); ++p)
      r.push(u);
  });
  const o = t - r.reduce((u, d) => u + d, 0);
  return o && S(o, e).forEach((d) => {
    r.push(d);
  }), r.sort((u, d) => u - d);
}
function _t(n, t = "desc") {
  return t == "desc" ? Object.keys(n).map((e) => parseInt(e)).sort((e, s) => s - e) : Object.keys(n).map((e) => parseInt(e)).sort((e, s) => e - s);
}
function bt(n, t) {
  return n in t;
}
function ee(n) {
  return At(U(n));
}
function At(n) {
  return BigInt(`0x${n}`);
}
function se(n) {
  return n.toString(16).padStart(64, "0");
}
function ft(n) {
  return /^[a-f0-9]*$/i.test(n);
}
function Et(n) {
  return Array.isArray(n) ? n.some((t) => !ft(t.id)) : ft(n.id);
}
function ne(n, t) {
  t && (n.proofs = C(n.proofs));
  const e = { token: [{ mint: n.mint, proofs: n.proofs }] };
  return n.unit && (e.unit = n.unit), n.memo && (e.memo = n.memo), te + Zt + gt(e);
}
function Ke(n, t) {
  if (Et(n.proofs) || t?.version === 3) {
    if (t?.version === 4)
      throw new Error("can not encode to v4 token if proofs contain non-hex keyset id");
    return ne(n, t?.removeDleq);
  }
  return re(n, t?.removeDleq);
}
function re(n, t) {
  if (t && (n.proofs = C(n.proofs)), n.proofs.forEach((c) => {
    if (c.dleq && c.dleq.r == null)
      throw new Error("Missing blinding factor in included DLEQ proof");
  }), Et(n.proofs))
    throw new Error("can not encode to v4 token if proofs contain non-hex keyset id");
  const s = Pt(n), r = J(s), i = "cashu", a = "B", o = Ft(r);
  return i + a + o;
}
function Pt(n) {
  const t = {}, e = n.mint;
  for (let r = 0; r < n.proofs.length; r++) {
    const i = n.proofs[r];
    t[i.id] ? t[i.id].push(i) : t[i.id] = [i];
  }
  const s = {
    m: e,
    u: n.unit || "sat",
    t: Object.keys(t).map(
      (r) => ({
        i: M(r),
        p: t[r].map(
          (i) => ({
            a: i.amount,
            s: i.secret,
            c: M(i.C),
            ...i.dleq && {
              d: {
                e: M(i.dleq.e),
                s: M(i.dleq.s),
                r: M(i.dleq.r ?? "00")
              }
            },
            ...i.witness && {
              w: JSON.stringify(i.witness)
            }
          })
        )
      })
    )
  };
  return n.memo && (s.d = n.memo), s;
}
function St(n) {
  const t = [];
  n.t.forEach(
    (s) => s.p.forEach((r) => {
      t.push({
        secret: r.s,
        C: U(r.c),
        amount: r.a,
        id: U(s.i),
        ...r.d && {
          dleq: {
            r: U(r.d.r),
            s: U(r.d.s),
            e: U(r.d.e)
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
function ie(n) {
  return ["web+cashu://", "cashu://", "cashu:", "cashu"].forEach((e) => {
    n.startsWith(e) && (n = n.slice(e.length));
  }), oe(n);
}
function oe(n) {
  const t = n.slice(0, 1), e = n.slice(1);
  if (t === "A") {
    const s = Bt(e);
    if (s.token.length > 1)
      throw new Error("Multi entry token are not supported");
    const r = s.token[0], i = {
      mint: r.mint,
      proofs: r.proofs,
      unit: s.unit || "sat"
    };
    return s.memo && (i.memo = s.memo), i;
  } else if (t === "B") {
    const s = yt(e), r = X(s);
    return St(r);
  }
  throw new Error("Token version is not supported");
}
function Te(n) {
  const t = Object.entries(n).sort((r, i) => +r[0] - +i[0]).map(([, r]) => M(r)).reduce((r, i) => ae(r, i), new Uint8Array()), e = Tt(t);
  return "00" + Buffer.from(e).toString("hex").slice(0, 14);
}
function ae(n, t) {
  const e = new Uint8Array(n.length + t.length);
  return e.set(n), e.set(t, n.length), e;
}
function q(n) {
  return typeof n == "object";
}
function _(...n) {
  return n.map((t) => t.replace(/(^\/+|\/+$)/g, "")).join("/");
}
function It(n) {
  return n.replace(/\/$/, "");
}
function T(n) {
  return n.reduce((t, e) => t + e.amount, 0);
}
function Ue(n) {
  return Z.fromEncodedRequest(n);
}
class ce {
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
class ue {
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
    const e = new ce(t);
    return this._size === 0 || !this._last ? (this._first = e, this._last = e) : (this._last.next = e, this._last = e), this._size++, !0;
  }
  dequeue() {
    if (this._size === 0 || !this._first) return null;
    const t = this._first;
    return this._first = t.next, t.next = null, this._size--, t.value;
  }
}
function C(n) {
  return n.map((t) => {
    const e = { ...t };
    return delete e.dleq, e;
  });
}
function qt(n, t) {
  if (n.dleq == null)
    return !1;
  const e = {
    e: M(n.dleq.e),
    s: M(n.dleq.s),
    r: At(n.dleq.r ?? "00")
  };
  if (!bt(n.amount, t.keys))
    throw new Error(`undefined key for amount ${n.amount}`);
  const s = t.keys[n.amount];
  return !!Kt(
    new TextEncoder().encode(n.secret),
    e,
    L(n.C),
    L(s)
  );
}
function he(...n) {
  const t = n.reduce((r, i) => r + i.length, 0), e = new Uint8Array(t);
  let s = 0;
  for (let r = 0; r < n.length; r++)
    e.set(n[r], s), s = s + n[r].length;
  return e;
}
function De(n) {
  const t = new TextEncoder(), e = Pt(n), s = J(e), r = t.encode("craw"), i = t.encode("B");
  return he(r, i, s);
}
function xe(n) {
  const t = new TextDecoder(), e = t.decode(n.slice(0, 4)), s = t.decode(new Uint8Array([n[4]]));
  if (e !== "craw" || s !== "B")
    throw new Error("not a valid binary token");
  const r = n.slice(5), i = X(r);
  return St(i);
}
function pt(n) {
  return n.reduce((t, e) => t + e, 0);
}
let tt;
typeof WebSocket < "u" && (tt = WebSocket);
function Ne(n) {
  tt = n;
}
function de() {
  return tt;
}
class D {
  constructor() {
    this.connectionMap = /* @__PURE__ */ new Map();
  }
  static getInstance() {
    return D.instace || (D.instace = new D()), D.instace;
  }
  getConnection(t) {
    if (this.connectionMap.has(t))
      return this.connectionMap.get(t);
    const e = new le(t);
    return this.connectionMap.set(t, e), e;
  }
}
class le {
  constructor(t) {
    this.subListeners = {}, this.rpcListeners = {}, this.rpcId = 0, this.onCloseCallbacks = [], this._WS = de(), this.url = new URL(t), this.messageQueue = new ue();
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
          this.subListeners[s].forEach((i) => i(r.params.payload));
        }
      }
    } catch (s) {
      console.error(s);
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
      (i) => {
        s(new Error(i.message));
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
const Oe = {
  UNSPENT: "UNSPENT",
  PENDING: "PENDING",
  SPENT: "SPENT"
}, B = {
  UNPAID: "UNPAID",
  PENDING: "PENDING",
  PAID: "PAID"
}, G = {
  UNPAID: "UNPAID",
  PAID: "PAID",
  ISSUED: "ISSUED"
};
var fe = /* @__PURE__ */ ((n) => (n.POST = "post", n.NOSTR = "nostr", n))(fe || {});
class R extends Error {
  constructor(t, e) {
    super(t), this.status = e, this.name = "HttpResponseError", Object.setPrototypeOf(this, R.prototype);
  }
}
class et extends Error {
  constructor(t) {
    super(t), this.name = "NetworkError", Object.setPrototypeOf(this, et.prototype);
  }
}
class st extends R {
  constructor(t, e) {
    super(e || "Unknown mint operation error", 400), this.code = t, this.name = "MintOperationError", Object.setPrototypeOf(this, st.prototype);
  }
}
let vt = {};
function Fe(n) {
  vt = n;
}
async function pe({
  endpoint: n,
  requestBody: t,
  headers: e,
  ...s
}) {
  const r = t ? JSON.stringify(t) : void 0, i = {
    Accept: "application/json, text/plain, */*",
    ...r ? { "Content-Type": "application/json" } : void 0,
    ...e
  };
  let a;
  try {
    a = await fetch(n, { body: r, headers: i, ...s });
  } catch (o) {
    throw new et(o instanceof Error ? o.message : "Network request failed");
  }
  if (!a.ok) {
    const o = await a.json().catch(() => ({ error: "bad response" }));
    throw a.status === 400 && "code" in o && "detail" in o ? new st(o.code, o.detail) : new R(
      "error" in o ? o.error : o.detail || "HTTP request failed",
      a.status
    );
  }
  try {
    return await a.json();
  } catch (o) {
    throw console.error("Failed to parse HTTP response", o), new R("bad response", a.status);
  }
}
async function A(n) {
  return await pe({ ...n, ...vt });
}
function j(n) {
  return n.state || (console.warn(
    "Field 'state' not found in MeltQuoteResponse. Update NUT-05 of mint: https://github.com/cashubtc/nuts/pull/136)"
  ), typeof n.paid == "boolean" && (n.state = n.paid ? B.PAID : B.UNPAID)), n;
}
function mt(n) {
  return n.state || (console.warn(
    "Field 'state' not found in MintQuoteResponse. Update NUT-04 of mint: https://github.com/cashubtc/nuts/pull/141)"
  ), typeof n.paid == "boolean" && (n.state = n.paid ? G.PAID : G.UNPAID)), n;
}
function me(n) {
  return Array.isArray(n?.contact) && n?.contact.length > 0 && (n.contact = n.contact.map((t) => Array.isArray(t) && t.length === 2 && typeof t[0] == "string" && typeof t[1] == "string" ? (console.warn(
    "Mint returned deprecated 'contact' field: Update NUT-06: https://github.com/cashubtc/nuts/pull/117"
  ), { method: t[0], info: t[1] }) : t)), n;
}
class V {
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
class E {
  /**
   * @param _mintUrl requires mint URL to create this object
   * @param _customRequest if passed, use custom request implementation for network communication with the mint
   * @param [blindAuthTokenGetter] a function that is called by the CashuMint instance to obtain a NUT-22 BlindedAuthToken (e.g. from a database or localstorage). This function should consume the BAT as they are one-time use tokens.
   * @param [clearAuthTokenGetter] a function that is called by the CashuMint instance to obtain a NUT-21 ClearAuthToken (e.g. from a database or localstorage)
   */
  constructor(t, e, s, r) {
    this._mintUrl = t, this._customRequest = e, this._mintUrl = It(t), this._customRequest = e, this._blindAuthTokenGetter = s, this._clearAuthTokenGetter = r;
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
  static async getInfo(t, e) {
    const r = await (e || A)({
      endpoint: _(t, "/v1/info")
    });
    return me(r);
  }
  /**
   * fetches mints info at the /info endpoint
   */
  async getInfo() {
    return E.getInfo(this._mintUrl, this._customRequest);
  }
  async getLazyMintInfo() {
    if (this._mintInfo)
      return this._mintInfo;
    const t = await E.getInfo(this._mintUrl, this._customRequest);
    return this._mintInfo = new V(t), this._mintInfo;
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
    const a = await (s || A)({
      endpoint: _(t, "/v1/swap"),
      method: "POST",
      requestBody: e,
      headers: r || {}
    });
    if (!q(a) || !Array.isArray(a?.signatures))
      throw new Error(a.detail ?? "bad response");
    return a;
  }
  /**
   * Performs a swap operation with ecash inputs and outputs.
   * @param swapPayload payload containing inputs and outputs
   * @returns signed outputs
   */
  async swap(t) {
    const e = await this.getAuthHeaders("/v1/swap");
    return E.swap(this._mintUrl, t, this._customRequest, e);
  }
  /**
   * Requests a new mint quote from the mint.
   * @param mintUrl
   * @param mintQuotePayload Payload for creating a new mint quote
   * @param customRequest
   * @param headers Authentication headers for protected endpoints
   * @returns the mint will create and return a new mint quote containing a payment request for the specified amount and unit
   */
  static async createMintQuote(t, e, s, r) {
    const a = await (s || A)({
      endpoint: _(t, "/v1/mint/quote/bolt11"),
      method: "POST",
      requestBody: e,
      headers: r || {}
    });
    return mt(a);
  }
  /**
   * Requests a new mint quote from the mint.
   * @param mintQuotePayload Payload for creating a new mint quote
   * @returns the mint will create and return a new mint quote containing a payment request for the specified amount and unit
   */
  async createMintQuote(t) {
    const e = await this.getAuthHeaders("/v1/mint/quote/bolt11");
    return E.createMintQuote(this._mintUrl, t, this._customRequest, e);
  }
  /**
   * Gets an existing mint quote from the mint.
   * @param mintUrl
   * @param quote Quote ID
   * @param customRequest
   * @param headers Authentication headers for protected endpoints
   * @returns the mint will create and return a Lightning invoice for the specified amount
   */
  static async checkMintQuote(t, e, s, r) {
    const a = await (s || A)({
      endpoint: _(t, "/v1/mint/quote/bolt11", e),
      method: "GET",
      headers: r || {}
    });
    return mt(a);
  }
  /**
   * Gets an existing mint quote from the mint.
   * @param quote Quote ID
   * @returns the mint will create and return a Lightning invoice for the specified amount
   */
  async checkMintQuote(t) {
    const e = await this.getAuthHeaders(`/v1/mint/quote/bolt11/${t}`);
    return E.checkMintQuote(this._mintUrl, t, this._customRequest, e);
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
    const a = await (s || A)({
      endpoint: _(t, "/v1/mint/bolt11"),
      method: "POST",
      requestBody: e,
      headers: r || {}
    });
    if (!q(a) || !Array.isArray(a?.signatures))
      throw new Error("bad response");
    return a;
  }
  /**
   * Mints new tokens by requesting blind signatures on the provided outputs.
   * @param mintPayload Payload containing the outputs to get blind signatures on
   * @returns serialized blinded signatures
   */
  async mint(t) {
    const e = await this.getAuthHeaders("/v1/mint/bolt11");
    return E.mint(this._mintUrl, t, this._customRequest, e);
  }
  /**
   * Requests a new melt quote from the mint.
   * @param mintUrl
   * @param MeltQuotePayload
   * @param customRequest
   * @param headers Authentication headers for protected endpoints
   * @returns
   */
  static async createMeltQuote(t, e, s, r) {
    const a = await (s || A)({
      endpoint: _(t, "/v1/melt/quote/bolt11"),
      method: "POST",
      requestBody: e,
      headers: r || {}
    }), o = j(a);
    if (!q(o) || typeof o?.amount != "number" || typeof o?.fee_reserve != "number" || typeof o?.quote != "string")
      throw new Error("bad response");
    return o;
  }
  /**
   * Requests a new melt quote from the mint.
   * @param MeltQuotePayload
   * @returns
   */
  async createMeltQuote(t) {
    const e = await this.getAuthHeaders("/v1/melt/quote/bolt11");
    return E.createMeltQuote(this._mintUrl, t, this._customRequest, e);
  }
  /**
   * Gets an existing melt quote.
   * @param mintUrl
   * @param quote Quote ID
   * @param customRequest
   * @param headers Authentication headers for protected endpoints
   * @returns
   */
  static async checkMeltQuote(t, e, s, r) {
    const a = await (s || A)({
      endpoint: _(t, "/v1/melt/quote/bolt11", e),
      method: "GET",
      headers: r || {}
    }), o = j(a);
    if (!q(o) || typeof o?.amount != "number" || typeof o?.fee_reserve != "number" || typeof o?.quote != "string" || typeof o?.state != "string" || !Object.values(B).includes(o.state))
      throw new Error("bad response");
    return o;
  }
  /**
   * Gets an existing melt quote.
   * @param quote Quote ID
   * @returns
   */
  async checkMeltQuote(t) {
    const e = await this.getAuthHeaders(`/v1/melt/quote/bolt11/${t}`);
    return E.checkMeltQuote(this._mintUrl, t, this._customRequest, e);
  }
  /**
   * Requests the mint to pay for a Bolt11 payment request by providing ecash as inputs to be spent. The inputs contain the amount and the fee_reserves for a Lightning payment. The payload can also contain blank outputs in order to receive back overpaid Lightning fees.
   * @param mintUrl
   * @param meltPayload
   * @param customRequest
   * @param headers Authentication headers for protected endpoints
   * @returns
   */
  static async melt(t, e, s, r) {
    const a = await (s || A)({
      endpoint: _(t, "/v1/melt/bolt11"),
      method: "POST",
      requestBody: e,
      headers: r || {}
    }), o = j(a);
    if (!q(o) || typeof o?.state != "string" || !Object.values(B).includes(o.state))
      throw new Error("bad response");
    return o;
  }
  /**
   * Ask mint to perform a melt operation. This pays a lightning invoice and destroys tokens matching its amount + fees
   * @param meltPayload
   * @returns
   */
  async melt(t) {
    const e = await this.getAuthHeaders("/v1/melt/bolt11");
    return E.melt(this._mintUrl, t, this._customRequest, e);
  }
  /**
   * Checks if specific proofs have already been redeemed
   * @param mintUrl
   * @param checkPayload
   * @param customRequest
   * @returns redeemed and unredeemed ordered list of booleans
   */
  static async check(t, e, s, r) {
    const a = await (s || A)({
      endpoint: _(t, "/v1/checkstate"),
      method: "POST",
      requestBody: e,
      headers: r || {}
    });
    if (!q(a) || !Array.isArray(a?.states))
      throw new Error("bad response");
    return a;
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
    const i = await (s || A)({
      endpoint: e ? _(t, "/v1/keys", e) : _(t, "/v1/keys")
    });
    if (!q(i) || !Array.isArray(i.keysets))
      throw new Error("bad response");
    return i;
  }
  /**
   * Get the mints public keys
   * @param keysetId optional param to get the keys for a specific keyset. If not specified, the keys from all active keysets are fetched
   * @returns the mints public keys
   */
  async getKeys(t, e) {
    return await E.getKeys(
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
    return (e || A)({ endpoint: _(t, "/v1/keysets") });
  }
  /**
   * Get the mints keysets in no specific order
   * @returns all the mints past and current keysets.
   */
  async getKeySets() {
    return E.getKeySets(this._mintUrl, this._customRequest);
  }
  /**
   * Checks if specific proofs have already been redeemed
   * @param checkPayload
   * @returns redeemed and unredeemed ordered list of booleans
   */
  async check(t) {
    const e = await this.getAuthHeaders("/v1/checkstate");
    return E.check(this._mintUrl, t, this._customRequest, e);
  }
  static async restore(t, e, s) {
    const i = await (s || A)({
      endpoint: _(t, "/v1/restore"),
      method: "POST",
      requestBody: e
    });
    if (!q(i) || !Array.isArray(i?.outputs) || !Array.isArray(i?.signatures))
      throw new Error("bad response");
    return i;
  }
  async restore(t) {
    return E.restore(this._mintUrl, t, this._customRequest);
  }
  /**
   * Tries to establish a websocket connection with the websocket mint url according to NUT-17
   */
  async connectWebSocket() {
    if (this.ws)
      await this.ws.ensureConnection();
    else {
      const t = new URL(this._mintUrl), e = "v1/ws";
      t.pathname && (t.pathname.endsWith("/") ? t.pathname += e : t.pathname += "/" + e), this.ws = D.getInstance().getConnection(
        `${t.protocol === "https:" ? "wss" : "ws"}://${t.host}${t.pathname}`
      );
      try {
        await this.ws.connect();
      } catch (s) {
        throw console.log(s), new Error("Failed to connect to WebSocket...");
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
class $ {
  constructor(t, e, s) {
    this.amount = t, this.B_ = e, this.id = s;
  }
  getSerializedBlindedMessage() {
    return { amount: this.amount, B_: this.B_.toHex(!0), id: this.id };
  }
}
function z(n) {
  return typeof n == "function";
}
class v {
  constructor(t, e, s) {
    this.secret = s, this.blindingFactor = e, this.blindedMessage = t;
  }
  toProof(t, e) {
    let s;
    t.dleq && (s = {
      s: ht(t.dleq.s),
      e: ht(t.dleq.e),
      r: this.blindingFactor
    });
    const r = {
      id: t.id,
      amount: t.amount,
      C_: L(t.C_),
      dleq: s
    }, i = L(e.keys[t.amount]), a = Dt(r, this.blindingFactor, this.secret, i);
    return {
      ...xt(a),
      ...s && {
        dleq: {
          s: O(s.s),
          e: O(s.e),
          r: se(s.r ?? BigInt(0))
        }
      }
    };
  }
  static createP2PKData(t, e, s, r) {
    return S(e, s.keys, r).map((a) => this.createSingleP2PKData(t, a, s.id));
  }
  static createSingleP2PKData(t, e, s) {
    const r = Array.isArray(t.pubkey) ? t.pubkey : [t.pubkey], i = Math.max(1, Math.min(t.requiredSignatures || 1, r.length)), a = Math.max(
      1,
      Math.min(t.requiredRefundSignatures || 1, t.refundKeys ? t.refundKeys.length : 1)
    ), o = [
      "P2PK",
      {
        nonce: O(dt(32)),
        data: r[0],
        // Primary key
        tags: []
      }
    ];
    t.locktime && o[1].tags.push(["locktime", String(t.locktime)]), r.length > 1 && (o[1].tags.push(["pubkeys", ...r.slice(1)]), i > 1 && o[1].tags.push(["n_sigs", String(i)])), t.refundKeys && (o[1].tags.push(["refund", ...t.refundKeys]), a > 1 && o[1].tags.push(["n_sigs_refund", String(a)]));
    const c = JSON.stringify(o), u = new TextEncoder().encode(c), { r: d, B_: f } = H(u);
    return new v(
      new $(e, f, s).getSerializedBlindedMessage(),
      d,
      u
    );
  }
  static createRandomData(t, e, s) {
    return S(t, e.keys, s).map((i) => this.createSingleRandomData(i, e.id));
  }
  static createSingleRandomData(t, e) {
    const s = O(dt(32)), r = new TextEncoder().encode(s), { r: i, B_: a } = H(r);
    return new v(
      new $(t, a, e).getSerializedBlindedMessage(),
      i,
      r
    );
  }
  static createDeterministicData(t, e, s, r, i) {
    return S(t, r.keys, i).map(
      (o, c) => this.createSingleDeterministicData(o, e, s + c, r.id)
    );
  }
  static createSingleDeterministicData(t, e, s, r) {
    const i = Nt(e, r, s), a = O(i), o = new TextEncoder().encode(a), c = ee(Ot(e, r, s)), { r: u, B_: d } = H(o, c);
    return new v(
      new $(t, d, r).getSerializedBlindedMessage(),
      u,
      o
    );
  }
}
const ye = 3, ge = "sat";
class Be {
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
    this._keys = /* @__PURE__ */ new Map(), this._keysets = [], this._seed = void 0, this._unit = ge, this._mintInfo = void 0, this._denominationTarget = ye, this.mint = t;
    let s = [];
    if (e?.keys && !Array.isArray(e.keys) ? s = [e.keys] : e?.keys && Array.isArray(e?.keys) && (s = e?.keys), s && s.forEach((r) => this._keys.set(r.id, r)), e?.unit && (this._unit = e?.unit), e?.keysets && (this._keysets = e.keysets), e?.mintInfo && (this._mintInfo = new V(e.mintInfo)), e?.denominationTarget && (this._denominationTarget = e.denominationTarget), e?.bip39seed) {
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
    return this._mintInfo = new V(t), this._mintInfo;
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
      (r, i) => (r.input_fee_ppk ?? 0) - (i.input_fee_ppk ?? 0)
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
    const { requireDleq: s, keysetId: r, outputAmounts: i, counter: a, pubkey: o, privkey: c, outputData: u, p2pk: d } = e || {};
    typeof t == "string" && (t = ie(t));
    const f = await this.getKeys(r);
    if (s && t.proofs.some((k) => !qt(k, f)))
      throw new Error("Token contains proofs with invalid DLEQ");
    const p = T(t.proofs) - this.getFeesForProofs(t.proofs);
    let h;
    u ? h = { send: u } : this._keepFactory && (h = { send: this._keepFactory });
    const l = this.createSwapPayload(
      p,
      t.proofs,
      f,
      i,
      a,
      o,
      c,
      h,
      d
    ), { signatures: w } = await this.mint.swap(l.payload), y = l.outputData.map((k, m) => k.toProof(w[m], f)), g = [];
    return l.sortedIndices.forEach((k, m) => {
      g[k] = y[m];
    }), g;
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
      proofsWeHave: r,
      offline: i,
      includeFees: a,
      includeDleq: o,
      keysetId: c,
      outputAmounts: u,
      pubkey: d,
      privkey: f,
      outputData: p
    } = s || {};
    if (o && (e = e.filter((y) => y.dleq != null)), T(e) < t)
      throw new Error("Not enough funds available to send");
    const { keep: h, send: l } = this.selectProofsToSend(
      e,
      t,
      s?.includeFees
    ), w = a ? this.getFeesForProofs(l) : 0;
    if (!i && (T(l) != t + w || // if the exact amount cannot be selected
    u || d || f || c || p)) {
      const { keep: y, send: g } = this.selectProofsToSend(
        e,
        t,
        !0
      );
      r?.push(...y);
      const k = await this.swap(t, g, s);
      let { keep: m, send: P } = k;
      const K = k.serialized;
      return m = y.concat(m), { keep: m, send: P, serialized: K };
    }
    if (T(l) < t + w)
      throw new Error("Not enough funds available to send");
    return { keep: h, send: l };
  }
  selectProofsToSend(t, e, s) {
    const r = t.sort((h, l) => h.amount - l.amount), i = r.filter((h) => h.amount <= e).sort((h, l) => l.amount - h.amount), o = r.filter((h) => h.amount > e).sort((h, l) => h.amount - l.amount)[0];
    if (!i.length && o)
      return {
        keep: t.filter((h) => h.secret !== o.secret),
        send: [o]
      };
    if (!i.length && !o)
      return { keep: t, send: [] };
    let c = e, u = [i[0]];
    const d = [], f = s ? this.getProofFeePPK(u[0]) : 0;
    if (c -= u[0].amount - f / 1e3, c > 0) {
      const { keep: h, send: l } = this.selectProofsToSend(
        i.slice(1),
        c,
        s
      );
      u.push(...l), d.push(...h);
    }
    const p = s ? this.getFeesForProofs(u) : 0;
    return T(u) < e + p && o && (u = [o]), {
      keep: t.filter((h) => !u.includes(h)),
      send: u
    };
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
    const { includeFees: i, keysetId: a, counter: o, pubkey: c, privkey: u, proofsWeHave: d, outputData: f, p2pk: p } = s || {}, h = await this.getKeys(a), l = e;
    let w = t;
    const y = T(e);
    let g = y - w - this.getFeesForProofs(l), k = r?.sendAmounts || S(w, h.keys);
    if (i) {
      let b = this.getFeesForKeyset(k.length, h.id), I = S(b, h.keys);
      for (; this.getFeesForKeyset(k.concat(I).length, h.id) > b; )
        b++, I = S(b, h.keys);
      k = k.concat(I), w += b, g -= b;
    }
    let m;
    if (!r?.keepAmounts && d)
      m = lt(
        d,
        g,
        h.keys,
        this._denominationTarget
      );
    else if (r) {
      if (r.keepAmounts?.reduce((b, I) => b + I, 0) != g)
        throw new Error("Keep amounts do not match amount to keep");
      m = r.keepAmounts;
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
      keepAmounts: m,
      sendAmounts: k
    };
    const P = f?.keep || this._keepFactory, K = f?.send, N = this.createSwapPayload(
      w,
      l,
      h,
      r,
      o,
      c,
      u,
      { keep: P, send: K },
      p
    ), { signatures: Mt } = await this.mint.swap(N.payload), nt = N.outputData.map((b, I) => b.toProof(Mt[I], h)), rt = [], it = [], ot = Array(N.keepVector.length), at = Array(nt.length);
    return N.sortedIndices.forEach((b, I) => {
      ot[b] = N.keepVector[I], at[b] = nt[I];
    }), at.forEach((b, I) => {
      ot[I] ? rt.push(b) : it.push(b);
    }), {
      keep: rt,
      send: it
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
    const i = Math.ceil(t / e), a = [];
    let o, c = 0;
    for (; c < i; ) {
      const u = await this.restore(s, e, { keysetId: r });
      u.proofs.length > 0 ? (c = 0, a.push(...u.proofs), o = u.lastCounterWithSignature) : c++, s += e;
    }
    return { proofs: a, lastCounterWithSignature: o };
  }
  /**
   * Regenerates
   * @param start set starting point for count (first cycle for each keyset should usually be 0)
   * @param count set number of blinded messages that should be generated
   * @param options.keysetId set a custom keysetId to restore from. keysetIds can be loaded with `CashuMint.getKeySets()`
   */
  async restore(t, e, s) {
    const { keysetId: r } = s || {}, i = await this.getKeys(r);
    if (!this._seed)
      throw new Error("CashuWallet must be initialized with a seed to use restore");
    const a = Array(e).fill(1), o = v.createDeterministicData(
      a.length,
      this._seed,
      t,
      i,
      a
    ), { outputs: c, signatures: u } = await this.mint.restore({
      outputs: o.map((h) => h.blindedMessage)
    }), d = {};
    c.forEach((h, l) => d[h.B_] = u[l]);
    const f = [];
    let p;
    for (let h = 0; h < o.length; h++) {
      const l = d[o[h].blindedMessage.B_];
      l && (p = t + h, o[h].blindedMessage.amount = l.amount, f.push(o[h].toProof(l, i)));
    }
    return {
      proofs: f,
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
    const i = {
      unit: this._unit,
      amount: t,
      description: s,
      pubkey: e
    }, a = await this.mint.createMintQuote(i);
    if (typeof a.pubkey != "string")
      throw new Error("Mint returned unlocked mint quote");
    {
      const o = a.pubkey;
      return { ...a, pubkey: o, amount: a.amount || t, unit: a.unit || this.unit };
    }
  }
  async checkMintQuote(t) {
    const e = typeof t == "string" ? t : t.quote, s = await this.mint.checkMintQuote(e);
    return typeof t == "string" ? s : { ...s, amount: s.amount || t.amount, unit: s.unit || t.unit };
  }
  async mintProofs(t, e, s) {
    let { outputAmounts: r } = s || {};
    const { counter: i, pubkey: a, p2pk: o, keysetId: c, proofsWeHave: u, outputData: d, privateKey: f } = s || {}, p = await this.getKeys(c);
    !r && u && (r = {
      keepAmounts: lt(u, t, p.keys, this._denominationTarget),
      sendAmounts: []
    });
    let h = [];
    if (d)
      if (z(d)) {
        const y = S(t, p.keys, r?.keepAmounts);
        for (let g = 0; g < y.length; g++)
          h.push(d(y[g], p));
      } else
        h = d;
    else if (this._keepFactory) {
      const y = S(t, p.keys, r?.keepAmounts);
      for (let g = 0; g < y.length; g++)
        h.push(this._keepFactory(y[g], p));
    } else
      h = this.createOutputData(
        t,
        p,
        i,
        a,
        r?.keepAmounts,
        o
      );
    let l;
    if (typeof e != "string") {
      if (!f)
        throw new Error("Can not sign locked quote without private key");
      const y = h.map((k) => k.blindedMessage), g = Ut(f, e.quote, y);
      l = {
        outputs: y,
        quote: e.quote,
        signature: g
      };
    } else
      l = {
        outputs: h.map((y) => y.blindedMessage),
        quote: e
      };
    const { signatures: w } = await this.mint.mint(l);
    return h.map((y, g) => y.toProof(w[g], p));
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
    const a = {
      mpp: {
        amount: e
      }
    }, o = {
      unit: this._unit,
      request: t,
      options: a
    };
    return { ...await this.mint.createMeltQuote(o), request: t, unit: this._unit };
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
    const { keysetId: r, counter: i, privkey: a } = s || {}, o = await this.getKeys(r), c = this.createBlankOutputs(
      T(e) - t.amount,
      o,
      i,
      this._keepFactory
    );
    a != null && (e = ut(e, a)), e = C(e), e = e.map((f) => {
      const p = f.witness && typeof f.witness != "string" ? JSON.stringify(f.witness) : f.witness;
      return { ...f, witness: p };
    });
    const u = {
      quote: t.quote,
      inputs: e,
      outputs: c.map((f) => f.blindedMessage)
    }, d = await this.mint.melt(u);
    return {
      quote: { ...d, unit: t.unit, request: t.request },
      change: d.change?.map((f, p) => c[p].toProof(f, o)) ?? []
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
  createSwapPayload(t, e, s, r, i, a, o, c, u) {
    const d = e.reduce((m, P) => m + P.amount, 0);
    r && r.sendAmounts && !r.keepAmounts && (r.keepAmounts = S(
      d - t - this.getFeesForProofs(e),
      s.keys
    ));
    const f = d - t - this.getFeesForProofs(e);
    let p = [], h = [];
    if (c?.keep)
      if (z(c.keep)) {
        const m = c.keep;
        S(f, s.keys).forEach((K) => {
          p.push(m(K, s));
        });
      } else
        p = c.keep;
    else
      p = this.createOutputData(
        f,
        s,
        i,
        void 0,
        r?.keepAmounts,
        void 0,
        this._keepFactory
      );
    if (c?.send)
      if (z(c.send)) {
        const m = c.send;
        S(t, s.keys).forEach((K) => {
          h.push(m(K, s));
        });
      } else
        h = c.send;
    else
      h = this.createOutputData(
        t,
        s,
        i ? i + p.length : void 0,
        a,
        r?.sendAmounts,
        u
      );
    o && (e = ut(e, o)), e = C(e), e = e.map((m) => {
      const P = m.witness && typeof m.witness != "string" ? JSON.stringify(m.witness) : m.witness;
      return { ...m, witness: P };
    });
    const l = [...p, ...h], w = l.map((m, P) => P).sort(
      (m, P) => l[m].blindedMessage.amount - l[P].blindedMessage.amount
    ), y = [
      ...Array(p.length).fill(!0),
      ...Array(h.length).fill(!1)
    ], g = w.map((m) => l[m]), k = w.map((m) => y[m]);
    return {
      payload: {
        inputs: e,
        outputs: g.map((m) => m.blindedMessage)
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
  async checkProofsStates(t) {
    const e = new TextEncoder(), s = t.map((a) => ct(e.encode(a.secret)).toHex(!0)), r = 100, i = [];
    for (let a = 0; a < s.length; a += r) {
      const o = s.slice(a, a + r), { states: c } = await this.mint.check({
        Ys: o
      }), u = {};
      c.forEach((d) => {
        u[d.Y] = d;
      });
      for (let d = 0; d < o.length; d++) {
        const f = u[o[d]];
        if (!f)
          throw new Error("Could not find state for proof with Y: " + o[d]);
        i.push(f);
      }
    }
    return i;
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
        r.state === B.PAID && e(r);
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
        r.state === G.PAID && e(r);
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
    const r = new TextEncoder(), i = {};
    for (let c = 0; c < t.length; c++) {
      const u = ct(r.encode(t[c].secret)).toHex(!0);
      i[u] = t[c];
    }
    const a = Object.keys(i), o = this.mint.webSocketConnection.createSubscription(
      { kind: "proof_state", filters: a },
      (c) => {
        e({ ...c, proof: i[c.Y] });
      },
      s
    );
    return () => {
      this.mint.webSocketConnection?.cancelSubscription(o, e);
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
  createOutputData(t, e, s, r, i, a, o) {
    let c;
    if (r)
      c = v.createP2PKData({ pubkey: r }, t, e, i);
    else if (s || s === 0) {
      if (!this._seed)
        throw new Error("cannot create deterministic messages without seed");
      c = v.createDeterministicData(
        t,
        this._seed,
        s,
        e,
        i
      );
    } else a ? c = v.createP2PKData(a, t, e, i) : o ? c = S(t, e.keys).map((d) => o(d, e)) : c = v.createRandomData(t, e, i);
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
    let i = Math.ceil(Math.log2(t)) || 1;
    i < 0 && (i = 0);
    const a = i ? Array(i).fill(1) : [];
    return this.createOutputData(
      a.length,
      e,
      s,
      void 0,
      a,
      void 0,
      r
    );
  }
}
class F {
  /**
   * @param _mintUrl requires mint URL to create this object
   * @param _customRequest if passed, use custom request implementation for network communication with the mint
   */
  constructor(t, e) {
    this._mintUrl = t, this._customRequest = e, this._mintUrl = It(t), this._customRequest = e;
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
    const i = r || A, a = {
      "Clear-auth": `${s}`
    }, o = await i({
      endpoint: _(t, "/v1/auth/blind/mint"),
      method: "POST",
      requestBody: e,
      headers: a
    });
    if (!q(o) || !Array.isArray(o?.signatures))
      throw new Error("bad response");
    return o;
  }
  /**
   * Mints new Blinded Authentication tokens by requesting blind signatures on the provided outputs.
   * @param mintPayload Payload containing the outputs to get blind signatures on
   * @param clearAuthToken A NUT-21 clear auth token
   * @returns serialized blinded signatures
   */
  async mint(t, e) {
    return F.mint(this._mintUrl, t, e, this._customRequest);
  }
  /**
   * Get the mints public NUT-22 keys
   * @param mintUrl
   * @param keysetId optional param to get the keys for a specific keyset. If not specified, the keys from all active keysets are fetched
   * @param customRequest
   * @returns
   */
  static async getKeys(t, e, s) {
    const i = await (s || A)({
      endpoint: e ? _(t, "/v1/auth/blind/keys", e) : _(t, "/v1/auth/blind/keys")
    });
    if (!q(i) || !Array.isArray(i.keysets))
      throw new Error("bad response");
    return i;
  }
  /**
   * Get the mints public NUT-22 keys
   * @param keysetId optional param to get the keys for a specific keyset. If not specified, the keys from all active keysets are fetched
   * @returns the mints public keys
   */
  async getKeys(t, e) {
    return await F.getKeys(
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
    return (e || A)({
      endpoint: _(t, "/v1/auth/blind/keysets")
    });
  }
  /**
   * Get the mints NUT-22 keysets in no specific order
   * @returns all the mints past and current keysets.
   */
  async getKeySets() {
    return F.getKeySets(this._mintUrl, this._customRequest);
  }
}
class we {
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
      (r, i) => (r.input_fee_ppk ?? 0) - (i.input_fee_ppk ?? 0)
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
    const r = await this.getKeys(s?.keysetId), i = v.createRandomData(t, r), a = {
      outputs: i.map((u) => u.blindedMessage)
    }, { signatures: o } = await this.mint.mint(a, e), c = i.map((u, d) => u.toProof(o[d], r));
    if (c.some((u) => !qt(u, r)))
      throw new Error("Mint returned auth proofs with invalid DLEQ");
    return c;
  }
}
function ke(n) {
  const t = {
    id: n.id,
    secret: n.secret,
    C: n.C
  }, e = gt(t);
  return "auth" + "A" + e;
}
async function Re(n, t, e) {
  const s = new F(t);
  return (await new we(s).mintProofs(n, e)).map((a) => ke(a));
}
export {
  F as CashuAuthMint,
  we as CashuAuthWallet,
  E as CashuMint,
  Be as CashuWallet,
  Oe as CheckStateEnum,
  R as HttpResponseError,
  B as MeltQuoteState,
  st as MintOperationError,
  G as MintQuoteState,
  et as NetworkError,
  v as OutputData,
  Z as PaymentRequest,
  fe as PaymentRequestTransportType,
  Ue as decodePaymentRequest,
  Te as deriveKeysetId,
  Re as getBlindedAuthToken,
  ie as getDecodedToken,
  xe as getDecodedTokenBinary,
  ke as getEncodedAuthToken,
  Ke as getEncodedToken,
  De as getEncodedTokenBinary,
  re as getEncodedTokenV4,
  qt as hasValidDleq,
  Ne as injectWebSocketImpl,
  Fe as setGlobalRequestOptions
};
//# sourceMappingURL=cashu-ts.es.js.map
