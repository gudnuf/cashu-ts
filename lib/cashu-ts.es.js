import { secp256k1 as L, schnorr as nt } from "@noble/curves/secp256k1";
import { sha256 as R } from "@noble/hashes/sha256";
import { bytesToHex as I, hexToBytes as M } from "@noble/curves/abstract/utils";
import { Buffer as D } from "buffer";
import { hexToBytes as X, bytesToHex as x, randomBytes as mt } from "@noble/hashes/utils";
import { HDKey as Rt } from "@scure/bip32";
function Q(s) {
  return _t(I(s));
}
function _t(s) {
  return BigInt(`0x${s}`);
}
function Ot(s) {
  return D.from(s, "base64");
}
const Ft = M("536563703235366b315f48617368546f43757276655f43617368755f");
function H(s) {
  const t = R(D.concat([Ft, s])), e = new Uint32Array(1), n = 2 ** 16;
  for (let r = 0; r < n; r++) {
    const o = new Uint8Array(e.buffer), c = R(D.concat([t, o]));
    try {
      return B(I(D.concat([new Uint8Array([2]), c])));
    } catch {
      e[0]++;
    }
  }
  throw new Error("No valid point found");
}
function Qt(s) {
  const e = s.map((r) => r.toHex(!1)).join("");
  return R(new TextEncoder().encode(e));
}
function B(s) {
  return L.ProjectivePoint.fromHex(s);
}
const Ct = (s) => {
  let t;
  return /^[a-fA-F0-9]+$/.test(s) ? t = _t(s) % BigInt(2 ** 31 - 1) : t = Q(Ot(s)) % BigInt(2 ** 31 - 1), t;
};
function Lt(s, t) {
  if (s.length !== t.length) return !1;
  for (let e = 0; e < s.length; e++)
    if (s[e] !== t[e]) return !1;
  return !0;
}
const Wt = (s, t, e, n) => {
  const r = L.ProjectivePoint.fromPrivateKey(I(s.s)), o = n.multiply(Q(s.e)), c = t.multiply(Q(s.s)), i = e.multiply(Q(s.e)), a = r.subtract(o), u = c.subtract(i), d = Qt([a, u, n, e]);
  return Lt(d, s.e);
}, $t = (s, t, e, n) => {
  if (t.r === void 0) throw new Error("verifyDLEQProof_reblind: Undefined blinding factor");
  const r = H(s), o = e.add(n.multiply(t.r)), c = L.ProjectivePoint.fromPrivateKey(t.r), i = r.add(c);
  return Wt(t, i, o, n);
};
function jt(s) {
  return D.from(s).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function St(s) {
  return D.from(s, "base64");
}
function Et(s) {
  const t = JSON.stringify(s);
  return Gt(D.from(t).toString("base64"));
}
function Ht(s) {
  const t = D.from(zt(s), "base64").toString();
  return JSON.parse(t);
}
function zt(s) {
  return s.replace(/-/g, "+").replace(/_/g, "/").split("=")[0];
}
function Gt(s) {
  return s.replace(/\+/g, "-").replace(/\//g, "_").split("=")[0];
}
function Vt(s) {
  return typeof s == "number" || typeof s == "string";
}
function st(s) {
  const t = [];
  return rt(s, t), new Uint8Array(t);
}
function rt(s, t) {
  if (s === null)
    t.push(246);
  else if (s === void 0)
    t.push(247);
  else if (typeof s == "boolean")
    t.push(s ? 245 : 244);
  else if (typeof s == "number")
    At(s, t);
  else if (typeof s == "string")
    Pt(s, t);
  else if (Array.isArray(s))
    Yt(s, t);
  else if (s instanceof Uint8Array)
    Jt(s, t);
  else if (typeof s == "object")
    Xt(s, t);
  else
    throw new Error("Unsupported type");
}
function At(s, t) {
  if (s < 24)
    t.push(s);
  else if (s < 256)
    t.push(24, s);
  else if (s < 65536)
    t.push(25, s >> 8, s & 255);
  else if (s < 4294967296)
    t.push(26, s >> 24, s >> 16 & 255, s >> 8 & 255, s & 255);
  else
    throw new Error("Unsupported integer size");
}
function Jt(s, t) {
  const e = s.length;
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
  for (let n = 0; n < s.length; n++)
    t.push(s[n]);
}
function Pt(s, t) {
  const e = new TextEncoder().encode(s), n = e.length;
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
  for (let r = 0; r < e.length; r++)
    t.push(e[r]);
}
function Yt(s, t) {
  const e = s.length;
  if (e < 24)
    t.push(128 | e);
  else if (e < 256)
    t.push(152, e);
  else if (e < 65536)
    t.push(153, e >> 8, e & 255);
  else
    throw new Error("Unsupported array length");
  for (const n of s)
    rt(n, t);
}
function Xt(s, t) {
  const e = Object.keys(s);
  At(e.length, t), t[t.length - 1] |= 160;
  for (const n of e)
    Pt(n, t), rt(s[n], t);
}
function ot(s) {
  const t = new DataView(s.buffer, s.byteOffset, s.byteLength);
  return z(t, 0).value;
}
function z(s, t) {
  if (t >= s.byteLength)
    throw new Error("Unexpected end of data");
  const e = s.getUint8(t++), n = e >> 5, r = e & 31;
  switch (n) {
    case 0:
      return Zt(s, t, r);
    case 1:
      return te(s, t, r);
    case 2:
      return ee(s, t, r);
    case 3:
      return ne(s, t, r);
    case 4:
      return se(s, t, r);
    case 5:
      return re(s, t, r);
    case 7:
      return ie(s, t, r);
    default:
      throw new Error(`Unsupported major type: ${n}`);
  }
}
function O(s, t, e) {
  if (e < 24) return { value: e, offset: t };
  if (e === 24) return { value: s.getUint8(t++), offset: t };
  if (e === 25) {
    const n = s.getUint16(t, !1);
    return t += 2, { value: n, offset: t };
  }
  if (e === 26) {
    const n = s.getUint32(t, !1);
    return t += 4, { value: n, offset: t };
  }
  if (e === 27) {
    const n = s.getUint32(t, !1), r = s.getUint32(t + 4, !1);
    return t += 8, { value: n * 2 ** 32 + r, offset: t };
  }
  throw new Error(`Unsupported length: ${e}`);
}
function Zt(s, t, e) {
  const { value: n, offset: r } = O(s, t, e);
  return { value: n, offset: r };
}
function te(s, t, e) {
  const { value: n, offset: r } = O(s, t, e);
  return { value: -1 - n, offset: r };
}
function ee(s, t, e) {
  const { value: n, offset: r } = O(s, t, e);
  if (r + n > s.byteLength)
    throw new Error("Byte string length exceeds data length");
  return { value: new Uint8Array(s.buffer, s.byteOffset + r, n), offset: r + n };
}
function ne(s, t, e) {
  const { value: n, offset: r } = O(s, t, e);
  if (r + n > s.byteLength)
    throw new Error("String length exceeds data length");
  const o = new Uint8Array(s.buffer, s.byteOffset + r, n);
  return { value: new TextDecoder().decode(o), offset: r + n };
}
function se(s, t, e) {
  const { value: n, offset: r } = O(s, t, e), o = [];
  let c = r;
  for (let i = 0; i < n; i++) {
    const a = z(s, c);
    o.push(a.value), c = a.offset;
  }
  return { value: o, offset: c };
}
function re(s, t, e) {
  const { value: n, offset: r } = O(s, t, e), o = {};
  let c = r;
  for (let i = 0; i < n; i++) {
    const a = z(s, c);
    if (!Vt(a.value))
      throw new Error("Invalid key type");
    const u = z(s, a.offset);
    o[a.value] = u.value, c = u.offset;
  }
  return { value: o, offset: c };
}
function oe(s) {
  const t = (s & 31744) >> 10, e = s & 1023, n = s & 32768 ? -1 : 1;
  return t === 0 ? n * 2 ** -14 * (e / 1024) : t === 31 ? e ? NaN : n * (1 / 0) : n * 2 ** (t - 15) * (1 + e / 1024);
}
function ie(s, t, e) {
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
  if (e === 24) return { value: s.getUint8(t++), offset: t };
  if (e === 25) {
    const n = oe(s.getUint16(t, !1));
    return t += 2, { value: n, offset: t };
  }
  if (e === 26) {
    const n = s.getFloat32(t, !1);
    return t += 4, { value: n, offset: t };
  }
  if (e === 27) {
    const n = s.getFloat64(t, !1);
    return t += 8, { value: n, offset: t };
  }
  throw new Error(`Unknown simple or float value: ${e}`);
}
class it {
  constructor(t, e, n, r, o, c, i = !1, a) {
    this.transport = t, this.id = e, this.amount = n, this.unit = r, this.mints = o, this.description = c, this.singleUse = i, this.nut10 = a;
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
    const t = this.toRawRequest(), e = st(t);
    return "creqA" + D.from(e).toString("base64");
  }
  getTransport(t) {
    return this.transport?.find((e) => e.type === t);
  }
  static fromRawRequest(t) {
    const e = t.t ? t.t.map((r) => ({
      type: r.t,
      target: r.a,
      tags: r.g
    })) : void 0, n = t.nut10 ? {
      kind: t.nut10.k,
      data: t.nut10.d,
      tags: t.nut10.t
    } : void 0;
    return new it(
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
    const n = t.slice(5), r = St(n), o = ot(r);
    return this.fromRawRequest(o);
  }
}
const ce = "A", ae = "cashu";
function P(s, t, e, n) {
  if (e) {
    const o = wt(e);
    if (o > s)
      throw new Error(`Split is greater than total amount: ${o} > ${s}`);
    if (e.some((c) => !It(c, t)))
      throw new Error("Provided amount preferences do not match the amounts of the mint keyset.");
    s = s - wt(e);
  } else
    e = [];
  return vt(t, "desc").forEach((o) => {
    const c = Math.floor(s / o);
    for (let i = 0; i < c; ++i) e?.push(o);
    s %= o;
  }), e.sort((o, c) => o - c);
}
function yt(s, t, e, n) {
  const r = [], o = s.map((u) => u.amount);
  vt(e, "asc").forEach((u) => {
    const d = o.filter((m) => m === u).length, f = Math.max(n - d, 0);
    for (let m = 0; m < f && !(r.reduce((h, l) => h + l, 0) + u > t); ++m)
      r.push(u);
  });
  const i = t - r.reduce((u, d) => u + d, 0);
  return i && P(i, e).forEach((d) => {
    r.push(d);
  }), r.sort((u, d) => u - d);
}
function vt(s, t = "desc") {
  return t == "desc" ? Object.keys(s).map((e) => parseInt(e)).sort((e, n) => n - e) : Object.keys(s).map((e) => parseInt(e)).sort((e, n) => e - n);
}
function It(s, t) {
  return s in t;
}
function ue(s) {
  return Tt(I(s));
}
function Tt(s) {
  return BigInt(`0x${s}`);
}
function he(s) {
  return s.toString(16).padStart(64, "0");
}
function gt(s) {
  return /^[a-f0-9]*$/i.test(s);
}
function Mt(s) {
  return Array.isArray(s) ? s.some((t) => !gt(t.id)) : gt(s.id);
}
function de(s) {
  const t = { token: [{ mint: s.mint, proofs: s.proofs }] };
  return s.unit && (t.unit = s.unit), s.memo && (t.memo = s.memo), ae + ce + Et(t);
}
function $e(s, t) {
  if (Mt(s.proofs) || t?.version === 3) {
    if (t?.version === 4)
      throw new Error("can not encode to v4 token if proofs contain non-hex keyset id");
    return de(s);
  }
  return le(s);
}
function le(s) {
  if (s.proofs.forEach((i) => {
    if (i.dleq && i.dleq.r == null)
      throw new Error("Missing blinding factor in included DLEQ proof");
  }), Mt(s.proofs))
    throw new Error("can not encode to v4 token if proofs contain non-hex keyset id");
  const e = Kt(s), n = st(e), r = "cashu", o = "B", c = jt(n);
  return r + o + c;
}
function Kt(s) {
  const t = {}, e = s.mint;
  for (let r = 0; r < s.proofs.length; r++) {
    const o = s.proofs[r];
    t[o.id] ? t[o.id].push(o) : t[o.id] = [o];
  }
  const n = {
    m: e,
    u: s.unit || "sat",
    t: Object.keys(t).map(
      (r) => ({
        i: M(r),
        p: t[r].map(
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
            },
            ...o.witness && {
              w: JSON.stringify(o.witness)
            }
          })
        )
      })
    )
  };
  return s.memo && (n.d = s.memo), n;
}
function Dt(s) {
  const t = [];
  s.t.forEach(
    (n) => n.p.forEach((r) => {
      t.push({
        secret: r.s,
        C: I(r.c),
        amount: r.a,
        id: I(n.i),
        ...r.d && {
          dleq: {
            r: I(r.d.r),
            s: I(r.d.s),
            e: I(r.d.e)
          }
        },
        ...r.w && {
          witness: r.w
        }
      });
    })
  );
  const e = { mint: s.m, proofs: t, unit: s.u || "sat" };
  return s.d && (e.memo = s.d), e;
}
function fe(s) {
  return ["web+cashu://", "cashu://", "cashu:", "cashu"].forEach((e) => {
    s.startsWith(e) && (s = s.slice(e.length));
  }), pe(s);
}
function pe(s) {
  const t = s.slice(0, 1), e = s.slice(1);
  if (t === "A") {
    const n = Ht(e);
    if (n.token.length > 1)
      throw new Error("Multi entry token are not supported");
    const r = n.token[0], o = {
      mint: r.mint,
      proofs: r.proofs,
      unit: n.unit || "sat"
    };
    return n.memo && (o.memo = n.memo), o;
  } else if (t === "B") {
    const n = St(e), r = ot(n);
    return Dt(r);
  }
  throw new Error("Token version is not supported");
}
function je(s) {
  const t = Object.entries(s).sort((r, o) => +r[0] - +o[0]).map(([, r]) => M(r)).reduce((r, o) => me(r, o), new Uint8Array()), e = R(t);
  return "00" + Buffer.from(e).toString("hex").slice(0, 14);
}
function me(s, t) {
  const e = new Uint8Array(s.length + t.length);
  return e.set(s), e.set(t, s.length), e;
}
function T(s) {
  return typeof s == "object";
}
function b(...s) {
  return s.map((t) => t.replace(/(^\/+|\/+$)/g, "")).join("/");
}
function qt(s) {
  return s.replace(/\/$/, "");
}
function U(s) {
  return s.reduce((t, e) => t + e.amount, 0);
}
function He(s) {
  return it.fromEncodedRequest(s);
}
class ye {
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
class ge {
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
    const e = new ye(t);
    return this._size === 0 || !this._last ? (this._first = e, this._last = e) : (this._last.next = e, this._last = e), this._size++, !0;
  }
  dequeue() {
    if (this._size === 0 || !this._first) return null;
    const t = this._first;
    return this._first = t.next, t.next = null, this._size--, t.value;
  }
}
function j(s) {
  return s.map((t) => {
    const e = { ...t };
    return delete e.dleq, e;
  });
}
function Ut(s, t) {
  if (s.dleq == null)
    return !1;
  const e = {
    e: M(s.dleq.e),
    s: M(s.dleq.s),
    r: Tt(s.dleq.r ?? "00")
  };
  if (!It(s.amount, t.keys))
    throw new Error(`undefined key for amount ${s.amount}`);
  const n = t.keys[s.amount];
  return !!$t(
    new TextEncoder().encode(s.secret),
    e,
    B(s.C),
    B(n)
  );
}
function we(...s) {
  const t = s.reduce((r, o) => r + o.length, 0), e = new Uint8Array(t);
  let n = 0;
  for (let r = 0; r < s.length; r++)
    e.set(s[r], n), n = n + s[r].length;
  return e;
}
function ze(s) {
  const t = new TextEncoder(), e = Kt(s), n = st(e), r = t.encode("craw"), o = t.encode("B");
  return we(r, o, n);
}
function Ge(s) {
  const t = new TextDecoder(), e = t.decode(s.slice(0, 4)), n = t.decode(new Uint8Array([s[4]]));
  if (e !== "craw" || n !== "B")
    throw new Error("not a valid binary token");
  const r = s.slice(5), o = ot(r);
  return Dt(o);
}
function wt(s) {
  return s.reduce((t, e) => t + e, 0);
}
let ct;
typeof WebSocket < "u" && (ct = WebSocket);
function Ve(s) {
  ct = s;
}
function ke() {
  return ct;
}
class N {
  constructor() {
    this.connectionMap = /* @__PURE__ */ new Map();
  }
  static getInstance() {
    return N.instace || (N.instace = new N()), N.instace;
  }
  getConnection(t) {
    if (this.connectionMap.has(t))
      return this.connectionMap.get(t);
    const e = new be(t);
    return this.connectionMap.set(t, e), e;
  }
}
class be {
  constructor(t) {
    this.subListeners = {}, this.rpcListeners = {}, this.rpcId = 0, this.manuallyClosing = !1, this.reconnectAttempts = 0, this.maxReconnectAttempts = 5, this.reconnectDelay = 1e3, this.maxReconnectDelay = 3e4, this.storedSubscriptions = /* @__PURE__ */ new Map(), this.subscriptionCallbacks = {}, this._WS = ke(), this.url = new URL(t), this.messageQueue = new ge();
  }
  connect() {
    return this.connectionPromise || (this.connectionPromise = new Promise((t, e) => {
      try {
        this.ws = new this._WS(this.url.toString());
      } catch (n) {
        e(n);
        return;
      }
      this.ws.onopen = () => {
        this.reconnectAttempts = 0, this.resubscribeAll(), t();
      }, this.ws.onerror = () => {
        e(new Error("Failed to open WebSocket"));
      }, this.ws.onmessage = (n) => {
        this.messageQueue.enqueue(n.data), this.handlingInterval || (this.handlingInterval = setInterval(
          this.handleNextMesage.bind(this),
          0
        ));
      }, this.ws.onclose = (n) => {
        this.connectionPromise = void 0, this.clearMessageHandling(), this.manuallyClosing || this.scheduleReconnect();
      };
    })), this.connectionPromise;
  }
  clearMessageHandling() {
    this.handlingInterval && (clearInterval(this.handlingInterval), this.handlingInterval = void 0);
  }
  scheduleReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error(
        `WSConnection: Max reconnection attempts (${this.maxReconnectAttempts}) reached for ${this.url}`
      );
      return;
    }
    const t = Math.min(
      this.reconnectDelay * Math.pow(2, this.reconnectAttempts),
      this.maxReconnectDelay
    );
    this.reconnectTimeout = setTimeout(() => {
      this.reconnectAttempts++, console.log(
        `cashu-ts WSConnection: Attempting reconnection ${this.reconnectAttempts}/${this.maxReconnectAttempts} to ${this.url}`
      ), this.connect().catch((e) => {
        console.error("WSConnection: Reconnection failed:", e);
      });
    }, t);
  }
  resubscribeAll() {
    for (const [t, e] of this.storedSubscriptions)
      try {
        this.addRpcListener(
          () => {
            this.addSubListener(t, e.callback);
          },
          (n) => {
            console.error("WSConnection: Failed to resubscribe:", n), e.errorCallback(new Error(n.message)), this.storedSubscriptions.delete(t);
          },
          this.rpcId
        ), this.sendRequest("subscribe", e.params), this.rpcId++;
      } catch (n) {
        console.error("WSConnection: Failed to resubscribe:", n), e.errorCallback(new Error("Failed to resubscribe after reconnection")), this.storedSubscriptions.delete(t);
      }
  }
  sendRequest(t, e) {
    if (this.ws?.readyState !== 1)
      throw new Error("Socket not open...");
    const n = this.rpcId;
    this.rpcId++;
    const r = JSON.stringify({ jsonrpc: "2.0", method: t, params: e, id: n });
    this.ws?.send(r);
  }
  closeSubscription(t) {
    this.ws?.send(JSON.stringify(["CLOSE", t]));
  }
  addSubListener(t, e) {
    (this.subListeners[t] = this.subListeners[t] || []).push(e);
  }
  //TODO: Move to RPCManagerClass
  addRpcListener(t, e, n) {
    this.rpcListeners[n] = { callback: t, errorCallback: e };
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
      this.subListeners[t] = this.subListeners[t].filter((n) => n !== e);
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
        const n = e.params.subId;
        if (!n)
          return;
        if (this.subListeners[n]?.length > 0) {
          const r = e;
          this.subListeners[n].forEach((o) => o(r.params.payload));
        }
      }
    } catch (n) {
      console.error(n);
      return;
    }
  }
  createSubscription(t, e, n) {
    if (this.ws?.readyState !== 1)
      return n(new Error("Socket is not open"));
    const r = (Math.random() + 1).toString(36).substring(7);
    return this.storedSubscriptions.set(r, {
      params: { ...t, subId: r },
      callback: e,
      errorCallback: n,
      originalSubId: r
    }), this.addRpcListener(
      () => {
        this.addSubListener(r, e);
      },
      (o) => {
        this.storedSubscriptions.delete(r), n(new Error(o.message));
      },
      this.rpcId
    ), this.sendRequest("subscribe", { ...t, subId: r }), this.rpcId++, r;
  }
  cancelSubscription(t, e) {
    this.storedSubscriptions.delete(t), this.removeRpcListener(t), this.removeListener(t, e), this.rpcId++, this.sendRequest("unsubscribe", { subId: t });
  }
  get activeSubscriptions() {
    return Object.keys(this.subListeners);
  }
  close() {
    this.manuallyClosing = !0, this.reconnectTimeout && (clearTimeout(this.reconnectTimeout), this.reconnectTimeout = void 0), this.storedSubscriptions.clear(), this.ws && this.ws?.close();
  }
  // Method to check if connection is attempting to reconnect
  get isReconnecting() {
    return this.reconnectTimeout !== void 0;
  }
  // Method to get current reconnection attempt count
  get currentReconnectAttempts() {
    return this.reconnectAttempts;
  }
  // Method to manually trigger reconnection (useful for testing or manual recovery)
  reconnect() {
    if (this.manuallyClosing)
      throw new Error("Cannot reconnect: connection was manually closed");
    return this.reconnectAttempts = 0, this.reconnectTimeout && (clearTimeout(this.reconnectTimeout), this.reconnectTimeout = void 0), this.ws && this.ws.readyState !== WebSocket.CLOSED && this.ws.close(), this.connectionPromise = void 0, this.connect();
  }
}
const Je = {
  UNSPENT: "UNSPENT",
  PENDING: "PENDING",
  SPENT: "SPENT"
}, W = {
  UNPAID: "UNPAID",
  PENDING: "PENDING",
  PAID: "PAID"
}, Z = {
  UNPAID: "UNPAID",
  PAID: "PAID",
  ISSUED: "ISSUED"
};
var _e = /* @__PURE__ */ ((s) => (s.POST = "post", s.NOSTR = "nostr", s))(_e || {});
class $ extends Error {
  constructor(t, e) {
    super(t), this.status = e, this.name = "HttpResponseError", Object.setPrototypeOf(this, $.prototype);
  }
}
class at extends Error {
  constructor(t) {
    super(t), this.name = "NetworkError", Object.setPrototypeOf(this, at.prototype);
  }
}
class ut extends $ {
  constructor(t, e) {
    super(e || "Unknown mint operation error", 400), this.code = t, this.name = "MintOperationError", Object.setPrototypeOf(this, ut.prototype);
  }
}
let Bt = {};
function Ye(s) {
  Bt = s;
}
async function Se({
  endpoint: s,
  requestBody: t,
  headers: e,
  ...n
}) {
  const r = t ? JSON.stringify(t) : void 0, o = {
    Accept: "application/json, text/plain, */*",
    ...r ? { "Content-Type": "application/json" } : void 0,
    ...e
  };
  let c;
  try {
    c = await fetch(s, { body: r, headers: o, ...n });
  } catch (i) {
    throw new at(i instanceof Error ? i.message : "Network request failed");
  }
  if (!c.ok) {
    const i = await c.json().catch(() => ({ error: "bad response" }));
    throw c.status === 400 && "code" in i && "detail" in i ? new ut(i.code, i.detail) : new $(
      "error" in i ? i.error : i.detail || "HTTP request failed",
      c.status
    );
  }
  try {
    return await c.json();
  } catch (i) {
    throw console.error("Failed to parse HTTP response", i), new $("bad response", c.status);
  }
}
async function S(s) {
  return await Se({ ...s, ...Bt });
}
function G(s) {
  return s.state || (console.warn(
    "Field 'state' not found in MeltQuoteResponse. Update NUT-05 of mint: https://github.com/cashubtc/nuts/pull/136)"
  ), typeof s.paid == "boolean" && (s.state = s.paid ? W.PAID : W.UNPAID)), s;
}
function kt(s) {
  return s.state || (console.warn(
    "Field 'state' not found in MintQuoteResponse. Update NUT-04 of mint: https://github.com/cashubtc/nuts/pull/141)"
  ), typeof s.paid == "boolean" && (s.state = s.paid ? Z.PAID : Z.UNPAID)), s;
}
function Ee(s) {
  return Array.isArray(s?.contact) && s?.contact.length > 0 && (s.contact = s.contact.map((t) => Array.isArray(t) && t.length === 2 && typeof t[0] == "string" && typeof t[1] == "string" ? (console.warn(
    "Mint returned deprecated 'contact' field: Update NUT-06: https://github.com/cashubtc/nuts/pull/117"
  ), { method: t[0], info: t[1] }) : t)), s;
}
class tt {
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
}
class E {
  /**
   * @param _mintUrl requires mint URL to create this object
   * @param _customRequest if passed, use custom request implementation for network communication with the mint
   * @param [authTokenGetter] a function that is called by the CashuMint instance to obtain a NUT-22 BlindedAuthToken (e.g. from a database or localstorage)
   */
  constructor(t, e, n) {
    this._mintUrl = t, this._customRequest = e, this._checkNut22 = !1, this._mintUrl = qt(t), this._customRequest = e, n && (this._checkNut22 = !0, this._authTokenGetter = n);
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
    const r = await (e || S)({
      endpoint: b(t, "/v1/info")
    });
    return Ee(r);
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
    return this._mintInfo = new tt(t), this._mintInfo;
  }
  /**
   * Performs a swap operation with ecash inputs and outputs.
   * @param mintUrl
   * @param swapPayload payload containing inputs and outputs
   * @param customRequest
   * @returns signed outputs
   */
  static async swap(t, e, n, r) {
    const o = n || S, c = r ? { "Blind-auth": r } : {}, i = await o({
      endpoint: b(t, "/v1/swap"),
      method: "POST",
      requestBody: e,
      headers: c
    });
    if (!T(i) || !Array.isArray(i?.signatures))
      throw new Error(i.detail ?? "bad response");
    return i;
  }
  /**
   * Performs a swap operation with ecash inputs and outputs.
   * @param swapPayload payload containing inputs and outputs
   * @returns signed outputs
   */
  async swap(t) {
    const e = await this.handleBlindAuth("/v1/swap");
    return E.swap(this._mintUrl, t, this._customRequest, e);
  }
  /**
   * Requests a new mint quote from the mint.
   * @param mintUrl
   * @param mintQuotePayload Payload for creating a new mint quote
   * @param customRequest
   * @returns the mint will create and return a new mint quote containing a payment request for the specified amount and unit
   */
  static async createMintQuote(t, e, n, r) {
    const o = n || S, c = r ? { "Blind-auth": r } : {}, i = await o({
      endpoint: b(t, "/v1/mint/quote/bolt11"),
      method: "POST",
      requestBody: e,
      headers: c
    });
    return kt(i);
  }
  /**
   * Requests a new mint quote from the mint.
   * @param mintQuotePayload Payload for creating a new mint quote
   * @returns the mint will create and return a new mint quote containing a payment request for the specified amount and unit
   */
  async createMintQuote(t) {
    const e = await this.handleBlindAuth("/v1/mint/quote/bolt11");
    return E.createMintQuote(
      this._mintUrl,
      t,
      this._customRequest,
      e
    );
  }
  /**
   * Gets an existing mint quote from the mint.
   * @param mintUrl
   * @param quote Quote ID
   * @param customRequest
   * @returns the mint will create and return a Lightning invoice for the specified amount
   */
  static async checkMintQuote(t, e, n, r) {
    const o = n || S, c = r ? { "Blind-auth": r } : {}, i = await o({
      endpoint: b(t, "/v1/mint/quote/bolt11", e),
      method: "GET",
      headers: c
    });
    return kt(i);
  }
  /**
   * Gets an existing mint quote from the mint.
   * @param quote Quote ID
   * @returns the mint will create and return a Lightning invoice for the specified amount
   */
  async checkMintQuote(t) {
    const e = await this.handleBlindAuth(`/v1/mint/quote/bolt11/${t}`);
    return E.checkMintQuote(this._mintUrl, t, this._customRequest, e);
  }
  /**
   * Mints new tokens by requesting blind signatures on the provided outputs.
   * @param mintUrl
   * @param mintPayload Payload containing the outputs to get blind signatures on
   * @param customRequest
   * @returns serialized blinded signatures
   */
  static async mint(t, e, n, r) {
    const o = n || S, c = r ? { "Blind-auth": r } : {}, i = await o({
      endpoint: b(t, "/v1/mint/bolt11"),
      method: "POST",
      requestBody: e,
      headers: c
    });
    if (!T(i) || !Array.isArray(i?.signatures))
      throw new Error("bad response");
    return i;
  }
  /**
   * Mints new tokens by requesting blind signatures on the provided outputs.
   * @param mintPayload Payload containing the outputs to get blind signatures on
   * @returns serialized blinded signatures
   */
  async mint(t) {
    const e = await this.handleBlindAuth("/v1/mint/bolt11");
    return E.mint(this._mintUrl, t, this._customRequest, e);
  }
  /**
   * Requests a new melt quote from the mint.
   * @param mintUrl
   * @param MeltQuotePayload
   * @returns
   */
  static async createMeltQuote(t, e, n, r) {
    const o = n || S, c = r ? { "Blind-auth": r } : {}, i = await o({
      endpoint: b(t, "/v1/melt/quote/bolt11"),
      method: "POST",
      requestBody: e,
      headers: c
    }), a = G(i);
    if (!T(a) || typeof a?.amount != "number" || typeof a?.fee_reserve != "number" || typeof a?.quote != "string")
      throw new Error("bad response");
    return a;
  }
  /**
   * Requests a new melt quote from the mint.
   * @param MeltQuotePayload
   * @returns
   */
  async createMeltQuote(t) {
    const e = await this.handleBlindAuth("/v1/melt/quote/bolt11");
    return E.createMeltQuote(
      this._mintUrl,
      t,
      this._customRequest,
      e
    );
  }
  /**
   * Gets an existing melt quote.
   * @param mintUrl
   * @param quote Quote ID
   * @returns
   */
  static async checkMeltQuote(t, e, n, r) {
    const o = n || S, c = r ? { "Blind-auth": r } : {}, i = await o({
      endpoint: b(t, "/v1/melt/quote/bolt11", e),
      method: "GET",
      headers: c
    }), a = G(i);
    if (!T(a) || typeof a?.amount != "number" || typeof a?.fee_reserve != "number" || typeof a?.quote != "string" || typeof a?.state != "string" || !Object.values(W).includes(a.state))
      throw new Error("bad response");
    return a;
  }
  /**
   * Gets an existing melt quote.
   * @param quote Quote ID
   * @returns
   */
  async checkMeltQuote(t) {
    const e = await this.handleBlindAuth(`/v1/melt/quote/bolt11/${t}`);
    return E.checkMeltQuote(this._mintUrl, t, this._customRequest, e);
  }
  /**
   * Requests the mint to pay for a Bolt11 payment request by providing ecash as inputs to be spent. The inputs contain the amount and the fee_reserves for a Lightning payment. The payload can also contain blank outputs in order to receive back overpaid Lightning fees.
   * @param mintUrl
   * @param meltPayload
   * @param customRequest
   * @returns
   */
  static async melt(t, e, n, r) {
    const o = n || S, c = r ? { "Blind-auth": r } : {}, i = await o({
      endpoint: b(t, "/v1/melt/bolt11"),
      method: "POST",
      requestBody: e,
      headers: c
    }), a = G(i);
    if (!T(a) || typeof a?.state != "string" || !Object.values(W).includes(a.state))
      throw new Error("bad response");
    return a;
  }
  /**
   * Ask mint to perform a melt operation. This pays a lightning invoice and destroys tokens matching its amount + fees
   * @param meltPayload
   * @returns
   */
  async melt(t) {
    const e = await this.handleBlindAuth("/v1/melt/bolt11");
    return E.melt(this._mintUrl, t, this._customRequest, e);
  }
  /**
   * Checks if specific proofs have already been redeemed
   * @param mintUrl
   * @param checkPayload
   * @param customRequest
   * @returns redeemed and unredeemed ordered list of booleans
   */
  static async check(t, e, n) {
    const o = await (n || S)({
      endpoint: b(t, "/v1/checkstate"),
      method: "POST",
      requestBody: e
    });
    if (!T(o) || !Array.isArray(o?.states))
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
  static async getKeys(t, e, n) {
    e && (e = e.replace(/\//g, "_").replace(/\+/g, "-"));
    const o = await (n || S)({
      endpoint: e ? b(t, "/v1/keys", e) : b(t, "/v1/keys")
    });
    if (!T(o) || !Array.isArray(o.keysets))
      throw new Error("bad response");
    return o;
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
    return (e || S)({ endpoint: b(t, "/v1/keysets") });
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
    return E.check(this._mintUrl, t, this._customRequest);
  }
  static async restore(t, e, n) {
    const o = await (n || S)({
      endpoint: b(t, "/v1/restore"),
      method: "POST",
      requestBody: e
    });
    if (!T(o) || !Array.isArray(o?.outputs) || !Array.isArray(o?.signatures))
      throw new Error("bad response");
    return o;
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
      t.pathname && (t.pathname.endsWith("/") ? t.pathname += e : t.pathname += "/" + e), this.ws = N.getInstance().getConnection(
        `${t.protocol === "https:" ? "wss" : "ws"}://${t.host}${t.pathname}`
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
const Ae = (s) => {
  try {
    return s instanceof Uint8Array && (s = new TextDecoder().decode(s)), JSON.parse(s);
  } catch {
    throw new Error("can't parse secret");
  }
}, Pe = (s, t) => {
  const e = R(new TextDecoder().decode(s));
  return nt.sign(e, t);
}, bt = (s, t) => {
  let e = [], n = "";
  if (t instanceof Array)
    for (const r of t)
      e.push({ priv: r, pub: I(nt.getPublicKey(r)) });
  else
    n = t;
  return s.map((r) => {
    try {
      const o = Ae(r.secret);
      if (o[0] !== "P2PK")
        throw new Error("unknown secret type");
      if (e.length) {
        const c = e.find((i) => o[1].data === i.pub)?.priv;
        if (c)
          n = c;
        else
          throw new Error("no matching key found");
      }
      return ve(r, M(n));
    } catch {
      return r;
    }
  });
}, ve = (s, t) => (s.witness || (s.witness = {
  signatures: [I(Pe(s.secret, t))]
}), s);
function V(s, t, e) {
  const n = H(s);
  t || (t = Q(L.utils.randomPrivateKey()));
  const r = L.ProjectivePoint.BASE.multiply(t);
  return { B_: n.add(r), r: t, secret: s };
}
function Ie(s, t, e) {
  return s.subtract(e.multiply(t));
}
function Te(s, t, e, n) {
  const r = n, o = Ie(s.C_, t, r);
  return {
    id: s.id,
    amount: s.amount,
    secret: e,
    C: o
  };
}
const et = (s) => ({
  amount: s.amount,
  C: s.C.toHex(!0),
  id: s.id,
  secret: new TextDecoder().decode(s.secret),
  witness: JSON.stringify(s.witness)
});
function Me(s, t) {
  let e = s;
  for (const r of t)
    e += r.B_;
  const n = new TextEncoder().encode(e);
  return R(n);
}
function Ke(s, t, e) {
  const n = Me(t, e), r = X(s), o = nt.sign(n, r);
  return x(o);
}
class J {
  constructor(t, e, n) {
    this.amount = t, this.B_ = e, this.id = n;
  }
  getSerializedBlindedMessage() {
    return { amount: this.amount, B_: this.B_.toHex(!0), id: this.id };
  }
}
const De = "m/129372'/0'", qe = (s, t, e) => xt(
  s,
  t,
  e,
  0
  /* SECRET */
), Ue = (s, t, e) => xt(
  s,
  t,
  e,
  1
  /* BLINDING_FACTOR */
), xt = (s, t, e, n) => {
  const r = Rt.fromMasterSeed(s), o = Ct(t), c = `${De}/${o}'/${e}'/${n}`, i = r.derive(c);
  if (i.privateKey === null)
    throw new Error("Could not derive private key");
  return i.privateKey;
};
function Y(s) {
  return typeof s == "function";
}
class K {
  constructor(t, e, n) {
    this.secret = n, this.blindingFactor = e, this.blindedMessage = t;
  }
  toProof(t, e) {
    let n;
    t.dleq && (n = {
      s: X(t.dleq.s),
      e: X(t.dleq.e),
      r: this.blindingFactor
    });
    const r = {
      id: t.id,
      amount: t.amount,
      C_: B(t.C_),
      dleq: n
    }, o = B(e.keys[t.amount]), c = Te(r, this.blindingFactor, this.secret, o);
    return {
      ...et(c),
      ...n && {
        dleq: {
          s: x(n.s),
          e: x(n.e),
          r: he(n.r ?? BigInt(0))
        }
      }
    };
  }
  static createP2PKData(t, e, n, r) {
    return P(e, n.keys, r).map((c) => this.createSingleP2PKData(t, c, n.id));
  }
  static createSingleP2PKData(t, e, n) {
    const r = [
      "P2PK",
      {
        nonce: x(mt(32)),
        data: t.pubkey,
        tags: []
      }
    ];
    t.locktime && r[1].tags.push(["locktime", t.locktime]), t.refundKeys && r[1].tags.push(["refund", ...t.refundKeys]);
    const o = JSON.stringify(r), c = new TextEncoder().encode(o), { r: i, B_: a } = V(c);
    return new K(
      new J(e, a, n).getSerializedBlindedMessage(),
      i,
      c
    );
  }
  static createRandomData(t, e, n) {
    return P(t, e.keys, n).map((o) => this.createSingleRandomData(o, e.id));
  }
  static createSingleRandomData(t, e) {
    const n = x(mt(32)), r = new TextEncoder().encode(n), { r: o, B_: c } = V(r);
    return new K(
      new J(t, c, e).getSerializedBlindedMessage(),
      o,
      r
    );
  }
  static createDeterministicData(t, e, n, r, o) {
    return P(t, r.keys, o).map(
      (i, a) => this.createSingleDeterministicData(i, e, n + a, r.id)
    );
  }
  static createSingleDeterministicData(t, e, n, r) {
    const o = qe(e, r, n), c = x(o), i = new TextEncoder().encode(c), a = ue(Ue(e, r, n)), { r: u, B_: d } = V(i, a);
    return new K(
      new J(t, d, r).getSerializedBlindedMessage(),
      u,
      i
    );
  }
}
const Be = 3, xe = "sat";
class Xe {
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
    this._keys = /* @__PURE__ */ new Map(), this._keysets = [], this._seed = void 0, this._unit = xe, this._mintInfo = void 0, this._denominationTarget = Be, this.mint = t;
    let n = [];
    if (e?.keys && !Array.isArray(e.keys) ? n = [e.keys] : e?.keys && Array.isArray(e?.keys) && (n = e?.keys), n && n.forEach((r) => this._keys.set(r.id, r)), e?.unit && (this._unit = e?.unit), e?.keysets && (this._keysets = e.keysets), e?.mintInfo && (this._mintInfo = new tt(e.mintInfo)), e?.denominationTarget && (this._denominationTarget = e.denominationTarget), e?.bip39seed) {
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
    return this._mintInfo = new tt(t), this._mintInfo;
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
    let e = t.filter((r) => r.active);
    e = e.filter((r) => r.id.startsWith("00"));
    const n = e.sort(
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
    const e = (await this.mint.getKeySets()).keysets.filter((n) => n.unit === this._unit);
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
    if ((!(this._keysets.length > 0) || e) && await this.getKeySets(), t || (t = this.getActiveKeyset(this._keysets).id), !this._keysets.find((n) => n.id === t) && (await this.getKeySets(), !this._keysets.find((n) => n.id === t)))
      throw new Error(`could not initialize keys. No keyset with id '${t}' found`);
    if (!this._keys.get(t)) {
      const n = await this.mint.getKeys(t);
      this._keys.set(t, n.keysets[0]);
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
    const { requireDleq: n, keysetId: r, outputAmounts: o, counter: c, pubkey: i, privkey: a, outputData: u, p2pk: d } = e || {};
    typeof t == "string" && (t = fe(t));
    const f = await this.getKeys(r);
    if (n && t.proofs.some((k) => !Ut(k, f)))
      throw new Error("Token contains proofs with invalid DLEQ");
    const m = U(t.proofs) - this.getFeesForProofs(t.proofs);
    let h;
    u ? h = { send: u } : this._keepFactory && (h = { send: this._keepFactory });
    const l = this.createSwapPayload(
      m,
      t.proofs,
      f,
      o,
      c,
      i,
      a,
      h,
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
  async send(t, e, n) {
    const {
      proofsWeHave: r,
      offline: o,
      includeFees: c,
      includeDleq: i,
      keysetId: a,
      outputAmounts: u,
      pubkey: d,
      privkey: f,
      outputData: m
    } = n || {};
    if (i && (e = e.filter((y) => y.dleq != null)), U(e) < t)
      throw new Error("Not enough funds available to send");
    const { keep: h, send: l } = this.selectProofsToSend(
      e,
      t,
      n?.includeFees
    ), w = c ? this.getFeesForProofs(l) : 0;
    if (!o && (U(l) != t + w || // if the exact amount cannot be selected
    u || d || f || a || m)) {
      const { keep: y, send: g } = this.selectProofsToSend(
        e,
        t,
        !0
      );
      r?.push(...y);
      const k = await this.swap(t, g, n);
      let { keep: p, send: A } = k;
      const q = k.serialized;
      return p = y.concat(p), i || (A = j(A)), { keep: p, send: A, serialized: q };
    }
    if (U(l) < t + w)
      throw new Error("Not enough funds available to send");
    return i ? { keep: h, send: l } : { keep: h, send: j(l) };
  }
  selectProofsToSend(t, e, n) {
    const r = t.sort((h, l) => h.amount - l.amount), o = r.filter((h) => h.amount <= e).sort((h, l) => l.amount - h.amount), i = r.filter((h) => h.amount > e).sort((h, l) => h.amount - l.amount)[0];
    if (!o.length && i)
      return {
        keep: t.filter((h) => h.secret !== i.secret),
        send: [i]
      };
    if (!o.length && !i)
      return { keep: t, send: [] };
    let a = e, u = [o[0]];
    const d = [], f = n ? this.getProofFeePPK(u[0]) : 0;
    if (a -= u[0].amount - f / 1e3, a > 0) {
      const { keep: h, send: l } = this.selectProofsToSend(
        o.slice(1),
        a,
        n
      );
      u.push(...l), d.push(...h);
    }
    const m = n ? this.getFeesForProofs(u) : 0;
    return U(u) < e + m && i && (u = [i]), {
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
    const e = t.reduce((n, r) => n + this.getProofFeePPK(r), 0);
    return Math.ceil(e / 1e3);
  }
  /**
   * Returns the current fee PPK for a proof according to the cached keyset
   * @param proof {Proof} A single proof
   * @returns feePPK {number} The feePPK for the selected proof
   * @throws throws an error if the proofs keyset is unknown
   */
  getProofFeePPK(t) {
    const e = this._keysets.find((n) => n.id === t.id);
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
  async swap(t, e, n) {
    let { outputAmounts: r } = n || {};
    const { includeFees: o, keysetId: c, counter: i, pubkey: a, privkey: u, proofsWeHave: d, outputData: f, p2pk: m } = n || {}, h = await this.getKeys(c), l = e;
    let w = t;
    const y = U(e);
    let g = y - w - this.getFeesForProofs(l), k = r?.sendAmounts || P(w, h.keys);
    if (o) {
      let _ = this.getFeesForKeyset(k.length, h.id), v = P(_, h.keys);
      for (; this.getFeesForKeyset(k.concat(v).length, h.id) > _; )
        _++, v = P(_, h.keys);
      k = k.concat(v), w += _, g -= _;
    }
    let p;
    if (!r?.keepAmounts && d)
      p = yt(
        d,
        g,
        h.keys,
        this._denominationTarget
      );
    else if (r) {
      if (r.keepAmounts?.reduce((_, v) => _ + v, 0) != g)
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
    const A = f?.keep || this._keepFactory, q = f?.send, F = this.createSwapPayload(
      w,
      l,
      h,
      r,
      i,
      a,
      u,
      { keep: A, send: q },
      m
    ), { signatures: Nt } = await this.mint.swap(F.payload), ht = F.outputData.map((_, v) => _.toProof(Nt[v], h)), dt = [], lt = [], ft = Array(F.keepVector.length), pt = Array(ht.length);
    return F.sortedIndices.forEach((_, v) => {
      ft[_] = F.keepVector[v], pt[_] = ht[v];
    }), pt.forEach((_, v) => {
      ft[v] ? dt.push(_) : lt.push(_);
    }), {
      keep: dt,
      send: lt
    };
  }
  /**
   * Restores batches of deterministic proofs until no more signatures are returned from the mint
   * @param [gapLimit=300] the amount of empty counters that should be returned before restoring ends (defaults to 300)
   * @param [batchSize=100] the amount of proofs that should be restored at a time (defaults to 100)
   * @param [counter=0] the counter that should be used as a starting point (defaults to 0)
   * @param [keysetId] which keysetId to use for the restoration. If none is passed the instance's default one will be used
   */
  async batchRestore(t = 300, e = 100, n = 0, r) {
    const o = Math.ceil(t / e), c = [];
    let i, a = 0;
    for (; a < o; ) {
      const u = await this.restore(n, e, { keysetId: r });
      u.proofs.length > 0 ? (a = 0, c.push(...u.proofs), i = u.lastCounterWithSignature) : a++, n += e;
    }
    return { proofs: c, lastCounterWithSignature: i };
  }
  /**
   * Regenerates
   * @param start set starting point for count (first cycle for each keyset should usually be 0)
   * @param count set number of blinded messages that should be generated
   * @param options.keysetId set a custom keysetId to restore from. keysetIds can be loaded with `CashuMint.getKeySets()`
   */
  async restore(t, e, n) {
    const { keysetId: r } = n || {}, o = await this.getKeys(r);
    if (!this._seed)
      throw new Error("CashuWallet must be initialized with a seed to use restore");
    const c = Array(e).fill(1), i = K.createDeterministicData(
      c.length,
      this._seed,
      t,
      o,
      c
    ), { outputs: a, signatures: u } = await this.mint.restore({
      outputs: i.map((h) => h.blindedMessage)
    }), d = {};
    a.forEach((h, l) => d[h.B_] = u[l]);
    const f = [];
    let m;
    for (let h = 0; h < i.length; h++) {
      const l = d[i[h].blindedMessage.B_];
      l && (m = t + h, i[h].blindedMessage.amount = l.amount, f.push(i[h].toProof(l, o)));
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
  async createMintQuote(t, e) {
    const n = {
      unit: this._unit,
      amount: t,
      description: e
    }, r = await this.mint.createMintQuote(n);
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
  async createLockedMintQuote(t, e, n) {
    const { supported: r } = (await this.getMintInfo()).isSupported(20);
    if (!r)
      throw new Error("Mint does not support NUT-20");
    const o = {
      unit: this._unit,
      amount: t,
      description: n,
      pubkey: e
    }, c = await this.mint.createMintQuote(o);
    if (typeof c.pubkey != "string")
      throw new Error("Mint returned unlocked mint quote");
    {
      const i = c.pubkey;
      return { ...c, pubkey: i, amount: c.amount || t, unit: c.unit || this.unit };
    }
  }
  async checkMintQuote(t) {
    const e = typeof t == "string" ? t : t.quote, n = await this.mint.checkMintQuote(e);
    return typeof t == "string" ? n : { ...n, amount: n.amount || t.amount, unit: n.unit || t.unit };
  }
  async mintProofs(t, e, n) {
    let { outputAmounts: r } = n || {};
    const { counter: o, pubkey: c, p2pk: i, keysetId: a, proofsWeHave: u, outputData: d, privateKey: f } = n || {}, m = await this.getKeys(a);
    !r && u && (r = {
      keepAmounts: yt(u, t, m.keys, this._denominationTarget),
      sendAmounts: []
    });
    let h = [];
    if (d)
      if (Y(d)) {
        const y = P(t, m.keys, r?.keepAmounts);
        for (let g = 0; g < y.length; g++)
          h.push(d(y[g], m));
      } else
        h = d;
    else if (this._keepFactory) {
      const y = P(t, m.keys, r?.keepAmounts);
      for (let g = 0; g < y.length; g++)
        h.push(this._keepFactory(y[g], m));
    } else
      h = this.createOutputData(
        t,
        m,
        o,
        c,
        r?.keepAmounts,
        i
      );
    let l;
    if (typeof e != "string") {
      if (!f)
        throw new Error("Can not sign locked quote without private key");
      const y = h.map((k) => k.blindedMessage), g = Ke(f, e.quote, y);
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
    return h.map((y, g) => y.toProof(w[g], m));
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
    }, n = await this.mint.createMeltQuote(e);
    return {
      ...n,
      unit: n.unit || this.unit,
      request: n.request || t
    };
  }
  /**
   * Requests a multi path melt quote from the mint.
   * @param invoice LN invoice that needs to get a fee estimate
   * @param partialAmount the partial amount of the invoice's total to be paid by this instance
   * @returns the mint will create and return a melt quote for the invoice with an amount and fee reserve
   */
  async createMultiPathMeltQuote(t, e) {
    const { supported: n, params: r } = (await this.lazyGetMintInfo()).isSupported(15);
    if (!n)
      throw new Error("Mint does not support NUT-15");
    if (!r?.some((u) => u.method === "bolt11" && u.unit === this.unit))
      throw new Error(`Mint does not support MPP for bolt11 and ${this.unit}`);
    const c = {
      mpp: {
        amount: e
      }
    }, i = {
      unit: this._unit,
      request: t,
      options: c
    };
    return { ...await this.mint.createMeltQuote(i), request: t, unit: this._unit };
  }
  async checkMeltQuote(t) {
    const e = typeof t == "string" ? t : t.quote, n = await this.mint.checkMeltQuote(e);
    return typeof t == "string" ? n : { ...n, request: t.request, unit: t.unit };
  }
  /**
   * Melt proofs for a melt quote. proofsToSend must be at least amount+fee_reserve form the melt quote. This function does not perform coin selection!.
   * Returns melt quote and change proofs
   * @param meltQuote ID of the melt quote
   * @param proofsToSend proofs to melt
   * @param {MeltProofOptions} [options] - Optional parameters for configuring the Melting Proof operation
   * @returns
   */
  async meltProofs(t, e, n) {
    const { keysetId: r, counter: o, privkey: c } = n || {}, i = await this.getKeys(r), a = this.createBlankOutputs(
      U(e) - t.amount,
      i,
      o,
      this._keepFactory
    );
    c != null && (e = bt(
      e.map((f) => ({
        amount: f.amount,
        C: B(f.C),
        id: f.id,
        secret: new TextEncoder().encode(f.secret)
      })),
      c
    ).map((f) => et(f))), e = j(e);
    const u = {
      quote: t.quote,
      inputs: e,
      outputs: a.map((f) => f.blindedMessage)
    }, d = await this.mint.melt(u);
    return {
      quote: { ...d, unit: t.unit, request: t.request },
      change: d.change?.map((f, m) => a[m].toProof(f, i)) ?? []
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
  createSwapPayload(t, e, n, r, o, c, i, a, u) {
    const d = e.reduce((p, A) => p + A.amount, 0);
    r && r.sendAmounts && !r.keepAmounts && (r.keepAmounts = P(
      d - t - this.getFeesForProofs(e),
      n.keys
    ));
    const f = d - t - this.getFeesForProofs(e);
    let m = [], h = [];
    if (a?.keep)
      if (Y(a.keep)) {
        const p = a.keep;
        P(f, n.keys).forEach((q) => {
          m.push(p(q, n));
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
      if (Y(a.send)) {
        const p = a.send;
        P(t, n.keys).forEach((q) => {
          h.push(p(q, n));
        });
      } else
        h = a.send;
    else
      h = this.createOutputData(
        t,
        n,
        o ? o + m.length : void 0,
        c,
        r?.sendAmounts,
        u
      );
    i && (e = bt(
      e.map((p) => ({
        amount: p.amount,
        C: B(p.C),
        id: p.id,
        secret: new TextEncoder().encode(p.secret)
      })),
      i
    ).map((p) => et(p))), e = j(e);
    const l = [...m, ...h], w = l.map((p, A) => A).sort(
      (p, A) => l[p].blindedMessage.amount - l[A].blindedMessage.amount
    ), y = [
      ...Array(m.length).fill(!0),
      ...Array(h.length).fill(!1)
    ], g = w.map((p) => l[p]), k = w.map((p) => y[p]);
    return {
      payload: {
        inputs: e,
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
  async checkProofsStates(t) {
    const e = new TextEncoder(), n = t.map((c) => H(e.encode(c.secret)).toHex(!0)), r = 100, o = [];
    for (let c = 0; c < n.length; c += r) {
      const i = n.slice(c, c + r), { states: a } = await this.mint.check({
        Ys: i
      }), u = {};
      a.forEach((d) => {
        u[d.Y] = d;
      });
      for (let d = 0; d < i.length; d++) {
        const f = u[i[d]];
        if (!f)
          throw new Error("Could not find state for proof with Y: " + i[d]);
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
  async onMintQuoteUpdates(t, e, n) {
    if (await this.mint.connectWebSocket(), !this.mint.webSocketConnection)
      throw new Error("failed to establish WebSocket connection.");
    const r = this.mint.webSocketConnection.createSubscription(
      { kind: "bolt11_mint_quote", filters: t },
      e,
      n
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
  async onMeltQuotePaid(t, e, n) {
    return this.onMeltQuoteUpdates(
      [t],
      (r) => {
        r.state === W.PAID && e(r);
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
  async onMintQuotePaid(t, e, n) {
    return this.onMintQuoteUpdates(
      [t],
      (r) => {
        r.state === Z.PAID && e(r);
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
  async onMeltQuoteUpdates(t, e, n) {
    if (await this.mint.connectWebSocket(), !this.mint.webSocketConnection)
      throw new Error("failed to establish WebSocket connection.");
    const r = this.mint.webSocketConnection.createSubscription(
      { kind: "bolt11_melt_quote", filters: t },
      e,
      n
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
  async onProofStateUpdates(t, e, n) {
    if (await this.mint.connectWebSocket(), !this.mint.webSocketConnection)
      throw new Error("failed to establish WebSocket connection.");
    const r = new TextEncoder(), o = {};
    for (let a = 0; a < t.length; a++) {
      const u = H(r.encode(t[a].secret)).toHex(!0);
      o[u] = t[a];
    }
    const c = Object.keys(o), i = this.mint.webSocketConnection.createSubscription(
      { kind: "proof_state", filters: c },
      (a) => {
        e({ ...a, proof: o[a.Y] });
      },
      n
    );
    return () => {
      this.mint.webSocketConnection?.cancelSubscription(i, e);
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
  createOutputData(t, e, n, r, o, c, i) {
    let a;
    if (r)
      a = K.createP2PKData({ pubkey: r }, t, e, o);
    else if (n || n === 0) {
      if (!this._seed)
        throw new Error("cannot create deterministic messages without seed");
      a = K.createDeterministicData(
        t,
        this._seed,
        n,
        e,
        o
      );
    } else c ? a = K.createP2PKData(c, t, e, o) : i ? a = P(t, e.keys).map((d) => i(d, e)) : a = K.createRandomData(t, e, o);
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
  createBlankOutputs(t, e, n, r) {
    let o = Math.ceil(Math.log2(t)) || 1;
    o < 0 && (o = 0);
    const c = o ? Array(o).fill(1) : [];
    return this.createOutputData(
      c.length,
      e,
      n,
      void 0,
      c,
      void 0,
      r
    );
  }
}
class C {
  /**
   * @param _mintUrl requires mint URL to create this object
   * @param _customRequest if passed, use custom request implementation for network communication with the mint
   */
  constructor(t, e) {
    this._mintUrl = t, this._customRequest = e, this._mintUrl = qt(t), this._customRequest = e;
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
  static async mint(t, e, n, r) {
    const o = r || S, c = {
      "Clear-auth": `${n}`
    }, i = await o({
      endpoint: b(t, "/v1/auth/blind/mint"),
      method: "POST",
      requestBody: e,
      headers: c
    });
    if (!T(i) || !Array.isArray(i?.signatures))
      throw new Error("bad response");
    return i;
  }
  /**
   * Mints new Blinded Authentication tokens by requesting blind signatures on the provided outputs.
   * @param mintPayload Payload containing the outputs to get blind signatures on
   * @param clearAuthToken A NUT-21 clear auth token
   * @returns serialized blinded signatures
   */
  async mint(t, e) {
    return C.mint(this._mintUrl, t, e, this._customRequest);
  }
  /**
   * Get the mints public NUT-22 keys
   * @param mintUrl
   * @param keysetId optional param to get the keys for a specific keyset. If not specified, the keys from all active keysets are fetched
   * @param customRequest
   * @returns
   */
  static async getKeys(t, e, n) {
    const o = await (n || S)({
      endpoint: e ? b(t, "/v1/auth/blind/keys", e) : b(t, "/v1/auth/blind/keys")
    });
    if (!T(o) || !Array.isArray(o.keysets))
      throw new Error("bad response");
    return o;
  }
  /**
   * Get the mints public NUT-22 keys
   * @param keysetId optional param to get the keys for a specific keyset. If not specified, the keys from all active keysets are fetched
   * @returns the mints public keys
   */
  async getKeys(t, e) {
    return await C.getKeys(
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
    return (e || S)({
      endpoint: b(t, "/v1/auth/blind/keysets")
    });
  }
  /**
   * Get the mints NUT-22 keysets in no specific order
   * @returns all the mints past and current keysets.
   */
  async getKeySets() {
    return C.getKeySets(this._mintUrl, this._customRequest);
  }
}
class Ne {
  /**
   * @param mint NUT-22 auth mint instance
   * @param options.keys public keys from the mint (will be fetched from mint if not provided)
   * @param options.keysets keysets from the mint (will be fetched from mint if not provided)
   */
  constructor(t, e) {
    this._keys = /* @__PURE__ */ new Map(), this._keysets = [], this._unit = "auth", this.mint = t;
    let n = [];
    e?.keys && !Array.isArray(e.keys) ? n = [e.keys] : e?.keys && Array.isArray(e?.keys) && (n = e?.keys), n && n.forEach((r) => this._keys.set(r.id, r)), e?.keysets && (this._keysets = e.keysets);
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
    const n = e.sort(
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
    const e = (await this.mint.getKeySets()).keysets.filter((n) => n.unit === this._unit);
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
    if ((!(this._keysets.length > 0) || e) && await this.getKeySets(), t || (t = this.getActiveKeyset(this._keysets).id), !this._keysets.find((n) => n.id === t) && (await this.getKeySets(), !this._keysets.find((n) => n.id === t)))
      throw new Error(`could not initialize keys. No keyset with id '${t}' found`);
    if (!this._keys.get(t)) {
      const n = await this.mint.getKeys(t);
      this._keys.set(t, n.keysets[0]);
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
  async mintProofs(t, e, n) {
    const r = await this.getKeys(n?.keysetId), o = K.createRandomData(t, r), c = {
      outputs: o.map((u) => u.blindedMessage)
    }, { signatures: i } = await this.mint.mint(c, e), a = o.map((u, d) => u.toProof(i[d], r));
    if (a.some((u) => !Ut(u, r)))
      throw new Error("Mint returned auth proofs with invalid DLEQ");
    return a;
  }
}
function Re(s) {
  const t = {
    id: s.id,
    secret: s.secret,
    C: s.C
  }, e = Et(t);
  return "auth" + "A" + e;
}
async function Ze(s, t, e) {
  const n = new C(t);
  return (await new Ne(n).mintProofs(s, e)).map((c) => Re(c));
}
export {
  C as CashuAuthMint,
  Ne as CashuAuthWallet,
  E as CashuMint,
  Xe as CashuWallet,
  Je as CheckStateEnum,
  $ as HttpResponseError,
  W as MeltQuoteState,
  ut as MintOperationError,
  Z as MintQuoteState,
  at as NetworkError,
  K as OutputData,
  it as PaymentRequest,
  _e as PaymentRequestTransportType,
  He as decodePaymentRequest,
  je as deriveKeysetId,
  Ze as getBlindedAuthToken,
  fe as getDecodedToken,
  Ge as getDecodedTokenBinary,
  Re as getEncodedAuthToken,
  $e as getEncodedToken,
  ze as getEncodedTokenBinary,
  le as getEncodedTokenV4,
  Ut as hasValidDleq,
  Ve as injectWebSocketImpl,
  Ye as setGlobalRequestOptions
};
//# sourceMappingURL=cashu-ts.es.js.map
