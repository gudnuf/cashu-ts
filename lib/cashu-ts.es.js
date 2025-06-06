import { secp256k1 as H, schnorr as nt } from "@noble/curves/secp256k1";
import { sha256 as R } from "@noble/hashes/sha256";
import { bytesToHex as I, hexToBytes as M } from "@noble/curves/abstract/utils";
import { Buffer as D } from "buffer";
import { hexToBytes as X, bytesToHex as U, randomBytes as pt } from "@noble/hashes/utils";
import { HDKey as Rt } from "@scure/bip32";
function F(s) {
  return _t(I(s));
}
function _t(s) {
  return BigInt(`0x${s}`);
}
function Nt(s) {
  return D.from(s, "base64");
}
const Ot = M("536563703235366b315f48617368546f43757276655f43617368755f");
function j(s) {
  const t = R(D.concat([Ot, s])), e = new Uint32Array(1), n = 2 ** 16;
  for (let r = 0; r < n; r++) {
    const i = new Uint8Array(e.buffer), a = R(D.concat([t, i]));
    try {
      return B(I(D.concat([new Uint8Array([2]), a])));
    } catch {
      e[0]++;
    }
  }
  throw new Error("No valid point found");
}
function Ft(s) {
  const e = s.map((r) => r.toHex(!1)).join("");
  return R(new TextEncoder().encode(e));
}
function B(s) {
  return H.ProjectivePoint.fromHex(s);
}
const Qt = (s) => {
  let t;
  return /^[a-fA-F0-9]+$/.test(s) ? t = _t(s) % BigInt(2 ** 31 - 1) : t = F(Nt(s)) % BigInt(2 ** 31 - 1), t;
};
function Ht(s, t) {
  if (s.length !== t.length) return !1;
  for (let e = 0; e < s.length; e++)
    if (s[e] !== t[e]) return !1;
  return !0;
}
const Lt = (s, t, e, n) => {
  const r = H.ProjectivePoint.fromPrivateKey(I(s.s)), i = n.multiply(F(s.e)), a = t.multiply(F(s.s)), o = e.multiply(F(s.e)), c = r.subtract(i), u = a.subtract(o), d = Ft([c, u, n, e]);
  return Ht(d, s.e);
}, Wt = (s, t, e, n) => {
  if (t.r === void 0) throw new Error("verifyDLEQProof_reblind: Undefined blinding factor");
  const r = j(s), i = e.add(n.multiply(t.r)), a = H.ProjectivePoint.fromPrivateKey(t.r), o = r.add(a);
  return Lt(t, o, i, n);
};
function $t(s) {
  return D.from(s).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function St(s) {
  return D.from(s, "base64");
}
function Et(s) {
  const t = JSON.stringify(s);
  return Gt(D.from(t).toString("base64"));
}
function jt(s) {
  const t = D.from(zt(s), "base64").toString();
  return JSON.parse(t);
}
function zt(s) {
  return s.replace(/-/g, "+").replace(/_/g, "/").split("=")[0];
}
function Gt(s) {
  return s.replace(/\+/g, "-").replace(/\//g, "_").split("=")[0];
}
function Jt(s) {
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
    Pt(s, t);
  else if (typeof s == "string")
    At(s, t);
  else if (Array.isArray(s))
    Yt(s, t);
  else if (s instanceof Uint8Array)
    Vt(s, t);
  else if (typeof s == "object")
    Xt(s, t);
  else
    throw new Error("Unsupported type");
}
function Pt(s, t) {
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
function Vt(s, t) {
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
function At(s, t) {
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
  Pt(e.length, t), t[t.length - 1] |= 160;
  for (const n of e)
    At(n, t), rt(s[n], t);
}
function it(s) {
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
      return oe(s, t, r);
    default:
      throw new Error(`Unsupported major type: ${n}`);
  }
}
function N(s, t, e) {
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
  const { value: n, offset: r } = N(s, t, e);
  return { value: n, offset: r };
}
function te(s, t, e) {
  const { value: n, offset: r } = N(s, t, e);
  return { value: -1 - n, offset: r };
}
function ee(s, t, e) {
  const { value: n, offset: r } = N(s, t, e);
  if (r + n > s.byteLength)
    throw new Error("Byte string length exceeds data length");
  return { value: new Uint8Array(s.buffer, s.byteOffset + r, n), offset: r + n };
}
function ne(s, t, e) {
  const { value: n, offset: r } = N(s, t, e);
  if (r + n > s.byteLength)
    throw new Error("String length exceeds data length");
  const i = new Uint8Array(s.buffer, s.byteOffset + r, n);
  return { value: new TextDecoder().decode(i), offset: r + n };
}
function se(s, t, e) {
  const { value: n, offset: r } = N(s, t, e), i = [];
  let a = r;
  for (let o = 0; o < n; o++) {
    const c = z(s, a);
    i.push(c.value), a = c.offset;
  }
  return { value: i, offset: a };
}
function re(s, t, e) {
  const { value: n, offset: r } = N(s, t, e), i = {};
  let a = r;
  for (let o = 0; o < n; o++) {
    const c = z(s, a);
    if (!Jt(c.value))
      throw new Error("Invalid key type");
    const u = z(s, c.offset);
    i[c.value] = u.value, a = u.offset;
  }
  return { value: i, offset: a };
}
function ie(s) {
  const t = (s & 31744) >> 10, e = s & 1023, n = s & 32768 ? -1 : 1;
  return t === 0 ? n * 2 ** -14 * (e / 1024) : t === 31 ? e ? NaN : n * (1 / 0) : n * 2 ** (t - 15) * (1 + e / 1024);
}
function oe(s, t, e) {
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
    const n = ie(s.getUint16(t, !1));
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
class ot {
  constructor(t, e, n, r, i, a, o = !1, c) {
    this.transport = t, this.id = e, this.amount = n, this.unit = r, this.mints = i, this.description = a, this.singleUse = o, this.nut10 = c;
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
    return new ot(
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
    const n = t.slice(5), r = St(n), i = it(r);
    return this.fromRawRequest(i);
  }
}
const ae = "A", ce = "cashu";
function A(s, t, e, n) {
  if (e) {
    const i = wt(e);
    if (i > s)
      throw new Error(`Split is greater than total amount: ${i} > ${s}`);
    if (e.some((a) => !It(a, t)))
      throw new Error("Provided amount preferences do not match the amounts of the mint keyset.");
    s = s - wt(e);
  } else
    e = [];
  return vt(t, "desc").forEach((i) => {
    const a = Math.floor(s / i);
    for (let o = 0; o < a; ++o) e?.push(i);
    s %= i;
  }), e.sort((i, a) => i - a);
}
function yt(s, t, e, n) {
  const r = [], i = s.map((u) => u.amount);
  vt(e, "asc").forEach((u) => {
    const d = i.filter((p) => p === u).length, f = Math.max(n - d, 0);
    for (let p = 0; p < f && !(r.reduce((h, l) => h + l, 0) + u > t); ++p)
      r.push(u);
  });
  const o = t - r.reduce((u, d) => u + d, 0);
  return o && A(o, e).forEach((d) => {
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
  return s.unit && (t.unit = s.unit), s.memo && (t.memo = s.memo), ce + ae + Et(t);
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
  if (s.proofs.forEach((o) => {
    if (o.dleq && o.dleq.r == null)
      throw new Error("Missing blinding factor in included DLEQ proof");
  }), Mt(s.proofs))
    throw new Error("can not encode to v4 token if proofs contain non-hex keyset id");
  const e = Kt(s), n = st(e), r = "cashu", i = "B", a = $t(n);
  return r + i + a;
}
function Kt(s) {
  const t = {}, e = s.mint;
  for (let r = 0; r < s.proofs.length; r++) {
    const i = s.proofs[r];
    t[i.id] ? t[i.id].push(i) : t[i.id] = [i];
  }
  const n = {
    m: e,
    u: s.unit || "sat",
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
  }), me(s);
}
function me(s) {
  const t = s.slice(0, 1), e = s.slice(1);
  if (t === "A") {
    const n = jt(e);
    if (n.token.length > 1)
      throw new Error("Multi entry token are not supported");
    const r = n.token[0], i = {
      mint: r.mint,
      proofs: r.proofs,
      unit: n.unit || "sat"
    };
    return n.memo && (i.memo = n.memo), i;
  } else if (t === "B") {
    const n = St(e), r = it(n);
    return Dt(r);
  }
  throw new Error("Token version is not supported");
}
function je(s) {
  const t = Object.entries(s).sort((r, i) => +r[0] - +i[0]).map(([, r]) => M(r)).reduce((r, i) => pe(r, i), new Uint8Array()), e = R(t);
  return "00" + Buffer.from(e).toString("hex").slice(0, 14);
}
function pe(s, t) {
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
function x(s) {
  return s.reduce((t, e) => t + e.amount, 0);
}
function ze(s) {
  return ot.fromEncodedRequest(s);
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
function $(s) {
  return s.map((t) => {
    const e = { ...t };
    return delete e.dleq, e;
  });
}
function xt(s, t) {
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
  return !!Wt(
    new TextEncoder().encode(s.secret),
    e,
    B(s.C),
    B(n)
  );
}
function we(...s) {
  const t = s.reduce((r, i) => r + i.length, 0), e = new Uint8Array(t);
  let n = 0;
  for (let r = 0; r < s.length; r++)
    e.set(s[r], n), n = n + s[r].length;
  return e;
}
function Ge(s) {
  const t = new TextEncoder(), e = Kt(s), n = st(e), r = t.encode("craw"), i = t.encode("B");
  return we(r, i, n);
}
function Je(s) {
  const t = new TextDecoder(), e = t.decode(s.slice(0, 4)), n = t.decode(new Uint8Array([s[4]]));
  if (e !== "craw" || n !== "B")
    throw new Error("not a valid binary token");
  const r = s.slice(5), i = it(r);
  return Dt(i);
}
function wt(s) {
  return s.reduce((t, e) => t + e, 0);
}
let at;
typeof WebSocket < "u" && (at = WebSocket);
function Ve(s) {
  at = s;
}
function ke() {
  return at;
}
class be {
  constructor(t, e) {
    this.callback = t, this.timerCalc = e, this.timer = void 0, this.tries = 0;
  }
  reset() {
    this.tries = 0, clearTimeout(this.timer);
  }
  scheduleTimeout() {
    clearTimeout(this.timer), this.timer = setTimeout(() => {
      this.tries = this.tries + 1, this.callback();
    }, this.timerCalc(this.tries + 1));
  }
}
class C {
  constructor() {
    this.connectionMap = /* @__PURE__ */ new Map();
  }
  static getInstance() {
    return C.instance || (C.instance = new C()), C.instance;
  }
  getConnection(t, e) {
    if (this.connectionMap.has(t))
      return this.connectionMap.get(t);
    const n = new _e(t, e);
    return this.connectionMap.set(t, n), n;
  }
}
class _e {
  constructor(t, e) {
    this.subListeners = {}, this.rpcListeners = {}, this.rpcId = 0, this.heartbeatIntervalMs = 3e4, this.pendingHeartbeatRef = null, this.heartbeatCallback = () => {
    }, this.logger = () => {
    }, this.maxReconnectAttempts = 1 / 0, this.enableHeartbeat = !0, this.isManualDisconnect = !1, this.stateChangeCallbacks = {
      open: [],
      close: [],
      error: [],
      message: [],
      reconnecting: []
    }, this._WS = ke(), this.url = new URL(t), this.messageQueue = new ge(), e?.heartbeatIntervalMs && (this.heartbeatIntervalMs = e.heartbeatIntervalMs), e?.logger && (this.logger = e.logger), e?.maxReconnectAttempts !== void 0 && (this.maxReconnectAttempts = e.maxReconnectAttempts), e?.enableHeartbeat !== void 0 && (this.enableHeartbeat = e.enableHeartbeat);
    const n = e?.reconnectAfterMs || ((r) => [1e3, 2e3, 5e3, 1e4][r - 1] || 1e4);
    this.reconnectTimer = new be(async () => {
      this.log("reconnection", "Attempting to reconnect..."), this.triggerStateChange("reconnecting"), await this.disconnect(!1), await this.connect();
    }, n);
  }
  /**
   * Add state change listener
   */
  onStateChange(t, e) {
    this.stateChangeCallbacks[t].push(e);
  }
  /**
   * Remove state change listener
   */
  offStateChange(t, e) {
    const n = this.stateChangeCallbacks[t].indexOf(e);
    n > -1 && this.stateChangeCallbacks[t].splice(n, 1);
  }
  /**
   * Set heartbeat callback
   */
  onHeartbeat(t) {
    this.heartbeatCallback = t;
  }
  /**
   * Get current connection state
   */
  connectionState() {
    if (!this.ws)
      return this.reconnectTimer.tries > 0 ? "reconnecting" : "closed";
    switch (this.ws.readyState) {
      case 0:
        return "connecting";
      case 1:
        return "open";
      case 2:
        return "closing";
      default:
        return "closed";
    }
  }
  /**
   * Check if connection is open
   */
  isConnected() {
    return this.connectionState() === "open";
  }
  async connect() {
    return this.connectionPromise || (this.isManualDisconnect = !1, this.connectionPromise = new Promise((t, e) => {
      try {
        this.ws = new this._WS(this.url.toString());
      } catch (n) {
        e(n);
        return;
      }
      this.setupConnection(), this.ws.onopen = () => {
        this.log("transport", `Connected to ${this.url.toString()}`), this.onConnOpen(), t();
      }, this.ws.onerror = (n) => {
        this.log("transport", "Connection error", n), this.onConnError(n), e(new Error("Failed to open WebSocket"));
      }, this.ws.onmessage = (n) => {
        this.onConnMessage(n);
      }, this.ws.onclose = (n) => {
        this.log("transport", "Connection closed", n), this.onConnClose(n);
      };
    })), this.connectionPromise;
  }
  /**
   * Disconnect with optional reconnection control
   */
  async disconnect(t = !0) {
    this.isManualDisconnect = t, this.ws && (this.ws.onclose = () => {
    }, this.ws.close(), this.ws = void 0), this.heartbeatTimer && (clearInterval(this.heartbeatTimer), this.heartbeatTimer = void 0), t && this.reconnectTimer.reset(), this.connectionPromise = void 0;
  }
  sendRequest(t, e) {
    if (!this.isConnected())
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
      this.subListeners[t] = this.subListeners[t].filter((n) => n !== e);
    }
  }
  async ensureConnection() {
    this.isConnected() || await this.connect();
  }
  /**
   * Send heartbeat message
   */
  sendHeartbeat() {
    if (!this.isConnected()) {
      this.heartbeatCallback("disconnected");
      return;
    }
    if (this.pendingHeartbeatRef) {
      this.pendingHeartbeatRef = null, this.log("transport", "Heartbeat timeout. Attempting to re-establish connection"), this.heartbeatCallback("timeout"), this.ws?.close(1e3, "heartbeat timeout");
      return;
    }
    this.pendingHeartbeatRef = this.makeRef();
    try {
      this.ws?.send(JSON.stringify({
        type: "heartbeat",
        ref: this.pendingHeartbeatRef
      })), this.heartbeatCallback("sent");
    } catch (t) {
      this.log("transport", "Failed to send heartbeat", t), this.heartbeatCallback("error");
    }
  }
  /**
   * Generate unique reference
   */
  makeRef() {
    return Math.random().toString(36).substring(2, 15);
  }
  /**
   * Log message
   */
  log(t, e, n) {
    this.logger(t, e, n);
  }
  /**
   * Trigger state change callbacks
   */
  triggerStateChange(t, e) {
    this.stateChangeCallbacks[t].forEach((n) => n(e));
  }
  /**
   * Setup WebSocket connection handlers
   */
  setupConnection() {
  }
  /**
   * Handle connection open
   */
  onConnOpen() {
    this.flushSendBuffer(), this.reconnectTimer.reset(), this.enableHeartbeat && (this.heartbeatTimer && clearInterval(this.heartbeatTimer), this.heartbeatTimer = setInterval(() => {
      this.sendHeartbeat();
    }, this.heartbeatIntervalMs)), this.triggerStateChange("open");
  }
  /**
   * Handle connection close
   */
  onConnClose(t) {
    this.connectionPromise = void 0, this.heartbeatTimer && (clearInterval(this.heartbeatTimer), this.heartbeatTimer = void 0), this.triggerStateChange("close", t), !this.isManualDisconnect && this.reconnectTimer.tries < this.maxReconnectAttempts ? (this.log("transport", `Connection lost. Scheduling reconnection attempt ${this.reconnectTimer.tries + 1}`), this.reconnectTimer.scheduleTimeout()) : this.reconnectTimer.tries >= this.maxReconnectAttempts && this.log("transport", "Max reconnection attempts reached. Giving up.");
  }
  /**
   * Handle connection error
   */
  onConnError(t) {
    this.triggerStateChange("error", t);
  }
  /**
   * Handle incoming messages
   */
  onConnMessage(t) {
    try {
      const e = JSON.parse(t.data);
      if (e.type === "heartbeat" && e.ref === this.pendingHeartbeatRef) {
        this.pendingHeartbeatRef = null, this.heartbeatCallback("ok");
        return;
      }
    } catch {
    }
    this.messageQueue.enqueue(t.data), this.handlingInterval || (this.handlingInterval = setInterval(
      this.handleNextMessage.bind(this),
      0
    )), this.triggerStateChange("message", t);
  }
  /**
   * Flush send buffer (for future message queuing implementation)
   */
  flushSendBuffer() {
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
        this.rpcListeners[e.id] && (this.rpcListeners[e.id].errorCallback(e.error), this.removeRpcListener(e.id));
      else if ("method" in e && !("id" in e)) {
        const n = e.params.subId;
        if (!n)
          return;
        if (this.subListeners[n]?.length > 0) {
          const r = e;
          this.subListeners[n].forEach((i) => i(r.params.payload));
        }
      }
    } catch (n) {
      console.error(n);
      return;
    }
  }
  createSubscription(t, e, n) {
    if (!this.isConnected())
      return n(new Error("Socket is not open"));
    const r = (Math.random() + 1).toString(36).substring(7);
    return this.addRpcListener(
      () => {
        this.addSubListener(r, e);
      },
      (i) => {
        n(new Error(i.message));
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
  /**
   * Close connection permanently
   */
  close() {
    this.disconnect(!0);
  }
  /**
   * Get reconnection statistics
   */
  getReconnectionStats() {
    return {
      attempts: this.reconnectTimer.tries,
      maxAttempts: this.maxReconnectAttempts,
      state: this.connectionState()
    };
  }
}
const Ye = {
  UNSPENT: "UNSPENT",
  PENDING: "PENDING",
  SPENT: "SPENT"
}, L = {
  UNPAID: "UNPAID",
  PENDING: "PENDING",
  PAID: "PAID"
}, Z = {
  UNPAID: "UNPAID",
  PAID: "PAID",
  ISSUED: "ISSUED"
};
var Se = /* @__PURE__ */ ((s) => (s.POST = "post", s.NOSTR = "nostr", s))(Se || {});
class W extends Error {
  constructor(t, e) {
    super(t), this.status = e, this.name = "HttpResponseError", Object.setPrototypeOf(this, W.prototype);
  }
}
class ct extends Error {
  constructor(t) {
    super(t), this.name = "NetworkError", Object.setPrototypeOf(this, ct.prototype);
  }
}
class ut extends W {
  constructor(t, e) {
    super(e || "Unknown mint operation error", 400), this.code = t, this.name = "MintOperationError", Object.setPrototypeOf(this, ut.prototype);
  }
}
let Bt = {};
function Xe(s) {
  Bt = s;
}
async function Ee({
  endpoint: s,
  requestBody: t,
  headers: e,
  ...n
}) {
  const r = t ? JSON.stringify(t) : void 0, i = {
    Accept: "application/json, text/plain, */*",
    ...r ? { "Content-Type": "application/json" } : void 0,
    ...e
  };
  let a;
  try {
    a = await fetch(s, { body: r, headers: i, ...n });
  } catch (o) {
    throw new ct(o instanceof Error ? o.message : "Network request failed");
  }
  if (!a.ok) {
    const o = await a.json().catch(() => ({ error: "bad response" }));
    throw a.status === 400 && "code" in o && "detail" in o ? new ut(o.code, o.detail) : new W(
      "error" in o ? o.error : o.detail || "HTTP request failed",
      a.status
    );
  }
  try {
    return await a.json();
  } catch (o) {
    throw console.error("Failed to parse HTTP response", o), new W("bad response", a.status);
  }
}
async function S(s) {
  return await Ee({ ...s, ...Bt });
}
function G(s) {
  return s.state || (console.warn(
    "Field 'state' not found in MeltQuoteResponse. Update NUT-05 of mint: https://github.com/cashubtc/nuts/pull/136)"
  ), typeof s.paid == "boolean" && (s.state = s.paid ? L.PAID : L.UNPAID)), s;
}
function kt(s) {
  return s.state || (console.warn(
    "Field 'state' not found in MintQuoteResponse. Update NUT-04 of mint: https://github.com/cashubtc/nuts/pull/141)"
  ), typeof s.paid == "boolean" && (s.state = s.paid ? Z.PAID : Z.UNPAID)), s;
}
function Pe(s) {
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
    return Pe(r);
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
    const i = n || S, a = r ? { "Blind-auth": r } : {}, o = await i({
      endpoint: b(t, "/v1/swap"),
      method: "POST",
      requestBody: e,
      headers: a
    });
    if (!T(o) || !Array.isArray(o?.signatures))
      throw new Error(o.detail ?? "bad response");
    return o;
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
    const i = n || S, a = r ? { "Blind-auth": r } : {}, o = await i({
      endpoint: b(t, "/v1/mint/quote/bolt11"),
      method: "POST",
      requestBody: e,
      headers: a
    });
    return kt(o);
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
    const i = n || S, a = r ? { "Blind-auth": r } : {}, o = await i({
      endpoint: b(t, "/v1/mint/quote/bolt11", e),
      method: "GET",
      headers: a
    });
    return kt(o);
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
    const i = n || S, a = r ? { "Blind-auth": r } : {}, o = await i({
      endpoint: b(t, "/v1/mint/bolt11"),
      method: "POST",
      requestBody: e,
      headers: a
    });
    if (!T(o) || !Array.isArray(o?.signatures))
      throw new Error("bad response");
    return o;
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
    const i = n || S, a = r ? { "Blind-auth": r } : {}, o = await i({
      endpoint: b(t, "/v1/melt/quote/bolt11"),
      method: "POST",
      requestBody: e,
      headers: a
    }), c = G(o);
    if (!T(c) || typeof c?.amount != "number" || typeof c?.fee_reserve != "number" || typeof c?.quote != "string")
      throw new Error("bad response");
    return c;
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
    const i = n || S, a = r ? { "Blind-auth": r } : {}, o = await i({
      endpoint: b(t, "/v1/melt/quote/bolt11", e),
      method: "GET",
      headers: a
    }), c = G(o);
    if (!T(c) || typeof c?.amount != "number" || typeof c?.fee_reserve != "number" || typeof c?.quote != "string" || typeof c?.state != "string" || !Object.values(L).includes(c.state))
      throw new Error("bad response");
    return c;
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
    const i = n || S, a = r ? { "Blind-auth": r } : {}, o = await i({
      endpoint: b(t, "/v1/melt/bolt11"),
      method: "POST",
      requestBody: e,
      headers: a
    }), c = G(o);
    if (!T(c) || typeof c?.state != "string" || !Object.values(L).includes(c.state))
      throw new Error("bad response");
    return c;
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
    const i = await (n || S)({
      endpoint: b(t, "/v1/checkstate"),
      method: "POST",
      requestBody: e
    });
    if (!T(i) || !Array.isArray(i?.states))
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
  static async getKeys(t, e, n) {
    e && (e = e.replace(/\//g, "_").replace(/\+/g, "-"));
    const i = await (n || S)({
      endpoint: e ? b(t, "/v1/keys", e) : b(t, "/v1/keys")
    });
    if (!T(i) || !Array.isArray(i.keysets))
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
    const i = await (n || S)({
      endpoint: b(t, "/v1/restore"),
      method: "POST",
      requestBody: e
    });
    if (!T(i) || !Array.isArray(i?.outputs) || !Array.isArray(i?.signatures))
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
      t.pathname && (t.pathname.endsWith("/") ? t.pathname += e : t.pathname += "/" + e), this.ws = C.getInstance().getConnection(
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
}, ve = (s, t) => {
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
      const i = Ae(r.secret);
      if (i[0] !== "P2PK")
        throw new Error("unknown secret type");
      if (e.length) {
        const a = e.find((o) => i[1].data === o.pub)?.priv;
        if (a)
          n = a;
        else
          throw new Error("no matching key found");
      }
      return Ie(r, M(n));
    } catch {
      return r;
    }
  });
}, Ie = (s, t) => (s.witness || (s.witness = {
  signatures: [I(ve(s.secret, t))]
}), s);
function J(s, t, e) {
  const n = j(s);
  t || (t = F(H.utils.randomPrivateKey()));
  const r = H.ProjectivePoint.BASE.multiply(t);
  return { B_: n.add(r), r: t, secret: s };
}
function Te(s, t, e) {
  return s.subtract(e.multiply(t));
}
function Me(s, t, e, n) {
  const r = n, i = Te(s.C_, t, r);
  return {
    id: s.id,
    amount: s.amount,
    secret: e,
    C: i
  };
}
const et = (s) => ({
  amount: s.amount,
  C: s.C.toHex(!0),
  id: s.id,
  secret: new TextDecoder().decode(s.secret),
  witness: JSON.stringify(s.witness)
});
function Ke(s, t) {
  let e = s;
  for (const r of t)
    e += r.B_;
  const n = new TextEncoder().encode(e);
  return R(n);
}
function De(s, t, e) {
  const n = Ke(t, e), r = X(s), i = nt.sign(n, r);
  return U(i);
}
class V {
  constructor(t, e, n) {
    this.amount = t, this.B_ = e, this.id = n;
  }
  getSerializedBlindedMessage() {
    return { amount: this.amount, B_: this.B_.toHex(!0), id: this.id };
  }
}
const qe = "m/129372'/0'", xe = (s, t, e) => Ut(
  s,
  t,
  e,
  0
  /* SECRET */
), Be = (s, t, e) => Ut(
  s,
  t,
  e,
  1
  /* BLINDING_FACTOR */
), Ut = (s, t, e, n) => {
  const r = Rt.fromMasterSeed(s), i = Qt(t), a = `${qe}/${i}'/${e}'/${n}`, o = r.derive(a);
  if (o.privateKey === null)
    throw new Error("Could not derive private key");
  return o.privateKey;
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
    }, i = B(e.keys[t.amount]), a = Me(r, this.blindingFactor, this.secret, i);
    return {
      ...et(a),
      ...n && {
        dleq: {
          s: U(n.s),
          e: U(n.e),
          r: he(n.r ?? BigInt(0))
        }
      }
    };
  }
  static createP2PKData(t, e, n, r) {
    return A(e, n.keys, r).map((a) => this.createSingleP2PKData(t, a, n.id));
  }
  static createSingleP2PKData(t, e, n) {
    const r = [
      "P2PK",
      {
        nonce: U(pt(32)),
        data: t.pubkey,
        tags: []
      }
    ];
    t.locktime && r[1].tags.push(["locktime", t.locktime]), t.refundKeys && r[1].tags.push(["refund", ...t.refundKeys]);
    const i = JSON.stringify(r), a = new TextEncoder().encode(i), { r: o, B_: c } = J(a);
    return new K(
      new V(e, c, n).getSerializedBlindedMessage(),
      o,
      a
    );
  }
  static createRandomData(t, e, n) {
    return A(t, e.keys, n).map((i) => this.createSingleRandomData(i, e.id));
  }
  static createSingleRandomData(t, e) {
    const n = U(pt(32)), r = new TextEncoder().encode(n), { r: i, B_: a } = J(r);
    return new K(
      new V(t, a, e).getSerializedBlindedMessage(),
      i,
      r
    );
  }
  static createDeterministicData(t, e, n, r, i) {
    return A(t, r.keys, i).map(
      (o, c) => this.createSingleDeterministicData(o, e, n + c, r.id)
    );
  }
  static createSingleDeterministicData(t, e, n, r) {
    const i = xe(e, r, n), a = U(i), o = new TextEncoder().encode(a), c = ue(Be(e, r, n)), { r: u, B_: d } = J(o, c);
    return new K(
      new V(t, d, r).getSerializedBlindedMessage(),
      u,
      o
    );
  }
}
const Ue = 3, Ce = "sat";
class Ze {
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
    this._keys = /* @__PURE__ */ new Map(), this._keysets = [], this._seed = void 0, this._unit = Ce, this._mintInfo = void 0, this._denominationTarget = Ue, this.mint = t;
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
      (r, i) => (r.input_fee_ppk ?? 0) - (i.input_fee_ppk ?? 0)
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
    const { requireDleq: n, keysetId: r, outputAmounts: i, counter: a, pubkey: o, privkey: c, outputData: u, p2pk: d } = e || {};
    typeof t == "string" && (t = fe(t));
    const f = await this.getKeys(r);
    if (n && t.proofs.some((k) => !xt(k, f)))
      throw new Error("Token contains proofs with invalid DLEQ");
    const p = x(t.proofs) - this.getFeesForProofs(t.proofs);
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
  async send(t, e, n) {
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
    } = n || {};
    if (o && (e = e.filter((y) => y.dleq != null)), x(e) < t)
      throw new Error("Not enough funds available to send");
    const { keep: h, send: l } = this.selectProofsToSend(
      e,
      t,
      n?.includeFees
    ), w = a ? this.getFeesForProofs(l) : 0;
    if (!i && (x(l) != t + w || // if the exact amount cannot be selected
    u || d || f || c || p)) {
      const { keep: y, send: g } = this.selectProofsToSend(
        e,
        t,
        !0
      );
      r?.push(...y);
      const k = await this.swap(t, g, n);
      let { keep: m, send: P } = k;
      const q = k.serialized;
      return m = y.concat(m), o || (P = $(P)), { keep: m, send: P, serialized: q };
    }
    if (x(l) < t + w)
      throw new Error("Not enough funds available to send");
    return o ? { keep: h, send: l } : { keep: h, send: $(l) };
  }
  selectProofsToSend(t, e, n) {
    const r = t.sort((h, l) => h.amount - l.amount), i = r.filter((h) => h.amount <= e).sort((h, l) => l.amount - h.amount), o = r.filter((h) => h.amount > e).sort((h, l) => h.amount - l.amount)[0];
    if (!i.length && o)
      return {
        keep: t.filter((h) => h.secret !== o.secret),
        send: [o]
      };
    if (!i.length && !o)
      return { keep: t, send: [] };
    let c = e, u = [i[0]];
    const d = [], f = n ? this.getProofFeePPK(u[0]) : 0;
    if (c -= u[0].amount - f / 1e3, c > 0) {
      const { keep: h, send: l } = this.selectProofsToSend(
        i.slice(1),
        c,
        n
      );
      u.push(...l), d.push(...h);
    }
    const p = n ? this.getFeesForProofs(u) : 0;
    return x(u) < e + p && o && (u = [o]), {
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
    const { includeFees: i, keysetId: a, counter: o, pubkey: c, privkey: u, proofsWeHave: d, outputData: f, p2pk: p } = n || {}, h = await this.getKeys(a), l = e;
    let w = t;
    const y = x(e);
    let g = y - w - this.getFeesForProofs(l), k = r?.sendAmounts || A(w, h.keys);
    if (i) {
      let _ = this.getFeesForKeyset(k.length, h.id), v = A(_, h.keys);
      for (; this.getFeesForKeyset(k.concat(v).length, h.id) > _; )
        _++, v = A(_, h.keys);
      k = k.concat(v), w += _, g -= _;
    }
    let m;
    if (!r?.keepAmounts && d)
      m = yt(
        d,
        g,
        h.keys,
        this._denominationTarget
      );
    else if (r) {
      if (r.keepAmounts?.reduce((_, v) => _ + v, 0) != g)
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
    const P = f?.keep || this._keepFactory, q = f?.send, O = this.createSwapPayload(
      w,
      l,
      h,
      r,
      o,
      c,
      u,
      { keep: P, send: q },
      p
    ), { signatures: Ct } = await this.mint.swap(O.payload), ht = O.outputData.map((_, v) => _.toProof(Ct[v], h)), dt = [], lt = [], ft = Array(O.keepVector.length), mt = Array(ht.length);
    return O.sortedIndices.forEach((_, v) => {
      ft[_] = O.keepVector[v], mt[_] = ht[v];
    }), mt.forEach((_, v) => {
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
    const i = Math.ceil(t / e), a = [];
    let o, c = 0;
    for (; c < i; ) {
      const u = await this.restore(n, e, { keysetId: r });
      u.proofs.length > 0 ? (c = 0, a.push(...u.proofs), o = u.lastCounterWithSignature) : c++, n += e;
    }
    return { proofs: a, lastCounterWithSignature: o };
  }
  /**
   * Regenerates
   * @param start set starting point for count (first cycle for each keyset should usually be 0)
   * @param count set number of blinded messages that should be generated
   * @param options.keysetId set a custom keysetId to restore from. keysetIds can be loaded with `CashuMint.getKeySets()`
   */
  async restore(t, e, n) {
    const { keysetId: r } = n || {}, i = await this.getKeys(r);
    if (!this._seed)
      throw new Error("CashuWallet must be initialized with a seed to use restore");
    const a = Array(e).fill(1), o = K.createDeterministicData(
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
    const i = {
      unit: this._unit,
      amount: t,
      description: n,
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
    const e = typeof t == "string" ? t : t.quote, n = await this.mint.checkMintQuote(e);
    return typeof t == "string" ? n : { ...n, amount: n.amount || t.amount, unit: n.unit || t.unit };
  }
  async mintProofs(t, e, n) {
    let { outputAmounts: r } = n || {};
    const { counter: i, pubkey: a, p2pk: o, keysetId: c, proofsWeHave: u, outputData: d, privateKey: f } = n || {}, p = await this.getKeys(c);
    !r && u && (r = {
      keepAmounts: yt(u, t, p.keys, this._denominationTarget),
      sendAmounts: []
    });
    let h = [];
    if (d)
      if (Y(d)) {
        const y = A(t, p.keys, r?.keepAmounts);
        for (let g = 0; g < y.length; g++)
          h.push(d(y[g], p));
      } else
        h = d;
    else if (this._keepFactory) {
      const y = A(t, p.keys, r?.keepAmounts);
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
      const y = h.map((k) => k.blindedMessage), g = De(f, e.quote, y);
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
    const { keysetId: r, counter: i, privkey: a } = n || {}, o = await this.getKeys(r), c = this.createBlankOutputs(
      x(e) - t.amount,
      o,
      i,
      this._keepFactory
    );
    a != null && (e = bt(
      e.map((f) => ({
        amount: f.amount,
        C: B(f.C),
        id: f.id,
        secret: new TextEncoder().encode(f.secret)
      })),
      a
    ).map((f) => et(f))), e = $(e);
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
   * @returns
   */
  createSwapPayload(t, e, n, r, i, a, o, c, u) {
    const d = e.reduce((m, P) => m + P.amount, 0);
    r && r.sendAmounts && !r.keepAmounts && (r.keepAmounts = A(
      d - t - this.getFeesForProofs(e),
      n.keys
    ));
    const f = d - t - this.getFeesForProofs(e);
    let p = [], h = [];
    if (c?.keep)
      if (Y(c.keep)) {
        const m = c.keep;
        A(f, n.keys).forEach((q) => {
          p.push(m(q, n));
        });
      } else
        p = c.keep;
    else
      p = this.createOutputData(
        f,
        n,
        i,
        void 0,
        r?.keepAmounts,
        void 0,
        this._keepFactory
      );
    if (c?.send)
      if (Y(c.send)) {
        const m = c.send;
        A(t, n.keys).forEach((q) => {
          h.push(m(q, n));
        });
      } else
        h = c.send;
    else
      h = this.createOutputData(
        t,
        n,
        i ? i + p.length : void 0,
        a,
        r?.sendAmounts,
        u
      );
    o && (e = bt(
      e.map((m) => ({
        amount: m.amount,
        C: B(m.C),
        id: m.id,
        secret: new TextEncoder().encode(m.secret)
      })),
      o
    ).map((m) => et(m))), e = $(e);
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
    const e = new TextEncoder(), n = t.map((a) => j(e.encode(a.secret)).toHex(!0)), r = 100, i = [];
    for (let a = 0; a < n.length; a += r) {
      const o = n.slice(a, a + r), { states: c } = await this.mint.check({
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
        r.state === L.PAID && e(r);
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
    const r = new TextEncoder(), i = {};
    for (let c = 0; c < t.length; c++) {
      const u = j(r.encode(t[c].secret)).toHex(!0);
      i[u] = t[c];
    }
    const a = Object.keys(i), o = this.mint.webSocketConnection.createSubscription(
      { kind: "proof_state", filters: a },
      (c) => {
        e({ ...c, proof: i[c.Y] });
      },
      n
    );
    return () => {
      this.mint.webSocketConnection?.cancelSubscription(o, e);
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
  createOutputData(t, e, n, r, i, a, o) {
    let c;
    if (r)
      c = K.createP2PKData({ pubkey: r }, t, e, i);
    else if (n || n === 0) {
      if (!this._seed)
        throw new Error("cannot create deterministic messages without seed");
      c = K.createDeterministicData(
        t,
        this._seed,
        n,
        e,
        i
      );
    } else a ? c = K.createP2PKData(a, t, e, i) : o ? c = A(t, e.keys).map((d) => o(d, e)) : c = K.createRandomData(t, e, i);
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
  createBlankOutputs(t, e, n, r) {
    let i = Math.ceil(Math.log2(t)) || 1;
    i < 0 && (i = 0);
    const a = i ? Array(i).fill(1) : [];
    return this.createOutputData(
      a.length,
      e,
      n,
      void 0,
      a,
      void 0,
      r
    );
  }
}
class Q {
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
    const i = r || S, a = {
      "Clear-auth": `${n}`
    }, o = await i({
      endpoint: b(t, "/v1/auth/blind/mint"),
      method: "POST",
      requestBody: e,
      headers: a
    });
    if (!T(o) || !Array.isArray(o?.signatures))
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
    return Q.mint(this._mintUrl, t, e, this._customRequest);
  }
  /**
   * Get the mints public NUT-22 keys
   * @param mintUrl
   * @param keysetId optional param to get the keys for a specific keyset. If not specified, the keys from all active keysets are fetched
   * @param customRequest
   * @returns
   */
  static async getKeys(t, e, n) {
    const i = await (n || S)({
      endpoint: e ? b(t, "/v1/auth/blind/keys", e) : b(t, "/v1/auth/blind/keys")
    });
    if (!T(i) || !Array.isArray(i.keysets))
      throw new Error("bad response");
    return i;
  }
  /**
   * Get the mints public NUT-22 keys
   * @param keysetId optional param to get the keys for a specific keyset. If not specified, the keys from all active keysets are fetched
   * @returns the mints public keys
   */
  async getKeys(t, e) {
    return await Q.getKeys(
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
    return Q.getKeySets(this._mintUrl, this._customRequest);
  }
}
class Re {
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
      (r, i) => (r.input_fee_ppk ?? 0) - (i.input_fee_ppk ?? 0)
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
    const r = await this.getKeys(n?.keysetId), i = K.createRandomData(t, r), a = {
      outputs: i.map((u) => u.blindedMessage)
    }, { signatures: o } = await this.mint.mint(a, e), c = i.map((u, d) => u.toProof(o[d], r));
    if (c.some((u) => !xt(u, r)))
      throw new Error("Mint returned auth proofs with invalid DLEQ");
    return c;
  }
}
function Ne(s) {
  const t = {
    id: s.id,
    secret: s.secret,
    C: s.C
  }, e = Et(t);
  return "auth" + "A" + e;
}
async function tn(s, t, e) {
  const n = new Q(t);
  return (await new Re(n).mintProofs(s, e)).map((a) => Ne(a));
}
export {
  Q as CashuAuthMint,
  Re as CashuAuthWallet,
  E as CashuMint,
  Ze as CashuWallet,
  Ye as CheckStateEnum,
  W as HttpResponseError,
  L as MeltQuoteState,
  ut as MintOperationError,
  Z as MintQuoteState,
  ct as NetworkError,
  K as OutputData,
  ot as PaymentRequest,
  Se as PaymentRequestTransportType,
  ze as decodePaymentRequest,
  je as deriveKeysetId,
  tn as getBlindedAuthToken,
  fe as getDecodedToken,
  Je as getDecodedTokenBinary,
  Ne as getEncodedAuthToken,
  $e as getEncodedToken,
  Ge as getEncodedTokenBinary,
  le as getEncodedTokenV4,
  xt as hasValidDleq,
  Ve as injectWebSocketImpl,
  Xe as setGlobalRequestOptions
};
//# sourceMappingURL=cashu-ts.es.js.map
