import { bytesToHex as P, hexToBytes as m } from "@noble/curves/abstract/utils";
import { sha256 as f } from "@noble/hashes/sha256";
import { schnorr as u } from "@noble/curves/secp256k1";
import { randomBytes as y } from "@noble/hashes/utils";
import { parseP2PKSecret as g } from "../common/NUT11.es.js";
const x = (t) => {
  const n = [
    "P2PK",
    {
      nonce: P(y(32)),
      data: t
    }
  ];
  return JSON.stringify(n);
}, p = (t, n) => {
  const s = f(t), e = u.sign(s, n);
  return P(e);
}, k = (t, n) => {
  const s = f(t), e = u.sign(s, n);
  return P(e);
}, h = (t, n, s) => {
  try {
    const e = f(n), r = s.length === 66 ? s.slice(2) : s;
    if (u.verify(t, e, m(r)))
      return !0;
  } catch (e) {
    console.error("verifyP2PKsecret error:", e);
  }
  return !1;
}, F = (t, n) => n.witness ? K(n.witness).some((e) => {
  try {
    return h(e, n.secret, t);
  } catch {
    return !1;
  }
}) : !1;
function w(t) {
  try {
    const n = typeof t == "string" ? g(t) : t;
    if (n[0] !== "P2PK")
      throw new Error('Invalid P2PK secret: must start with "P2PK"');
    const { data: s, tags: e } = n[1], r = Math.floor(Date.now() / 1e3);
    return d(n) > r ? E(n) : I(n);
  } catch {
  }
  return [];
}
function E(t) {
  const n = typeof t == "string" ? g(t) : t;
  if (n[0] !== "P2PK")
    throw new Error('Invalid P2PK secret: must start with "P2PK"');
  const { data: s, tags: e } = n[1], r = e && e.find((i) => i[0] === "pubkeys"), o = r && r.length > 1 ? r.slice(1) : [];
  return [s, ...o].filter(Boolean);
}
function I(t) {
  const n = typeof t == "string" ? g(t) : t;
  if (n[0] !== "P2PK")
    throw new Error('Invalid P2PK secret: must start with "P2PK"');
  const { tags: s } = n[1], e = s && s.find((r) => r[0] === "refund");
  return e && e.length > 1 ? e.slice(1).filter(Boolean) : [];
}
function d(t) {
  const n = typeof t == "string" ? g(t) : t;
  if (n[0] !== "P2PK")
    throw new Error('Invalid P2PK secret: must start with "P2PK"');
  const { tags: s } = n[1], e = s && s.find((r) => r[0] === "locktime");
  return e && e.length > 1 ? parseInt(e[1], 10) : 1 / 0;
}
function N(t) {
  const n = typeof t == "string" ? g(t) : t;
  if (n[0] !== "P2PK")
    throw new Error('Invalid P2PK secret: must start with "P2PK"');
  if (!w(n).length)
    return 0;
  const { tags: e } = n[1], r = Math.floor(Date.now() / 1e3);
  if (d(n) > r) {
    const c = e && e.find((a) => a[0] === "n_sigs");
    return c && c.length > 1 ? parseInt(c[1], 10) : 1;
  }
  const i = e && e.find((c) => c[0] === "n_sigs_refund");
  return i && i.length > 1 ? parseInt(i[1], 10) : 1;
}
function O(t) {
  const n = typeof t == "string" ? g(t) : t;
  if (n[0] !== "P2PK")
    throw new Error('Invalid P2PK secret: must start with "P2PK"');
  const { tags: s } = n[1], e = s && s.find((r) => r[0] === "sigflag");
  return e && e.length > 1 ? e[1] : "SIG_INPUTS";
}
const K = (t) => {
  if (!t) return [];
  if (typeof t == "string")
    try {
      return JSON.parse(t).signatures || [];
    } catch (n) {
      return console.error("Failed to parse witness string:", n), [];
    }
  return t.signatures || [];
}, W = (t, n, s = !1) => {
  const e = Array.isArray(n) ? n : [n];
  return t.map((r, o) => {
    let i = r;
    for (const c of e)
      try {
        i = T(i, c);
      } catch (a) {
        const l = a instanceof Error ? a.message : "Unknown error";
        if (s)
          throw new Error(`Failed signing proof #${o + 1}: ${l}`);
        console.warn(`Proof #${o + 1}: ${l}`);
      }
    return i;
  });
}, T = (t, n) => {
  const s = g(t.secret);
  if (s[0] !== "P2PK")
    throw new Error("not a P2PK secret");
  const e = P(u.getPublicKey(n)), r = w(s);
  if (!r.length || !r.some((a) => a.includes(e)))
    throw new Error(`Signature not required from [02|03]${e}`);
  const o = K(t.witness);
  if (o.some((a) => {
    try {
      return h(a, t.secret, e);
    } catch {
      return !1;
    }
  }))
    throw new Error(`Proof already signed by [02|03]${e}`);
  const c = p(t.secret, n);
  return o.push(c), { ...t, witness: { signatures: o } };
}, _ = (t, n) => {
  const s = t.B_.toHex(!0), e = k(s, n);
  return t.witness = { signatures: [e] }, t;
}, H = (t, n) => t.map((s) => _(s, n));
export {
  x as createP2PKsecret,
  w as getP2PKExpectedKWitnessPubkeys,
  d as getP2PKLocktime,
  N as getP2PKNSigs,
  O as getP2PKSigFlag,
  E as getP2PKWitnessPubkeys,
  I as getP2PKWitnessRefundkeys,
  K as getP2PKWitnessSignatures,
  _ as getSignedOutput,
  H as getSignedOutputs,
  F as hasP2PKSignedProof,
  k as signBlindedMessage,
  T as signP2PKProof,
  W as signP2PKProofs,
  p as signP2PKSecret,
  h as verifyP2PKSecretSignature
};
//# sourceMappingURL=NUT11.es.js.map
