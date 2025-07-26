import { secp256k1 as f } from "@noble/curves/secp256k1";
import { sha256 as a } from "@noble/hashes/sha256";
import { hexToBytes as u, bytesToHex as m } from "@noble/curves/abstract/utils";
import { hexToNumber as h, bytesToNumber as y, encodeBase64toUint8 as x } from "./util.es.js";
import { Buffer as i } from "buffer";
const g = u("536563703235366b315f48617368546f43757276655f43617368755f");
function T(t) {
  const e = a(i.concat([g, t])), n = new Uint32Array(1), c = 2 ** 16;
  for (let s = 0; s < c; s++) {
    const r = new Uint8Array(n.buffer), o = a(i.concat([e, r]));
    try {
      return p(m(i.concat([new Uint8Array([2]), o])));
    } catch {
      n[0]++;
    }
  }
  throw new Error("No valid point found");
}
function v(t) {
  const n = t.map((s) => s.toHex(!1)).join("");
  return a(new TextEncoder().encode(n));
}
function P(t) {
  return f.ProjectivePoint.fromHex(m(t));
}
function p(t) {
  return f.ProjectivePoint.fromHex(t);
}
const U = (t) => {
  let e;
  return /^[a-fA-F0-9]+$/.test(t) ? e = h(t) % BigInt(2 ** 31 - 1) : e = y(x(t)) % BigInt(2 ** 31 - 1), e;
};
function j() {
  return f.utils.randomPrivateKey();
}
function d(t) {
  const e = {};
  return Object.keys(t).forEach((n) => {
    e[n] = m(t[n]);
  }), e;
}
function K(t) {
  const e = {};
  return Object.keys(t).forEach((n) => {
    e[n] = u(t[n]);
  }), e;
}
function E(t) {
  const e = (r) => [BigInt(r[0]), r[1]], n = Object.entries(d(t)).map(e).sort((r, o) => r[0] < o[0] ? -1 : r[0] > o[0] ? 1 : 0).map(([, r]) => u(r)).reduce((r, o) => l(r, o), new Uint8Array()), c = a(n);
  return "00" + i.from(c).toString("hex").slice(0, 14);
}
function l(t, e) {
  const n = new Uint8Array(t.length + e.length);
  return n.set(t), n.set(e, t.length), n;
}
export {
  j as createRandomPrivateKey,
  E as deriveKeysetId,
  K as deserializeMintKeys,
  U as getKeysetIdInt,
  T as hashToCurve,
  v as hash_e,
  P as pointFromBytes,
  p as pointFromHex,
  d as serializeMintKeys
};
//# sourceMappingURL=common.es.js.map
