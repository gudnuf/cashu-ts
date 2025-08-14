import { hmac as h } from "@noble/hashes/hmac";
import { sha512 as v } from "@noble/hashes/sha2";
import { getKeysetIdInt as l } from "../common.es.js";
import { HDKey as p } from "@scure/bip32";
import { Buffer as o } from "buffer";
const u = "m/129372'/0'", B = (t, r, e) => {
  if (r.startsWith("00"))
    return f(
      t,
      r,
      e,
      0
      /* SECRET */
    );
  if (r.startsWith("01"))
    return m(
      t,
      r,
      e,
      0
      /* SECRET */
    );
  throw new Error(`Unrecognized keyset ID version ${r.slice(0, 2)}`);
}, _ = (t, r, e) => {
  if (r.startsWith("00"))
    return f(
      t,
      r,
      e,
      1
      /* BLINDING_FACTOR */
    );
  if (r.startsWith("01"))
    return m(
      t,
      r,
      e,
      1
      /* BLINDING_FACTOR */
    );
  throw new Error(`Unrecognized keyset ID version ${r.slice(0, 2)}`);
}, m = (t, r, e, c) => {
  const n = o.alloc(8);
  n.writeBigUInt64BE(BigInt(e));
  let i = o.concat([
    o.from("Cashu_KDF_HMAC_SHA512"),
    o.from(r, "hex"),
    n
  ]);
  switch (c) {
    case 0:
      i = o.concat([i, o.from([0])]);
      break;
    case 1:
      i = o.concat([i, o.from([1])]);
  }
  return h(v, t, i).slice(0, 32);
}, f = (t, r, e, c) => {
  const n = p.fromMasterSeed(t), i = l(r), s = `${u}/${i}'/${e}'/${c}`, a = n.derive(s);
  if (a.privateKey === null)
    throw new Error("Could not derive private key");
  return a.privateKey;
};
export {
  _ as deriveBlindingFactor,
  B as deriveSecret
};
//# sourceMappingURL=NUT09.es.js.map
