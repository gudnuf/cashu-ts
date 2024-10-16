import { encodeBase64ToJson, encodeBase64toUint8, encodeJsonToBase64, encodeUint8toBase64Url } from './base64.js';
import { TOKEN_PREFIX, TOKEN_VERSION } from './utils/Constants.js';
import { bytesToHex, hexToBytes } from '@noble/curves/abstract/utils';
import { sha256 } from '@noble/hashes/sha256';
import { decodeCBOR, encodeCBOR } from './cbor.js';
import { PaymentRequest } from './model/PaymentRequest.js';
function splitAmount(value, keyset, amountPreference, isDesc) {
    var chunks = [];
    if (amountPreference) {
        chunks.push.apply(chunks, getPreference(value, keyset, amountPreference));
        value =
            value -
                chunks.reduce(function (curr, acc) {
                    return curr + acc;
                }, 0);
    }
    var sortedKeyAmounts = Object.keys(keyset)
        .map(function (k) { return parseInt(k); })
        .sort(function (a, b) { return b - a; });
    sortedKeyAmounts.forEach(function (amt) {
        var q = Math.floor(value / amt);
        for (var i = 0; i < q; ++i)
            chunks.push(amt);
        value %= amt;
    });
    return chunks.sort(function (a, b) { return (isDesc ? b - a : a - b); });
}
/*
function isPowerOfTwo(number: number) {
    return number && !(number & (number - 1));
}
*/
function hasCorrespondingKey(amount, keyset) {
    return amount in keyset;
}
function getPreference(amount, keyset, preferredAmounts) {
    var chunks = [];
    var accumulator = 0;
    preferredAmounts.forEach(function (pa) {
        if (!hasCorrespondingKey(pa.amount, keyset)) {
            throw new Error('Provided amount preferences do not match the amounts of the mint keyset.');
        }
        for (var i = 1; i <= pa.count; i++) {
            accumulator += pa.amount;
            if (accumulator > amount) {
                return;
            }
            chunks.push(pa.amount);
        }
    });
    return chunks;
}
function getDefaultAmountPreference(amount, keyset) {
    var amounts = splitAmount(amount, keyset);
    return amounts.map(function (a) {
        return { amount: a, count: 1 };
    });
}
function bytesToNumber(bytes) {
    return hexToNumber(bytesToHex(bytes));
}
function hexToNumber(hex) {
    return BigInt("0x".concat(hex));
}
//used for json serialization
function bigIntStringify(_key, value) {
    return typeof value === 'bigint' ? value.toString() : value;
}
/**
 * Helper function to encode a v3 cashu token
 * @param token
 * @returns
 */
function getEncodedToken(token) {
    return TOKEN_PREFIX + TOKEN_VERSION + encodeJsonToBase64(token);
}
function getEncodedTokenV4(token) {
    var idMap = {};
    var mint = undefined;
    for (var i = 0; i < token.token.length; i++) {
        if (!mint) {
            mint = token.token[i].mint;
        }
        else {
            if (mint !== token.token[i].mint) {
                throw new Error('Multimint token can not be encoded as V4 token');
            }
        }
        for (var j = 0; j < token.token[i].proofs.length; j++) {
            var proof = token.token[i].proofs[j];
            if (idMap[proof.id]) {
                idMap[proof.id].push(proof);
            }
            else {
                idMap[proof.id] = [proof];
            }
        }
    }
    var tokenTemplate = {
        m: mint,
        u: token.unit || 'sat',
        t: Object.keys(idMap).map(function (id) { return ({
            i: hexToBytes(id),
            p: idMap[id].map(function (p) { return ({ a: p.amount, s: p.secret, c: hexToBytes(p.C) }); })
        }); })
    };
    if (token.memo) {
        tokenTemplate.d = token.memo;
    }
    var encodedData = encodeCBOR(tokenTemplate);
    var prefix = 'cashu';
    var version = 'B';
    var base64Data = encodeUint8toBase64Url(encodedData);
    return prefix + version + base64Data;
}
/**
 * Helper function to decode cashu tokens into object
 * @param token an encoded cashu token (cashuAey...)
 * @returns cashu token object
 */
function getDecodedToken(token) {
    // remove prefixes
    var uriPrefixes = ['web+cashu://', 'cashu://', 'cashu:', 'cashu'];
    uriPrefixes.forEach(function (prefix) {
        if (!token.startsWith(prefix)) {
            return;
        }
        token = token.slice(prefix.length);
    });
    return handleTokens(token);
}
/**
 * @param token
 * @returns
 */
function handleTokens(token) {
    var version = token.slice(0, 1);
    var encodedToken = token.slice(1);
    if (version === 'A') {
        return encodeBase64ToJson(encodedToken);
    }
    else if (version === 'B') {
        var uInt8Token = encodeBase64toUint8(encodedToken);
        var tokenData = decodeCBOR(uInt8Token);
        var mergedTokenEntry_1 = { mint: tokenData.m, proofs: [] };
        tokenData.t.forEach(function (tokenEntry) {
            return tokenEntry.p.forEach(function (p) {
                mergedTokenEntry_1.proofs.push({
                    secret: p.s,
                    C: bytesToHex(p.c),
                    amount: p.a,
                    id: bytesToHex(tokenEntry.i)
                });
            });
        });
        return { token: [mergedTokenEntry_1], memo: tokenData.d || '', unit: tokenData.u || 'sat' };
    }
    throw new Error('Token version is not supported');
}
/**
 * Returns the keyset id of a set of keys
 * @param keys keys object to derive keyset id from
 * @returns
 */
export function deriveKeysetId(keys) {
    var pubkeysConcat = Object.entries(keys)
        .sort(function (a, b) { return +a[0] - +b[0]; })
        .map(function (_a) {
        var pubKey = _a[1];
        return hexToBytes(pubKey);
    })
        .reduce(function (prev, curr) { return mergeUInt8Arrays(prev, curr); }, new Uint8Array());
    var hash = sha256(pubkeysConcat);
    var hashHex = Buffer.from(hash).toString('hex').slice(0, 14);
    return '00' + hashHex;
}
function mergeUInt8Arrays(a1, a2) {
    // sum of individual array lengths
    var mergedArray = new Uint8Array(a1.length + a2.length);
    mergedArray.set(a1);
    mergedArray.set(a2, a1.length);
    return mergedArray;
}
export function sortProofsById(proofs) {
    return proofs.sort(function (a, b) { return a.id.localeCompare(b.id); });
}
export function isObj(v) {
    return typeof v === 'object';
}
export function checkResponse(data) {
    if (!isObj(data))
        return;
    if ('error' in data && data.error) {
        throw new Error(data.error);
    }
    if ('detail' in data && data.detail) {
        throw new Error(data.detail);
    }
}
export function joinUrls() {
    var parts = [];
    for (var _i = 0; _i < arguments.length; _i++) {
        parts[_i] = arguments[_i];
    }
    return parts.map(function (part) { return part.replace(/(^\/+|\/+$)/g, ''); }).join('/');
}
export function sanitizeUrl(url) {
    return url.replace(/\/$/, '');
}
function decodePaymentRequest(paymentRequest) {
    if (!paymentRequest.startsWith('creq')) {
        throw new Error('unsupported pr: invalid prefix');
    }
    var version = paymentRequest[4];
    if (version !== 'A') {
        throw new Error('unsupported pr version');
    }
    var encodedData = paymentRequest.slice(5);
    var data = encodeBase64toUint8(encodedData);
    var decoded = decodeCBOR(data);
    var transports = decoded.t.map(function (t) { return ({ type: t.t, target: t.a, tags: t.g }); });
    return new PaymentRequest(transports, decoded.i, decoded.a, decoded.u, decoded.m, decoded.d);
}
export { bigIntStringify, bytesToNumber, getDecodedToken, getEncodedToken, getEncodedTokenV4, hexToNumber, splitAmount, getDefaultAmountPreference, decodePaymentRequest };
//# sourceMappingURL=utils.js.map