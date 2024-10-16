"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PaymentRequest = void 0;
var base64_1 = require("../base64");
var cbor_1 = require("../cbor");
var buffer_1 = require("buffer");
var PaymentRequest = /** @class */ (function () {
    function PaymentRequest(transport, id, amount, unit, mints, description) {
        var _this = this;
        this.transport = transport;
        this.id = id;
        this.amount = amount;
        this.unit = unit;
        this.mints = mints;
        this.description = description;
        this.tags = new Map();
        this.transport.forEach(function (t) {
            if (t.tags) {
                t.tags.forEach(function (tag) {
                    if (Array.isArray(tag) && tag.length === 2) {
                        _this.tags.set(tag[0], tag[1]);
                    }
                    else {
                        throw new Error('invalid tag');
                    }
                });
            }
        });
    }
    PaymentRequest.prototype.toEncodedRequest = function () {
        var rawRequest = {
            t: this.transport.map(function (t) { return ({ t: t.type, a: t.target }); })
        };
        if (this.id) {
            rawRequest.i = this.id;
        }
        if (this.amount) {
            rawRequest.a = this.amount;
        }
        if (this.unit) {
            rawRequest.u = this.unit;
        }
        if (this.mints) {
            rawRequest.m = this.mints;
        }
        if (this.description) {
            rawRequest.d = this.description;
        }
        var data = (0, cbor_1.encodeCBOR)(rawRequest);
        var encodedData = buffer_1.Buffer.from(data).toString('base64');
        return 'creq' + 'A' + encodedData;
    };
    PaymentRequest.prototype.getTransport = function (type) {
        return this.transport.find(function (t) { return t.type === type; });
    };
    PaymentRequest.prototype.getTag = function (tag) {
        return this.tags.get(tag);
    };
    PaymentRequest.fromEncodedRequest = function (encodedRequest) {
        if (!encodedRequest.startsWith('creq')) {
            throw new Error('unsupported pr: invalid prefix');
        }
        var version = encodedRequest[4];
        if (version !== 'A') {
            throw new Error('unsupported pr version');
        }
        var encodedData = encodedRequest.slice(5);
        var data = (0, base64_1.encodeBase64toUint8)(encodedData);
        var decoded = (0, cbor_1.decodeCBOR)(data);
        var transports = decoded.t.map(function (t) { return ({ type: t.t, target: t.a, tags: t.g }); });
        return new PaymentRequest(transports, decoded.i, decoded.a, decoded.u, decoded.m, decoded.d);
    };
    return PaymentRequest;
}());
exports.PaymentRequest = PaymentRequest;
