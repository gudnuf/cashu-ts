import { PaymentRequestTransport, PaymentRequestTransportType } from './types';
export declare class PaymentRequest {
    transport: Array<PaymentRequestTransport>;
    id?: string;
    amount?: number;
    unit?: string;
    mints?: Array<string>;
    description?: string;
    private tags;
    constructor(transport: Array<PaymentRequestTransport>, id?: string, amount?: number, unit?: string, mints?: Array<string>, description?: string);
    toEncodedRequest(): string;
    getTransport(type: PaymentRequestTransportType): PaymentRequestTransport;
    getTag(tag: string): string;
    static fromEncodedRequest(encodedRequest: string): PaymentRequest;
}
