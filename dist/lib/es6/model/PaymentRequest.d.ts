import { PaymentRequestTransport, PaymentRequestTransportType } from './types';
export declare class PaymentRequest {
    transport: Array<PaymentRequestTransport>;
    id?: string | undefined;
    amount?: number | undefined;
    unit?: string | undefined;
    mints?: string[] | undefined;
    description?: string | undefined;
    private tags;
    constructor(transport: Array<PaymentRequestTransport>, id?: string | undefined, amount?: number | undefined, unit?: string | undefined, mints?: string[] | undefined, description?: string | undefined);
    toEncodedRequest(): string;
    getTransport(type: PaymentRequestTransportType): PaymentRequestTransport | undefined;
    getTag(tag: string): string | undefined;
    static fromEncodedRequest(encodedRequest: string): PaymentRequest;
}
