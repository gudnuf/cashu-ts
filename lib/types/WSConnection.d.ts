import { JsonRpcReqParams } from './model/types';
export declare class ConnectionManager {
    static instace: ConnectionManager;
    private connectionMap;
    static getInstance(): ConnectionManager;
    getConnection(url: string): WSConnection;
}
export declare class WSConnection {
    readonly url: URL;
    private readonly _WS;
    private ws;
    private connectionPromise;
    private subListeners;
    private rpcListeners;
    private messageQueue;
    private handlingInterval?;
    private rpcId;
    private manuallyClosing;
    private reconnectAttempts;
    private maxReconnectAttempts;
    private reconnectDelay;
    private maxReconnectDelay;
    private reconnectTimeout?;
    private storedSubscriptions;
    private subscriptionCallbacks;
    constructor(url: string);
    connect(): Promise<void>;
    private clearMessageHandling;
    private scheduleReconnect;
    private resubscribeAll;
    sendRequest(method: 'subscribe', params: JsonRpcReqParams): void;
    sendRequest(method: 'unsubscribe', params: {
        subId: string;
    }): void;
    closeSubscription(subId: string): void;
    addSubListener(subId: string, callback: (payload: any) => any): void;
    private addRpcListener;
    private removeRpcListener;
    private removeListener;
    ensureConnection(): Promise<void>;
    private handleNextMesage;
    createSubscription(params: Omit<JsonRpcReqParams, 'subId'>, callback: (payload: any) => any, errorCallback: (e: Error) => any): any;
    cancelSubscription(subId: string, callback: (payload: any) => any): void;
    get activeSubscriptions(): string[];
    close(): void;
    get isReconnecting(): boolean;
    get currentReconnectAttempts(): number;
    reconnect(): Promise<void>;
}
