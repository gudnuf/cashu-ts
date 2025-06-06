import { JsonRpcReqParams } from './model/types';
export declare enum ConnectionState {
    Connecting = "connecting",
    Open = "open",
    Closing = "closing",
    Closed = "closed",
    Reconnecting = "reconnecting"
}
export declare enum SocketStates {
    connecting = 0,
    open = 1,
    closing = 2,
    closed = 3
}
export type HeartbeatStatus = 'sent' | 'ok' | 'error' | 'timeout' | 'disconnected';
export type WSConnectionOptions = {
    heartbeatIntervalMs?: number;
    reconnectAfterMs?: (tries: number) => number;
    logger?: (kind: string, msg: string, data?: any) => void;
    maxReconnectAttempts?: number;
    enableHeartbeat?: boolean;
};
/**
 * Timer class for handling reconnection with exponential backoff
 */
export declare class Timer {
    callback: Function;
    timerCalc: Function;
    timer: number | undefined;
    tries: number;
    constructor(callback: Function, timerCalc: Function);
    reset(): void;
    scheduleTimeout(): void;
}
export declare class ConnectionManager {
    static instance: ConnectionManager;
    private connectionMap;
    static getInstance(): ConnectionManager;
    getConnection(url: string, options?: WSConnectionOptions): WSConnection;
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
    private reconnectTimer;
    private heartbeatTimer?;
    private heartbeatIntervalMs;
    private pendingHeartbeatRef;
    private heartbeatCallback;
    private logger;
    private maxReconnectAttempts;
    private enableHeartbeat;
    private isManualDisconnect;
    private stateChangeCallbacks;
    constructor(url: string, options?: WSConnectionOptions);
    /**
     * Add state change listener
     */
    onStateChange(event: keyof typeof this.stateChangeCallbacks, callback: Function): void;
    /**
     * Remove state change listener
     */
    offStateChange(event: keyof typeof this.stateChangeCallbacks, callback: Function): void;
    /**
     * Set heartbeat callback
     */
    onHeartbeat(callback: (status: HeartbeatStatus) => void): void;
    /**
     * Get current connection state
     */
    connectionState(): ConnectionState;
    /**
     * Check if connection is open
     */
    isConnected(): boolean;
    connect(): Promise<void>;
    /**
     * Disconnect with optional reconnection control
     */
    disconnect(permanent?: boolean): Promise<void>;
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
    /**
     * Send heartbeat message
     */
    private sendHeartbeat;
    /**
     * Generate unique reference
     */
    private makeRef;
    /**
     * Log message
     */
    private log;
    /**
     * Trigger state change callbacks
     */
    private triggerStateChange;
    /**
     * Setup WebSocket connection handlers
     */
    private setupConnection;
    /**
     * Handle connection open
     */
    private onConnOpen;
    /**
     * Handle connection close
     */
    private onConnClose;
    /**
     * Handle connection error
     */
    private onConnError;
    /**
     * Handle incoming messages
     */
    private onConnMessage;
    /**
     * Flush send buffer (for future message queuing implementation)
     */
    private flushSendBuffer;
    private handleNextMessage;
    createSubscription(params: Omit<JsonRpcReqParams, 'subId'>, callback: (payload: any) => any, errorCallback: (e: Error) => any): any;
    cancelSubscription(subId: string, callback: (payload: any) => any): void;
    get activeSubscriptions(): string[];
    /**
     * Close connection permanently
     */
    close(): void;
    /**
     * Get reconnection statistics
     */
    getReconnectionStats(): {
        attempts: number;
        maxAttempts: number;
        state: ConnectionState;
    };
}
