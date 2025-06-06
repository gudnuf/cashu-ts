import { MessageQueue } from './utils';
import {
	JsonRpcErrorObject,
	JsonRpcMessage,
	JsonRpcNotification,
	JsonRpcReqParams,
	RpcSubId
} from './model/types';
import { OnOpenError, OnOpenSuccess } from './model/types/wallet/websocket';
import { getWebSocketImpl } from './ws';

// Connection states
export enum ConnectionState {
	Connecting = 'connecting',
	Open = 'open',
	Closing = 'closing',
	Closed = 'closed',
	Reconnecting = 'reconnecting'
}

// WebSocket ready states
export enum SocketStates {
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
export class Timer {
	timer: number | undefined = undefined;
	tries: number = 0;

	constructor(
		public callback: Function, 
		public timerCalc: Function
	) {}

	reset() {
		this.tries = 0;
		clearTimeout(this.timer);
	}

	scheduleTimeout() {
		clearTimeout(this.timer);
		this.timer = setTimeout(() => {
			this.tries = this.tries + 1;
			this.callback();
		}, this.timerCalc(this.tries + 1)) as unknown as number;
	}
}

export class ConnectionManager {
	static instance: ConnectionManager;
	private connectionMap: Map<string, WSConnection> = new Map();

	static getInstance() {
		if (!ConnectionManager.instance) {
			ConnectionManager.instance = new ConnectionManager();
		}
		return ConnectionManager.instance;
	}

	getConnection(url: string, options?: WSConnectionOptions): WSConnection {
		if (this.connectionMap.has(url)) {
			return this.connectionMap.get(url) as WSConnection;
		}
		const newConn = new WSConnection(url, options);
		this.connectionMap.set(url, newConn);
		return newConn;
	}
}

export class WSConnection {
	public readonly url: URL;
	private readonly _WS: typeof WebSocket;
	private ws: WebSocket | undefined;
	private connectionPromise: Promise<void> | undefined;
	private subListeners: { [subId: string]: Array<(payload: any) => any> } = {};
	private rpcListeners: { [rpcSubId: string]: any } = {};
	private messageQueue: MessageQueue;
	private handlingInterval?: number;
	private rpcId = 0;

	// Reconnection properties
	private reconnectTimer: Timer;
	private heartbeatTimer?: number;
	private heartbeatIntervalMs: number = 30000; // 30 seconds
	private pendingHeartbeatRef: string | null = null;
	private heartbeatCallback: (status: HeartbeatStatus) => void = () => {};
	private logger: (kind: string, msg: string, data?: any) => void = () => {};
	private maxReconnectAttempts: number = Infinity;
	private enableHeartbeat: boolean = true;
	private isManualDisconnect: boolean = false;

	// State change callbacks
	private stateChangeCallbacks: {
		open: Function[];
		close: Function[];
		error: Function[];
		message: Function[];
		reconnecting: Function[];
	} = {
		open: [],
		close: [],
		error: [],
		message: [],
		reconnecting: []
	};

	constructor(url: string, options?: WSConnectionOptions) {
		this._WS = getWebSocketImpl();
		this.url = new URL(url);
		this.messageQueue = new MessageQueue();

		// Configure options
		if (options?.heartbeatIntervalMs) {
			this.heartbeatIntervalMs = options.heartbeatIntervalMs;
		}
		if (options?.logger) {
			this.logger = options.logger;
		}
		if (options?.maxReconnectAttempts !== undefined) {
			this.maxReconnectAttempts = options.maxReconnectAttempts;
		}
		if (options?.enableHeartbeat !== undefined) {
			this.enableHeartbeat = options.enableHeartbeat;
		}

		// Set up reconnection timer with exponential backoff
		const reconnectAfterMs = options?.reconnectAfterMs || ((tries: number) => {
			return [1000, 2000, 5000, 10000][tries - 1] || 10000;
		});

		this.reconnectTimer = new Timer(async () => {
			this.log('reconnection', 'Attempting to reconnect...');
			this.triggerStateChange('reconnecting');
			await this.disconnect(false); // Don't mark as manual disconnect
			await this.connect();
		}, reconnectAfterMs);
	}

	/**
	 * Add state change listener
	 */
	onStateChange(event: keyof typeof this.stateChangeCallbacks, callback: Function) {
		this.stateChangeCallbacks[event].push(callback);
	}

	/**
	 * Remove state change listener
	 */
	offStateChange(event: keyof typeof this.stateChangeCallbacks, callback: Function) {
		const index = this.stateChangeCallbacks[event].indexOf(callback);
		if (index > -1) {
			this.stateChangeCallbacks[event].splice(index, 1);
		}
	}

	/**
	 * Set heartbeat callback
	 */
	onHeartbeat(callback: (status: HeartbeatStatus) => void): void {
		this.heartbeatCallback = callback;
	}

	/**
	 * Get current connection state
	 */
	connectionState(): ConnectionState {
		if (!this.ws) {
			return this.reconnectTimer.tries > 0 ? ConnectionState.Reconnecting : ConnectionState.Closed;
		}

		switch (this.ws.readyState) {
			case SocketStates.connecting:
				return ConnectionState.Connecting;
			case SocketStates.open:
				return ConnectionState.Open;
			case SocketStates.closing:
				return ConnectionState.Closing;
			default:
				return ConnectionState.Closed;
		}
	}

	/**
	 * Check if connection is open
	 */
	isConnected(): boolean {
		return this.connectionState() === ConnectionState.Open;
	}

	async connect(): Promise<void> {
		if (!this.connectionPromise) {
			this.isManualDisconnect = false;
			this.connectionPromise = new Promise((res: OnOpenSuccess, rej: OnOpenError) => {
				try {
					this.ws = new this._WS(this.url.toString());
				} catch (err) {
					rej(err);
					return;
				}

				this.setupConnection();

				this.ws.onopen = () => {
					this.log('transport', `Connected to ${this.url.toString()}`);
					this.onConnOpen();
					res();
				};

				this.ws.onerror = (error) => {
					this.log('transport', 'Connection error', error);
					this.onConnError(error);
					rej(new Error('Failed to open WebSocket'));
				};

				this.ws.onmessage = (e: MessageEvent) => {
					this.onConnMessage(e);
				};

				this.ws.onclose = (event) => {
					this.log('transport', 'Connection closed', event);
					this.onConnClose(event);
				};
			});
		}
		return this.connectionPromise;
	}

	/**
	 * Disconnect with optional reconnection control
	 */
	async disconnect(permanent: boolean = true): Promise<void> {
		this.isManualDisconnect = permanent;
		
		if (this.ws) {
			this.ws.onclose = () => {}; // Prevent triggering reconnection logic
			this.ws.close();
			this.ws = undefined;
		}

		// Clear timers
		if (this.heartbeatTimer) {
			clearInterval(this.heartbeatTimer);
			this.heartbeatTimer = undefined;
		}

		if (permanent) {
			this.reconnectTimer.reset();
		}

		this.connectionPromise = undefined;
	}

	sendRequest(method: 'subscribe', params: JsonRpcReqParams): void;
	sendRequest(method: 'unsubscribe', params: { subId: string }): void;
	sendRequest(method: 'subscribe' | 'unsubscribe', params: Partial<JsonRpcReqParams>) {
		if (!this.isConnected()) {
			throw new Error('Socket not open...');
		}
		const id = this.rpcId;
		this.rpcId++;
		const message = JSON.stringify({ jsonrpc: '2.0', method, params, id });
		this.ws?.send(message);
	}

	closeSubscription(subId: string) {
		this.ws?.send(JSON.stringify(['CLOSE', subId]));
	}

	addSubListener(subId: string, callback: (payload: any) => any) {
		(this.subListeners[subId] = this.subListeners[subId] || []).push(callback);
	}

	private addRpcListener(
		callback: () => any,
		errorCallback: (e: JsonRpcErrorObject) => any,
		id: Exclude<RpcSubId, null>
	) {
		this.rpcListeners[id] = { callback, errorCallback };
	}

	private removeRpcListener(id: Exclude<RpcSubId, null>) {
		delete this.rpcListeners[id];
	}

	private removeListener(subId: string, callback: (payload: any) => any) {
		if (!this.subListeners[subId]) {
			return;
		}
		if (this.subListeners[subId].length === 1) {
			delete this.subListeners[subId];
			return;
		}
		this.subListeners[subId] = this.subListeners[subId].filter((fn: any) => fn !== callback);
	}

	async ensureConnection() {
		if (!this.isConnected()) {
			await this.connect();
		}
	}

	/**
	 * Send heartbeat message
	 */
	private sendHeartbeat() {
		if (!this.isConnected()) {
			this.heartbeatCallback('disconnected');
			return;
		}

		if (this.pendingHeartbeatRef) {
			this.pendingHeartbeatRef = null;
			this.log('transport', 'Heartbeat timeout. Attempting to re-establish connection');
			this.heartbeatCallback('timeout');
			this.ws?.close(1000, 'heartbeat timeout');
			return;
		}

		this.pendingHeartbeatRef = this.makeRef();
		// Send a simple ping message or custom heartbeat
		try {
			this.ws?.send(JSON.stringify({ 
				type: 'heartbeat', 
				ref: this.pendingHeartbeatRef 
			}));
			this.heartbeatCallback('sent');
		} catch (error) {
			this.log('transport', 'Failed to send heartbeat', error);
			this.heartbeatCallback('error');
		}
	}

	/**
	 * Generate unique reference
	 */
	private makeRef(): string {
		return Math.random().toString(36).substring(2, 15);
	}

	/**
	 * Log message
	 */
	private log(kind: string, msg: string, data?: any) {
		this.logger ? this.logger(kind, msg, data) : console.log(`[${kind}] ${msg}`, data);
	}

	/**
	 * Trigger state change callbacks
	 */
	private triggerStateChange(event: keyof typeof this.stateChangeCallbacks, data?: any) {
		this.stateChangeCallbacks[event].forEach(callback => callback(data));
	}

	/**
	 * Setup WebSocket connection handlers
	 */
	private setupConnection(): void {
		// This method is called after WebSocket is created
		// Additional setup can be done here if needed
	}

	/**
	 * Handle connection open
	 */
	private onConnOpen() {
		this.flushSendBuffer();
		this.reconnectTimer.reset();
		
		// Start heartbeat if enabled
		if (this.enableHeartbeat) {
			if (this.heartbeatTimer) {
				clearInterval(this.heartbeatTimer);
			}
			this.heartbeatTimer = setInterval(() => {
				this.sendHeartbeat();
			}, this.heartbeatIntervalMs) as unknown as number;
		}

		this.triggerStateChange('open');
	}

	/**
	 * Handle connection close
	 */
	private onConnClose(event: CloseEvent) {
		this.connectionPromise = undefined;
		
		// Clear heartbeat timer
		if (this.heartbeatTimer) {
			clearInterval(this.heartbeatTimer);
			this.heartbeatTimer = undefined;
		}

		this.triggerStateChange('close', event);

		// Attempt reconnection if not a manual disconnect and within retry limits
		if (!this.isManualDisconnect && this.reconnectTimer.tries < this.maxReconnectAttempts) {
			this.log('transport', `Connection lost. Scheduling reconnection attempt ${this.reconnectTimer.tries + 1}`);
			this.reconnectTimer.scheduleTimeout();
		} else if (this.reconnectTimer.tries >= this.maxReconnectAttempts) {
			this.log('transport', 'Max reconnection attempts reached. Giving up.');
		}
	}

	/**
	 * Handle connection error
	 */
	private onConnError(error: Event) {
		this.triggerStateChange('error', error);
	}

	/**
	 * Handle incoming messages
	 */
	private onConnMessage(e: MessageEvent) {
		// Check for heartbeat response
		try {
			const parsed = JSON.parse(e.data);
			if (parsed.type === 'heartbeat' && parsed.ref === this.pendingHeartbeatRef) {
				this.pendingHeartbeatRef = null;
				this.heartbeatCallback('ok');
				return;
			}
		} catch {
			// Not a JSON message, continue with normal processing
		}

		this.messageQueue.enqueue(e.data);
		if (!this.handlingInterval) {
			this.handlingInterval = setInterval(
				this.handleNextMessage.bind(this),
				0
			) as unknown as number;
		}

		this.triggerStateChange('message', e);
	}

	/**
	 * Flush send buffer (for future message queuing implementation)
	 */
	private flushSendBuffer() {
		// Implementation for message queuing during disconnection
		// This would store messages and send them once reconnected
	}

	private handleNextMessage() {
		if (this.messageQueue.size === 0) {
			clearInterval(this.handlingInterval);
			this.handlingInterval = undefined;
			return;
		}
		const message = this.messageQueue.dequeue() as string;
		let parsed;
		try {
			parsed = JSON.parse(message) as JsonRpcMessage;
			if ('result' in parsed && parsed.id != undefined) {
				if (this.rpcListeners[parsed.id]) {
					this.rpcListeners[parsed.id].callback();
					this.removeRpcListener(parsed.id);
				}
			} else if ('error' in parsed && parsed.id != undefined) {
				if (this.rpcListeners[parsed.id]) {
					this.rpcListeners[parsed.id].errorCallback(parsed.error);
					this.removeRpcListener(parsed.id);
				}
			} else if ('method' in parsed) {
				if ('id' in parsed) {
					// Do nothing as mints should not send requests
				} else {
					const subId = parsed.params.subId;
					if (!subId) {
						return;
					}
					if (this.subListeners[subId]?.length > 0) {
						const notification = parsed as JsonRpcNotification;
						this.subListeners[subId].forEach((cb) => cb(notification.params.payload));
					}
				}
			}
		} catch (e) {
			console.error(e);
			return;
		}
	}

	createSubscription(
		params: Omit<JsonRpcReqParams, 'subId'>,
		callback: (payload: any) => any,
		errorCallback: (e: Error) => any
	) {
		if (!this.isConnected()) {
			return errorCallback(new Error('Socket is not open'));
		}
		const subId = (Math.random() + 1).toString(36).substring(7);
		this.addRpcListener(
			() => {
				this.addSubListener(subId, callback);
			},
			(e: JsonRpcErrorObject) => {
				errorCallback(new Error(e.message));
			},
			this.rpcId
		);
		this.sendRequest('subscribe', { ...params, subId });
		this.rpcId++;
		return subId;
	}

	cancelSubscription(subId: string, callback: (payload: any) => any) {
		this.removeRpcListener(subId);
		this.removeListener(subId, callback);
		this.rpcId++;
		this.sendRequest('unsubscribe', { subId });
	}

	get activeSubscriptions() {
		return Object.keys(this.subListeners);
	}

	/**
	 * Close connection permanently
	 */
	close() {
		this.disconnect(true);
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