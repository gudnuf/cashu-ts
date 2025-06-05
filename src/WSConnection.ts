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

export class ConnectionManager {
	static instace: ConnectionManager;
	private connectionMap: Map<string, WSConnection> = new Map();

	static getInstance() {
		if (!ConnectionManager.instace) {
			ConnectionManager.instace = new ConnectionManager();
		}
		return ConnectionManager.instace;
	}

	getConnection(url: string): WSConnection {
		if (this.connectionMap.has(url)) {
			return this.connectionMap.get(url) as WSConnection;
		}
		const newConn = new WSConnection(url);
		this.connectionMap.set(url, newConn);
		return newConn;
	}
}

interface StoredSubscription {
	params: JsonRpcReqParams;
	callback: (payload: any) => any;
	errorCallback: (e: Error) => any;
	originalSubId: string;
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

	// Reconnection-related properties
	private manuallyClosing = false;
	private reconnectAttempts = 0;
	private maxReconnectAttempts = 5;
	private reconnectDelay = 1000; // Start with 1 second
	private maxReconnectDelay = 30000; // Max 30 seconds
	private reconnectTimeout?: number;
	private storedSubscriptions: Map<string, StoredSubscription> = new Map();
	private subscriptionCallbacks: { [subId: string]: (payload: any) => any } = {};

	constructor(url: string) {
		this._WS = getWebSocketImpl();
		this.url = new URL(url);
		this.messageQueue = new MessageQueue();
	}

	connect() {
		if (!this.connectionPromise) {
			this.connectionPromise = new Promise((res: OnOpenSuccess, rej: OnOpenError) => {
				try {
					this.ws = new this._WS(this.url.toString());
				} catch (err) {
					rej(err);
					return;
				}
				this.ws.onopen = () => {
					this.reconnectAttempts = 0; // Reset reconnect attempts on successful connection
					this.resubscribeAll(); // Re-establish all subscriptions
					res();
				};
				this.ws.onerror = () => {
					rej(new Error('Failed to open WebSocket'));
				};
				this.ws.onmessage = (e: MessageEvent) => {
					this.messageQueue.enqueue(e.data);
					if (!this.handlingInterval) {
						this.handlingInterval = setInterval(
							this.handleNextMesage.bind(this),
							0
						) as unknown as number;
					}
				};
				this.ws.onclose = (event: CloseEvent) => {
					this.connectionPromise = undefined;
					this.clearMessageHandling();

					// Only attempt reconnection if not manually closing
					if (!this.manuallyClosing) {
						this.scheduleReconnect();
					}
				};
			});
		}
		return this.connectionPromise;
	}

	private clearMessageHandling() {
		if (this.handlingInterval) {
			clearInterval(this.handlingInterval);
			this.handlingInterval = undefined;
		}
	}

	private scheduleReconnect() {
		if (this.reconnectAttempts >= this.maxReconnectAttempts) {
			console.error(
				`WSConnection: Max reconnection attempts (${this.maxReconnectAttempts}) reached for ${this.url}`
			);
			return;
		}

		const delay = Math.min(
			this.reconnectDelay * Math.pow(2, this.reconnectAttempts),
			this.maxReconnectDelay
		);

		this.reconnectTimeout = setTimeout(() => {
			this.reconnectAttempts++;
			console.log(
				`cashu-ts WSConnection: Attempting reconnection ${this.reconnectAttempts}/${this.maxReconnectAttempts} to ${this.url}`
			);
			this.connect().catch((error) => {
				console.error('WSConnection: Reconnection failed:', error);
				// The onclose handler will schedule the next attempt
			});
		}, delay) as unknown as number;
	}

	private resubscribeAll() {
		// Re-establish all stored subscriptions
		for (const [originalSubId, subscription] of this.storedSubscriptions) {
			try {
				// Send subscription request directly without storing it again
				this.addRpcListener(
					() => {
						// Use the original subId to maintain client mapping
						this.addSubListener(originalSubId, subscription.callback);
					},
					(e: JsonRpcErrorObject) => {
						console.error('WSConnection: Failed to resubscribe:', e);
						subscription.errorCallback(new Error(e.message));
						// Remove failed subscription
						this.storedSubscriptions.delete(originalSubId);
					},
					this.rpcId
				);

				// Send the subscription request with the original subId
				this.sendRequest('subscribe', subscription.params);
				this.rpcId++;
			} catch (error) {
				console.error('WSConnection: Failed to resubscribe:', error);
				subscription.errorCallback(new Error('Failed to resubscribe after reconnection'));
				// Remove failed subscription
				this.storedSubscriptions.delete(originalSubId);
			}
		}
	}

	sendRequest(method: 'subscribe', params: JsonRpcReqParams): void;
	sendRequest(method: 'unsubscribe', params: { subId: string }): void;
	sendRequest(method: 'subscribe' | 'unsubscribe', params: Partial<JsonRpcReqParams>) {
		if (this.ws?.readyState !== 1) {
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

	//TODO: Move to RPCManagerClass
	private addRpcListener(
		callback: () => any,
		errorCallback: (e: JsonRpcErrorObject) => any,
		id: Exclude<RpcSubId, null>
	) {
		this.rpcListeners[id] = { callback, errorCallback };
	}

	//TODO: Move to RPCManagerClass
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
		if (this.ws?.readyState !== 1) {
			await this.connect();
		}
	}

	private handleNextMesage() {
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
		if (this.ws?.readyState !== 1) {
			return errorCallback(new Error('Socket is not open'));
		}
		const subId = (Math.random() + 1).toString(36).substring(7);

		// Store subscription for reconnection
		this.storedSubscriptions.set(subId, {
			params: { ...params, subId },
			callback,
			errorCallback,
			originalSubId: subId
		});

		this.addRpcListener(
			() => {
				this.addSubListener(subId, callback);
			},
			(e: JsonRpcErrorObject) => {
				// Remove from stored subscriptions if it fails
				this.storedSubscriptions.delete(subId);
				errorCallback(new Error(e.message));
			},
			this.rpcId
		);
		this.sendRequest('subscribe', { ...params, subId });
		this.rpcId++;
		return subId;
	}

	cancelSubscription(subId: string, callback: (payload: any) => any) {
		// Remove from stored subscriptions
		this.storedSubscriptions.delete(subId);

		this.removeRpcListener(subId);
		this.removeListener(subId, callback);
		this.rpcId++;
		this.sendRequest('unsubscribe', { subId });
	}

	get activeSubscriptions() {
		return Object.keys(this.subListeners);
	}

	close() {
		this.manuallyClosing = true;

		// Clear any pending reconnection attempts
		if (this.reconnectTimeout) {
			clearTimeout(this.reconnectTimeout);
			this.reconnectTimeout = undefined;
		}

		// Clear stored subscriptions since we're manually closing
		this.storedSubscriptions.clear();

		if (this.ws) {
			this.ws?.close();
		}
	}

	// Method to check if connection is attempting to reconnect
	get isReconnecting(): boolean {
		return this.reconnectTimeout !== undefined;
	}

	// Method to get current reconnection attempt count
	get currentReconnectAttempts(): number {
		return this.reconnectAttempts;
	}

	// Method to manually trigger reconnection (useful for testing or manual recovery)
	reconnect(): Promise<void> {
		if (this.manuallyClosing) {
			throw new Error('Cannot reconnect: connection was manually closed');
		}

		// Reset reconnection state
		this.reconnectAttempts = 0;
		if (this.reconnectTimeout) {
			clearTimeout(this.reconnectTimeout);
			this.reconnectTimeout = undefined;
		}

		// Close existing connection if any
		if (this.ws && this.ws.readyState !== WebSocket.CLOSED) {
			this.ws.close();
		}

		// Clear connection promise to force new connection
		this.connectionPromise = undefined;

		return this.connect();
	}
}
