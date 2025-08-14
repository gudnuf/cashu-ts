import { WSConnection } from './WSConnection.js';
import { CheckStatePayload, CheckStateResponse, GetInfoResponse, MeltPayload, MintActiveKeys, MintAllKeysets, PostRestoreResponse, SerializedBlindedMessage, SwapPayload, SwapResponse, MintQuotePayload, MintPayload, MintResponse, PostRestorePayload, MeltQuotePayload, PartialMintQuoteResponse, PartialMeltQuoteResponse, Bolt12MintQuotePayload, Bolt12MintQuoteResponse, Bolt12MeltQuoteResponse, OnchainMintQuotePayload, OnchainMintQuoteResponse, OnchainMeltQuotePayload, OnchainMeltQuoteResponse } from './model/types/index.js';
import { default as request } from './request.js';
import { MintInfo } from './model/MintInfo.js';
import { Logger } from './logger.js';
/**
 * Class represents Cashu Mint API. This class contains Lower level functions that are implemented
 * by CashuWallet.
 */
declare class CashuMint {
    private _mintUrl;
    private _customRequest?;
    private ws?;
    private _mintInfo?;
    private _authTokenGetter?;
    private _checkNut22;
    private _logger;
    /**
     * @param _mintUrl Requires mint URL to create this object.
     * @param _customRequest If passed, use custom request implementation for network communication
     *   with the mint.
     * @param [authTokenGetter] A function that is called by the CashuMint instance to obtain a NUT-22
     *   BlindedAuthToken (e.g. from a database or localstorage)
     */
    constructor(_mintUrl: string, _customRequest?: typeof request | undefined, authTokenGetter?: () => Promise<string>, options?: {
        logger?: Logger;
    });
    get mintUrl(): string;
    /**
     * Fetches mints info at the /info endpoint.
     *
     * @param mintUrl
     * @param customRequest
     */
    static getInfo(mintUrl: string, customRequest?: typeof request, logger?: Logger): Promise<GetInfoResponse>;
    /**
     * Fetches mints info at the /info endpoint.
     */
    getInfo(): Promise<GetInfoResponse>;
    getLazyMintInfo(): Promise<MintInfo>;
    /**
     * Performs a swap operation with ecash inputs and outputs.
     *
     * @param mintUrl
     * @param swapPayload Payload containing inputs and outputs.
     * @param customRequest
     * @returns Signed outputs.
     */
    static swap(mintUrl: string, swapPayload: SwapPayload, customRequest?: typeof request, blindAuthToken?: string): Promise<SwapResponse>;
    /**
     * Performs a swap operation with ecash inputs and outputs.
     *
     * @param swapPayload Payload containing inputs and outputs.
     * @returns Signed outputs.
     */
    swap(swapPayload: SwapPayload): Promise<SwapResponse>;
    /**
     * Requests a new mint quote from the mint.
     *
     * @param mintUrl
     * @param mintQuotePayload Payload for creating a new mint quote.
     * @param customRequest
     * @returns The mint will create and return a new mint quote containing a payment request for the
     *   specified amount and unit.
     */
    static createMintQuote(mintUrl: string, mintQuotePayload: MintQuotePayload, customRequest?: typeof request, blindAuthToken?: string, logger?: Logger): Promise<PartialMintQuoteResponse>;
    /**
     * Requests a new mint quote from the mint.
     *
     * @param mintQuotePayload Payload for creating a new mint quote.
     * @returns The mint will create and return a new mint quote containing a payment request for the
     *   specified amount and unit.
     */
    createMintQuote(mintQuotePayload: MintQuotePayload): Promise<PartialMintQuoteResponse>;
    /**
     * Requests a new BOLT12 mint quote from the mint using Lightning Network offers.
     *
     * @param mintUrl The mint's base URL.
     * @param mintQuotePayload Payload containing amount, unit, optional description, and required
     *   pubkey.
     * @param customRequest Optional custom request implementation.
     * @param blindAuthToken Optional authentication token for NUT-22.
     * @returns A mint quote containing a BOLT12 offer.
     */
    static createMintQuoteBolt12(mintUrl: string, mintQuotePayload: Bolt12MintQuotePayload, customRequest?: typeof request, blindAuthToken?: string): Promise<Bolt12MintQuoteResponse>;
    /**
     * Requests a new BOLT12 mint quote from the mint using Lightning Network offers.
     *
     * @param mintQuotePayload Payload containing amount, unit, optional description, and required
     *   pubkey.
     * @returns A mint quote containing a BOLT12 offer.
     */
    createMintQuoteBolt12(mintQuotePayload: Bolt12MintQuotePayload): Promise<Bolt12MintQuoteResponse>;
    /**
     * Requests a new on-chain mint quote from the mint using Bitcoin on-chain payments.
     *
     * @param mintUrl The mint's base URL.
     * @param mintQuotePayload Payload containing unit and required pubkey for the on-chain quote.
     * @param customRequest Optional custom request implementation.
     * @param blindAuthToken Optional authentication token for NUT-22.
     * @returns A mint quote containing a Bitcoin address for on-chain payments.
     */
    static createMintQuoteOnchain(mintUrl: string, mintQuotePayload: OnchainMintQuotePayload, customRequest?: typeof request, blindAuthToken?: string): Promise<OnchainMintQuoteResponse>;
    /**
     * Requests a new on-chain mint quote from the mint using Bitcoin on-chain payments.
     *
     * @param mintQuotePayload Payload containing unit and required pubkey for the on-chain quote.
     * @returns A mint quote containing a Bitcoin address for on-chain payments.
     */
    createMintQuoteOnchain(mintQuotePayload: OnchainMintQuotePayload): Promise<OnchainMintQuoteResponse>;
    /**
     * Gets an existing mint quote from the mint.
     *
     * @param mintUrl
     * @param quote Quote ID.
     * @param customRequest
     * @returns The mint will create and return a Lightning invoice for the specified amount.
     */
    static checkMintQuote(mintUrl: string, quote: string, customRequest?: typeof request, blindAuthToken?: string, logger?: Logger): Promise<PartialMintQuoteResponse>;
    /**
     * Gets an existing mint quote from the mint.
     *
     * @param quote Quote ID.
     * @returns The mint will create and return a Lightning invoice for the specified amount.
     */
    checkMintQuote(quote: string): Promise<PartialMintQuoteResponse>;
    /**
     * Gets an existing BOLT12 mint quote from the mint.
     *
     * @param mintUrl The mint's base URL.
     * @param quote Quote ID to check.
     * @param customRequest Optional custom request implementation.
     * @param blindAuthToken Optional authentication token for NUT-22.
     * @returns Updated quote with current payment and issuance amounts.
     */
    static checkMintQuoteBolt12(mintUrl: string, quote: string, customRequest?: typeof request, blindAuthToken?: string): Promise<Bolt12MintQuoteResponse>;
    /**
     * Gets an existing BOLT12 mint quote from the mint.
     *
     * @param quote Quote ID to check.
     * @returns Updated quote with current payment and issuance amounts.
     */
    checkMintQuoteBolt12(quote: string): Promise<Bolt12MintQuoteResponse>;
    /**
     * Gets an existing on-chain mint quote from the mint.
     *
     * @param mintUrl The mint's base URL.
     * @param quote Quote ID to check.
     * @param customRequest Optional custom request implementation.
     * @param blindAuthToken Optional authentication token for NUT-22.
     * @returns Updated on-chain quote with current payment and issuance amounts.
     */
    static checkMintQuoteOnchain(mintUrl: string, quote: string, customRequest?: typeof request, blindAuthToken?: string): Promise<OnchainMintQuoteResponse>;
    /**
     * Gets an existing on-chain mint quote from the mint.
     *
     * @param quote Quote ID to check.
     * @returns Updated on-chain quote with current payment and issuance amounts.
     */
    checkMintQuoteOnchain(quote: string): Promise<OnchainMintQuoteResponse>;
    /**
     * Mints new tokens by requesting blind signatures on the provided outputs.
     *
     * @param mintUrl
     * @param mintPayload Payload containing the outputs to get blind signatures on.
     * @param customRequest
     * @returns Serialized blinded signatures.
     */
    static mint(mintUrl: string, mintPayload: MintPayload, customRequest?: typeof request, blindAuthToken?: string): Promise<MintResponse>;
    /**
     * Mints new tokens by requesting blind signatures on the provided outputs.
     *
     * @param mintPayload Payload containing the outputs to get blind signatures on.
     * @returns Serialized blinded signatures.
     */
    mint(mintPayload: MintPayload): Promise<MintResponse>;
    /**
     * Mints new tokens using a BOLT12 quote by requesting blind signatures on the provided outputs.
     *
     * @param mintUrl The mint's base URL.
     * @param mintPayload Payload containing the quote ID and outputs to get blind signatures on.
     * @param customRequest Optional custom request implementation.
     * @param blindAuthToken Optional authentication token for NUT-22.
     * @returns Serialized blinded signatures for the requested outputs.
     */
    static mintBolt12(mintUrl: string, mintPayload: MintPayload, customRequest?: typeof request, blindAuthToken?: string): Promise<MintResponse>;
    /**
     * Mints new tokens using a BOLT12 quote by requesting blind signatures on the provided outputs.
     *
     * @param mintPayload Payload containing the quote ID and outputs to get blind signatures on.
     * @returns Serialized blinded signatures for the requested outputs.
     */
    mintBolt12(mintPayload: MintPayload): Promise<MintResponse>;
    /**
     * Mints new tokens using an on-chain quote by requesting blind signatures on the provided outputs.
     *
     * @param mintUrl The mint's base URL.
     * @param mintPayload Payload containing the quote ID and outputs to get blind signatures on.
     * @param customRequest Optional custom request implementation.
     * @param blindAuthToken Optional authentication token for NUT-22.
     * @returns Serialized blinded signatures for the requested outputs.
     */
    static mintOnchain(mintUrl: string, mintPayload: MintPayload, customRequest?: typeof request, blindAuthToken?: string): Promise<MintResponse>;
    /**
     * Mints new tokens using an on-chain quote by requesting blind signatures on the provided outputs.
     *
     * @param mintPayload Payload containing the quote ID and outputs to get blind signatures on.
     * @returns Serialized blinded signatures for the requested outputs.
     */
    mintOnchain(mintPayload: MintPayload): Promise<MintResponse>;
    /**
     * Requests a new melt quote from the mint.
     *
     * @param mintUrl
     * @param MeltQuotePayload
     * @returns
     */
    static createMeltQuote(mintUrl: string, meltQuotePayload: MeltQuotePayload, customRequest?: typeof request, blindAuthToken?: string, logger?: Logger): Promise<PartialMeltQuoteResponse>;
    /**
     * Requests a new melt quote from the mint.
     *
     * @param MeltQuotePayload
     * @returns
     */
    createMeltQuote(meltQuotePayload: MeltQuotePayload): Promise<PartialMeltQuoteResponse>;
    /**
     * Requests a new BOLT12 melt quote from the mint for paying a Lightning Network offer. For
     * amount-less offers, specify the amount in options.amountless.amount_msat.
     *
     * @param mintUrl The mint's base URL.
     * @param meltQuotePayload Payload containing the BOLT12 offer to pay and unit.
     * @param customRequest Optional custom request implementation.
     * @param blindAuthToken Optional authentication token for NUT-22.
     * @returns Melt quote with amount, fee reserve, and payment state.
     */
    static createMeltQuoteBolt12(mintUrl: string, meltQuotePayload: MeltQuotePayload, customRequest?: typeof request, blindAuthToken?: string): Promise<Bolt12MeltQuoteResponse>;
    /**
     * Requests a new BOLT12 melt quote from the mint for paying a Lightning Network offer. For
     * amount-less offers, specify the amount in options.amountless.amount_msat.
     *
     * @param meltQuotePayload Payload containing the BOLT12 offer to pay and unit.
     * @returns Melt quote with amount, fee reserve, and payment state.
     */
    createMeltQuoteBolt12(meltQuotePayload: MeltQuotePayload): Promise<Bolt12MeltQuoteResponse>;
    /**
     * Requests a new on-chain melt quote from the mint for sending Bitcoin to an on-chain address.
     *
     * @param mintUrl The mint's base URL.
     * @param meltQuotePayload Payload containing the Bitcoin address to pay and amount.
     * @param customRequest Optional custom request implementation.
     * @param blindAuthToken Optional authentication token for NUT-22.
     * @returns Melt quote with amount, fee reserve, and payment state for on-chain transaction.
     */
    static createMeltQuoteOnchain(mintUrl: string, meltQuotePayload: OnchainMeltQuotePayload, customRequest?: typeof request, blindAuthToken?: string): Promise<OnchainMeltQuoteResponse>;
    /**
     * Requests a new on-chain melt quote from the mint for sending Bitcoin to an on-chain address.
     *
     * @param meltQuotePayload Payload containing the Bitcoin address to pay and amount.
     * @returns Melt quote with amount, fee reserve, and payment state for on-chain transaction.
     */
    createMeltQuoteOnchain(meltQuotePayload: OnchainMeltQuotePayload): Promise<OnchainMeltQuoteResponse>;
    /**
     * Gets an existing melt quote.
     *
     * @param mintUrl
     * @param quote Quote ID.
     * @returns
     */
    static checkMeltQuote(mintUrl: string, quote: string, customRequest?: typeof request, blindAuthToken?: string, logger?: Logger): Promise<PartialMeltQuoteResponse>;
    /**
     * Gets an existing melt quote.
     *
     * @param quote Quote ID.
     * @returns
     */
    checkMeltQuote(quote: string): Promise<PartialMeltQuoteResponse>;
    /**
     * Gets an existing BOLT12 melt quote from the mint. Returns current payment state (UNPAID,
     * PENDING, or PAID) and payment preimage if paid.
     *
     * @param mintUrl The mint's base URL.
     * @param quote Quote ID to check.
     * @param customRequest Optional custom request implementation.
     * @param blindAuthToken Optional authentication token for NUT-22.
     * @returns Updated quote with current payment state and preimage if available.
     */
    static checkMeltQuoteBolt12(mintUrl: string, quote: string, customRequest?: typeof request, blindAuthToken?: string): Promise<Bolt12MeltQuoteResponse>;
    /**
     * Gets an existing BOLT12 melt quote from the mint. Returns current payment state (UNPAID,
     * PENDING, or PAID) and payment preimage if paid.
     *
     * @param quote Quote ID to check.
     * @returns Updated quote with current payment state and preimage if available.
     */
    checkMeltQuoteBolt12(quote: string): Promise<Bolt12MeltQuoteResponse>;
    /**
     * Gets an existing on-chain melt quote from the mint. Returns current payment state (UNPAID,
     * PENDING, or PAID) and transaction ID if paid.
     *
     * @param mintUrl The mint's base URL.
     * @param quote Quote ID to check.
     * @param customRequest Optional custom request implementation.
     * @param blindAuthToken Optional authentication token for NUT-22.
     * @returns Updated on-chain quote with current payment state and transaction ID if available.
     */
    static checkMeltQuoteOnchain(mintUrl: string, quote: string, customRequest?: typeof request, blindAuthToken?: string): Promise<OnchainMeltQuoteResponse>;
    /**
     * Gets an existing on-chain melt quote from the mint. Returns current payment state (UNPAID,
     * PENDING, or PAID) and transaction ID if paid.
     *
     * @param quote Quote ID to check.
     * @returns Updated on-chain quote with current payment state and transaction ID if available.
     */
    checkMeltQuoteOnchain(quote: string): Promise<OnchainMeltQuoteResponse>;
    /**
     * Requests the mint to pay for a Bolt11 payment request by providing ecash as inputs to be spent.
     * The inputs contain the amount and the fee_reserves for a Lightning payment. The payload can
     * also contain blank outputs in order to receive back overpaid Lightning fees.
     *
     * @param mintUrl
     * @param meltPayload
     * @param customRequest
     * @returns
     */
    static melt(mintUrl: string, meltPayload: MeltPayload, customRequest?: typeof request, blindAuthToken?: string, logger?: Logger): Promise<PartialMeltQuoteResponse>;
    /**
     * Ask mint to perform a melt operation. This pays a lightning invoice and destroys tokens
     * matching its amount + fees.
     *
     * @param meltPayload
     * @returns
     */
    melt(meltPayload: MeltPayload): Promise<PartialMeltQuoteResponse>;
    /**
     * Requests the mint to pay a BOLT12 offer by providing ecash inputs to be spent. The inputs must
     * cover the amount plus fee reserves. Optional outputs can be included to receive change for
     * overpaid Lightning fees.
     *
     * @param mintUrl The mint's base URL.
     * @param meltPayload Payload containing quote ID, inputs, and optional outputs for change.
     * @param customRequest Optional custom request implementation.
     * @param blindAuthToken Optional authentication token for NUT-22.
     * @returns Payment result with state and optional change signatures.
     */
    static meltBolt12(mintUrl: string, meltPayload: MeltPayload, customRequest?: typeof request, blindAuthToken?: string): Promise<Bolt12MeltQuoteResponse>;
    /**
     * Requests the mint to pay a BOLT12 offer by providing ecash inputs to be spent. The inputs must
     * cover the amount plus fee reserves. Optional outputs can be included to receive change for
     * overpaid Lightning fees.
     *
     * @param meltPayload Payload containing quote ID, inputs, and optional outputs for change.
     * @returns Payment result with state and optional change signatures.
     */
    meltBolt12(meltPayload: MeltPayload): Promise<Bolt12MeltQuoteResponse>;
    /**
     * Requests the mint to send Bitcoin to an on-chain address by providing ecash inputs to be spent.
     * The inputs must cover the amount plus fee reserves. Optional outputs can be included to receive
     * change for overpaid transaction fees.
     *
     * @param mintUrl The mint's base URL.
     * @param meltPayload Payload containing quote ID, inputs, and optional outputs for change.
     * @param customRequest Optional custom request implementation.
     * @param blindAuthToken Optional authentication token for NUT-22.
     * @returns Payment result with state and optional change signatures.
     */
    static meltOnchain(mintUrl: string, meltPayload: MeltPayload, customRequest?: typeof request, blindAuthToken?: string): Promise<OnchainMeltQuoteResponse>;
    /**
     * Requests the mint to send Bitcoin to an on-chain address by providing ecash inputs to be spent.
     * The inputs must cover the amount plus fee reserves. Optional outputs can be included to receive
     * change for overpaid transaction fees.
     *
     * @param meltPayload Payload containing quote ID, inputs, and optional outputs for change.
     * @returns Payment result with state and optional change signatures.
     */
    meltOnchain(meltPayload: MeltPayload): Promise<OnchainMeltQuoteResponse>;
    /**
     * Checks if specific proofs have already been redeemed.
     *
     * @param mintUrl
     * @param checkPayload
     * @param customRequest
     * @returns Redeemed and unredeemed ordered list of booleans.
     */
    static check(mintUrl: string, checkPayload: CheckStatePayload, customRequest?: typeof request): Promise<CheckStateResponse>;
    /**
     * Get the mints public keys.
     *
     * @param mintUrl
     * @param keysetId Optional param to get the keys for a specific keyset. If not specified, the
     *   keys from all active keysets are fetched.
     * @param customRequest
     * @returns
     */
    static getKeys(mintUrl: string, keysetId?: string, customRequest?: typeof request): Promise<MintActiveKeys>;
    /**
     * Get the mints public keys.
     *
     * @param keysetId Optional param to get the keys for a specific keyset. If not specified, the
     *   keys from all active keysets are fetched.
     * @returns The mints public keys.
     */
    getKeys(keysetId?: string, mintUrl?: string): Promise<MintActiveKeys>;
    /**
     * Get the mints keysets in no specific order.
     *
     * @param mintUrl
     * @param customRequest
     * @returns All the mints past and current keysets.
     */
    static getKeySets(mintUrl: string, customRequest?: typeof request): Promise<MintAllKeysets>;
    /**
     * Get the mints keysets in no specific order.
     *
     * @returns All the mints past and current keysets.
     */
    getKeySets(): Promise<MintAllKeysets>;
    /**
     * Checks if specific proofs have already been redeemed.
     *
     * @param checkPayload
     * @returns Redeemed and unredeemed ordered list of booleans.
     */
    check(checkPayload: CheckStatePayload): Promise<CheckStateResponse>;
    static restore(mintUrl: string, restorePayload: PostRestorePayload, customRequest?: typeof request): Promise<PostRestoreResponse>;
    restore(restorePayload: {
        outputs: SerializedBlindedMessage[];
    }): Promise<PostRestoreResponse>;
    /**
     * Tries to establish a websocket connection with the websocket mint url according to NUT-17.
     */
    connectWebSocket(): Promise<void>;
    /**
     * Closes a websocket connection.
     */
    disconnectWebSocket(): void;
    get webSocketConnection(): WSConnection | undefined;
    handleBlindAuth(path: string): Promise<string | undefined>;
}
export { CashuMint };
