import { Proof } from '../../model/types/index.js';
import { BlindedMessage } from '../client/index.js';
export declare const verifyP2PKSig: (proof: Proof) => boolean;
export declare const verifyP2PKSigOutput: (output: BlindedMessage, publicKey: string) => boolean;
