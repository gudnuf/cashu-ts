import { BlindedMessage } from './BlindedMessage.js';
import { Proof } from './types/index.js';
declare class Split {
    proofs: Proof[];
    amount: number;
    outputs: BlindedMessage[];
    constructor(proofs: Proof[], amount: number, outputs: BlindedMessage[]);
    getSerializedSplit(): {
        proofs: Proof[];
        amount: number;
        outputs: {
            amount: number;
            B_: string;
        }[];
    };
}
export { Split };
