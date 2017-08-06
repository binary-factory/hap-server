import { PairSetupContext } from './context';
import { ExchangeResponse } from './exchange-response';
import { StartResponse } from './start-response';
import { VerifyResponse } from './verify-response';

export abstract class PairSetupState {

    constructor(protected _handle: PairSetupContext) {
    }


    start(setupCode?: string): StartResponse {
        throw new Error('operation not allowed in this state.');
    }

    verify(deviceSRPPublicKey: Buffer, deviceSRPProof: Buffer): VerifyResponse {
        throw new Error('operation not allowed in this state.');
    }

    exchange(encryptedData: Buffer, accessoryLongTimePublicKey: Buffer, accessoryLongTimePrivateKey: Buffer, accessoryPairingId: Buffer): ExchangeResponse {
        throw new Error('operation not allowed in this state.');
    }
}