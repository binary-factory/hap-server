import { PairSetupExchangeResponse, PairSetupStartResponse, PairSetupVerifyResponse } from '../messages/pair-setup';
import { PairSetupContext } from './context';

export abstract class PairSetupState {

    constructor(protected _handle: PairSetupContext) {
    }

    start(setupCode?: string): PairSetupStartResponse {
        throw new Error('operation not allowed in this state.');
    }

    verify(deviceSRPPublicKey: Buffer, deviceSRPProof: Buffer): PairSetupVerifyResponse {
        throw new Error('operation not allowed in this state.');
    }

    exchange(encryptedData: Buffer, accessoryLongTimePublicKey: Buffer, accessoryLongTimePrivateKey: Buffer, accessoryPairingId: Buffer): PairSetupExchangeResponse {
        throw new Error('operation not allowed in this state.');
    }
}