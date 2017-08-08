import { SecureRemotePassword } from '../../../crypto/srp/srp';
import { PairSetupExchangeResponse } from '../messages/pair-setup/exchange-response';
import { PairSetupStartResponse } from '../messages/pair-setup/start-response';
import { PairSetupVerifyResponse } from '../messages/pair-setup/verify-response';
import { PairSetupState } from './state';
import { PairSetupStateInitial } from './states/initial';

export class PairSetupContext {
    private _state: PairSetupState = new PairSetupStateInitial(this);
    private _srp: SecureRemotePassword;
    private _attempts: number = 0;
    private _sessionKey: Buffer;

    get state(): PairSetupState {
        return this._state;
    }

    set state(value: PairSetupState) {
        this._state = value;
    }

    get srp(): SecureRemotePassword {
        return this._srp;
    }

    set srp(value: SecureRemotePassword) {
        this._srp = value;
    }


    get attempts(): number {
        return this._attempts;
    }

    set attempts(value: number) {
        this._attempts = value;
    }


    get sessionKey(): Buffer {
        return this._sessionKey;
    }

    set sessionKey(value: Buffer) {
        this._sessionKey = value;
    }

    start(setupCode?: string): PairSetupStartResponse {
        return this._state.start(setupCode);
    }

    verify(deviceSRPPublicKey: Buffer, deviceSRPProof: Buffer): PairSetupVerifyResponse {
        return this._state.verify(deviceSRPPublicKey, deviceSRPProof);
    }

    exchange(encryptedData: Buffer, accessoryLongTimePublicKey: Buffer, accessoryLongTimePrivateKey: Buffer, accessoryPairingId: Buffer): PairSetupExchangeResponse {
        return this._state.exchange(encryptedData, accessoryLongTimePublicKey, accessoryLongTimePrivateKey, accessoryPairingId);
    }
}