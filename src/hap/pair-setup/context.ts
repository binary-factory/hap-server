import { SecureRemotePassword } from '../../crypto/srp/srp';
import { ExchangeResponse } from './exchange-response';
import { StartResponse } from './start-response';
import { PairSetupState } from './state';
import { PairSetupStateInitial } from './states/initial';
import { VerifyResponse } from './verify-response';

export class PairSetupContext {
    private _state: PairSetupState = new PairSetupStateInitial(this);

    get state(): PairSetupState {
        return this._state;
    }

    set state(value: PairSetupState) {
        this._state = value;
    }

    private _srp: SecureRemotePassword;

    get srp(): SecureRemotePassword {
        return this._srp;
    }

    set srp(value: SecureRemotePassword) {
        this._srp = value;
    }

    private _attempts: number = 0;

    get attempts(): number {
        return this._attempts;
    }

    set attempts(value: number) {
        this._attempts = value;
    }

    private _sessionKey: Buffer;

    get sessionKey(): Buffer {
        return this._sessionKey;
    }

    set sessionKey(value: Buffer) {
        this._sessionKey = value;
    }

    start(setupCode?: string): StartResponse {
        return this._state.start(setupCode);
    }

    verify(deviceSRPPublicKey: Buffer, deviceSRPProof: Buffer): VerifyResponse {
        return this._state.verify(deviceSRPPublicKey, deviceSRPProof);
    }

    exchange(encryptedData: Buffer, accessoryLongTimePublicKey: Buffer, accessoryLongTimePrivateKey: Buffer, accessoryPairingId: Buffer): ExchangeResponse {
        return this._state.exchange(encryptedData, accessoryLongTimePublicKey, accessoryLongTimePrivateKey, accessoryPairingId);
    }
}