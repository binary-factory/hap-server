import * as crypto from 'crypto';
import { SRPConfigurations } from '../../../../crypto/srp/configurations';
import { SecureRemotePassword } from '../../../../crypto/srp/srp';
import { PairSetupStartResponse } from '../../messages/pair-setup';
import { PairSetupState } from '../state';
import { PairSetupStateStarted } from './started';

export class PairSetupStateInitial extends PairSetupState {

    start(setupCode: string): PairSetupStartResponse {
        const username = 'Pair-Setup';
        const salt = crypto.randomBytes(16);
        const configuration = SRPConfigurations[3072];
        const privateKey = crypto.randomBytes(16);

        this._handle.srp = new SecureRemotePassword(username, setupCode, salt, configuration, privateKey);
        this._handle.attempts = 0;
        this._handle.state = new PairSetupStateStarted(this._handle);

        return {
            accessorySRPPublicKey: this._handle.srp.getServerPublicKey(),
            accessorySRPSalt: salt
        };
    }
}