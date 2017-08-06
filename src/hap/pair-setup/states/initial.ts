import * as crypto from 'crypto';
import { SRPConfigurations } from '../../../crypto/srp/configurations';
import { SecureRemotePassword } from '../../../crypto/srp/srp';
import { StartResponse } from '../start-response';
import { PairSetupState } from '../state';
import { PairSetupStateStarted } from './started';

export class PairSetupStateInitial extends PairSetupState {

    start(setupCode?: string): StartResponse {
        const username = 'Pair-Setup';
        const configuration = SRPConfigurations[3072];
        const privateKey = crypto.randomBytes(16);
        const salt = crypto.randomBytes(16);

        let password: string;
        if (setupCode) {
            password = setupCode;
        } else {
            password = '123-99-123';
        }

        this._handle.srp = new SecureRemotePassword(username, password, salt, configuration, privateKey);
        this._handle.attempts = 0;
        this._handle.state = new PairSetupStateStarted(this._handle);

        return {
            accessorySRPPublicKey: this._handle.srp.getServerPublicKey(),
            accessorySRPSalt: salt,
            setupCode
        };
    }
}