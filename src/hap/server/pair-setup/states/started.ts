import { hkdf } from '../../../../crypto';
import { PairSetupVerifyResponse } from '../../messages/pair-setup/verify-response';
import { AuthenticationError } from '../errors/authentication';
import { MaxTriesError } from '../errors/max-tries';
import { PairSetupState } from '../state';
import { PairSetupStateVerified } from './verified';

export class PairSetupStateStarted extends PairSetupState {
    verify(deviceSRPPublicKey: Buffer, deviceSRPProof: Buffer): PairSetupVerifyResponse {

        if (this._handle.attempts >= 100) {
            throw new MaxTriesError();
        }

        this._handle.srp.setClientPublicKey(deviceSRPPublicKey);
        const sharedSecret = this._handle.srp.getSessionKey();
        const verified = this._handle.srp.verifyProof(deviceSRPProof);
        if (!verified) {
            this._handle.attempts++;
            throw new AuthenticationError('invalid setup-code.');
        }

        // Derive session key from SRP shared secret.
        const pairSetupEncryptSalt = Buffer.from('Pair-Setup-Encrypt-Salt');
        const pairSetupEncryptInfo = Buffer.from('Pair-Setup-Encrypt-Info');
        const sessionKey = hkdf('sha512', sharedSecret, pairSetupEncryptSalt, pairSetupEncryptInfo, 32);


        const accessorySRPProof = this._handle.srp.getProof();
        this._handle.sessionKey = sessionKey;
        this._handle.state = new PairSetupStateVerified(this._handle);

        return { accessorySRPProof };
    }
}