import { SecureRemotePassword } from '../../crypto/srp/srp';
import { PairSetupState } from './pair-setup-state';

export interface PairSetupContext {
    state: PairSetupState;
    srp?: SecureRemotePassword;
    sharedSecret?: Buffer;
    sessionKey?: Buffer;
}