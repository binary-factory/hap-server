import { SecureRemotePassword } from '../../crypto/srp/srp';
import { PairState } from './pair-state';

export interface PairSetupContext {
    state: PairState;
    srp?: SecureRemotePassword;
    sharedSecret?: Buffer;
    sessionKey?: Buffer;
}