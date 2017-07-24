import { SecureRemotePassword } from '../../crypto/srp/srp';
import { PairState } from './pair-state';

interface PairSetupContext {
    state: PairState;
    srp?: SecureRemotePassword;
    sharedSecret?: Buffer;
    sessionKey?: Buffer;
}