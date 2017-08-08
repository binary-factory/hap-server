import { VerifyState } from '../constants/pair-verify-state';

export interface PairVerifyContext {
    state: VerifyState;
    devicePublicKey?: Buffer;
    accessoryPublicKey?: Buffer;
    sharedSecret?: Buffer;
    sessionKey?: Buffer;
}