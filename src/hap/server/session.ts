import { PairSetupContext } from './pair-setup/context';
import { PairVerifyContext } from './pair-verify-context';
import { SecureDecryptStream } from './secure-decrypt-stream';
import { SecureEncryptStream } from './secure-encrypt-stream';

export interface Session {
    pairContext: PairSetupContext;
    verifyContext: PairVerifyContext;
    decryptStream?: SecureDecryptStream;
    encryptStream?: SecureEncryptStream;
}