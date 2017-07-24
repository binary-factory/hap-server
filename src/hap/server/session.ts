export interface Session {
    authenticationAttempts: number;
    pairContext: PairSetupContext;
    verifyContext: PairVerifyContext;
    decryptStream?: SecureDecryptStream;
    encryptStream?: SecureEncryptStream;
}