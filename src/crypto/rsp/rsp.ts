
import * as BigNum from 'bignum';
import * as crypto from 'crypto';

export interface SRPConfiguration {
    safePrime: Buffer;
    generator: Buffer;
    hashAlgorithm: string;
}

export class RemoteSecurePassword {

    private privateKey: BigNum;
    private passwordVerifier: BigNum;

    constructor(
        private username: string,
        private password: string,
        private salt: Buffer,
        private configuration: SRPConfiguration
    ) {

        this.privateKey = BigNum.fromBuffer(this.hash(salt, username, password));
        //this.passwordVerifier =
    }

    private hash(...args: (Buffer | string | BigNum)[]) {
        const hash = crypto.createHash(this.configuration.hashAlgorithm);

        for (let i = 0; i < args.length; i++) {
            const item = args[i];

            if (Buffer.isBuffer(item) || typeof item === 'string') {
                hash.update(item);
            } else {
                hash.update(item.toBuffer());
            }
        }

        return hash.digest();
    }
}