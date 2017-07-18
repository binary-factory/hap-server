import * as BigNum from 'bignum';
import * as crypto from 'crypto';
import { SRPConfiguration } from './configurations';

export class SecureRemotePassword {

    private multiplier: BigNum;
    private privateKey: BigNum;
    private passwordVerifier: BigNum;
    private clientPublicKey: BigNum;
    private clientProof: Buffer;
    private serverPrivateKey: BigNum;
    private serverPublicKey: BigNum;
    private premasterSecret: BigNum;
    private sessionKey: BigNum;

    constructor(private username: string,
                private password: string,
                private salt: Buffer,
                private configuration: SRPConfiguration, priv: Buffer) {

        const size = configuration.safePrime.bitLength() / 8;
        this.multiplier = this.hash(configuration.safePrime, configuration.generator.toBuffer({ endian: 'big', size }));
        this.privateKey = this.hash(salt, this.hash(`${username}:${password}`));
        this.passwordVerifier = configuration.generator.powm(this.privateKey, configuration.safePrime);

        this.serverPrivateKey = BigNum.fromBuffer(priv);
    }

    setClientPublicKey(clientPublicKey: Buffer) {
        this.clientPublicKey = BigNum.fromBuffer(clientPublicKey);
    }

    getServerPublicKey(): Buffer {
        this.serverPublicKey = this.multiplier
            .mul(this.passwordVerifier)
            .add(this.configuration.generator.powm(this.serverPrivateKey, this.configuration.safePrime))
            .mod(this.configuration.safePrime);

        return this.serverPublicKey.toBuffer();
    }

    getSessionKey(): Buffer {
        const scrambling = this.hash(this.clientPublicKey, this.serverPublicKey);
        this.premasterSecret = this.clientPublicKey
            .mul(this.passwordVerifier.powm(scrambling, this.configuration.safePrime))
            .powm(this.serverPrivateKey, this.configuration.safePrime);

        this.sessionKey = this.hash(this.premasterSecret);
        return this.sessionKey.toBuffer();
    }

    verifyProof(clientProof: Buffer): boolean {
        const hashedSafePrime = this.hash(this.configuration.safePrime);
        const hashedGenerator = this.hash(this.configuration.generator);
        const hashedUsername = this.hash(this.username);
        const proof = this.hash(hashedSafePrime.xor(hashedGenerator), hashedUsername, this.salt, this.clientPublicKey, this.serverPublicKey, this.sessionKey);

        this.clientProof = clientProof; //TODO: only whether true
        return proof.toBuffer().compare(clientProof) === 0;
    }

    getProof(): Buffer {
        return this.hash(this.clientPublicKey, this.clientProof, this.sessionKey).toBuffer();
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

        return BigNum.fromBuffer(hash.digest());
    }
}