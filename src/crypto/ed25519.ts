const sodium = require('sodium');

export namespace ed25519 {

    export function verify(signature: Buffer, data: Buffer, publicKey: Buffer): boolean {
        const verified = sodium.api.crypto_sign_ed25519_verify_detached(signature, data, publicKey);

        return verified;
    }

    export function sign(data: Buffer, privateKey: Buffer): Buffer {
        const signature = sodium.api.crypto_sign_ed25519_detached(data, privateKey);
        if (!signature) {
            throw new Error('bad sign.');
        }

        return signature;
    }
}