const sodium = require('sodium');

export namespace chacha20poly1305 {
    export function encrypt(plain: Buffer, nonce: Buffer, key: Buffer, aead: Buffer): Buffer {
        const encrypted = sodium.api.crypto_aead_chacha20poly1305_ietf_encrypt(plain, aead, nonce, key);

        if (!encrypted) {
            throw new Error('bad encrypt.');
        }

        return encrypted;
    }

    export function decrypt(encrypted: Buffer, nonce: Buffer, key: Buffer, aead: Buffer): Buffer {
        const decrypted = sodium.api.crypto_aead_chacha20poly1305_ietf_decrypt(encrypted, aead, nonce, key);
        if (!decrypted) {
            throw new Error('bad decrypt.');
        }

        return decrypted;
    }
}