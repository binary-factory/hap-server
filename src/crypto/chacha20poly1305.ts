const sodium = require('sodium');

export namespace chacha20poly1305 {

    export function encrypt(plain: Buffer, nonce: Buffer, key: Buffer, aead: Buffer = null): Buffer {
        const encrypted = sodium.api.crypto_aead_chacha20poly1305_ietf_encrypt(plain, aead, padNonce(nonce), key);

        if (!encrypted) {
            throw new Error('bad encrypt.');
        }

        return encrypted;
    }

    export function decrypt(encrypted: Buffer, nonce: Buffer, key: Buffer, aead: Buffer = null): Buffer {
        const decrypted = sodium.api.crypto_aead_chacha20poly1305_ietf_decrypt(encrypted, aead, padNonce(nonce), key);
        if (!decrypted) {
            throw new Error('bad decrypt.');
        }

        return decrypted;
    }

    function encryptDetached(plain: Buffer, nonce: Buffer, key: Buffer, authTag: Buffer, aead: Buffer = null): Buffer {
        const encrypted = sodium.api.crypto_aead_chacha20poly1305_ietf_encrypt_detached(plain, authTag, aead, padNonce(nonce), key);
        if (!encrypted) {
            throw new Error('bad encrypt.');
        }

        return encrypted;
    }

    function decryptDetached(encrypted: Buffer, nonce: Buffer, key: Buffer, authTag: Buffer, aead: Buffer = null): Buffer {
        const decrypted = sodium.api.crypto_aead_chacha20poly1305_ietf_decrypt_detached(encrypted, authTag, aead, padNonce(nonce), key);
        if (!decrypted) {
            throw new Error('bad decrypt.');
        }

        return decrypted;
    }

    function padNonce(nonce: Buffer): Buffer {
        const nonceLength = sodium.api.crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
        const padded = Buffer.alloc(nonceLength);
        const offset = padded.length - nonce.length;
        nonce.copy(padded, offset, 0, nonce.length);

        return padded;
    }
}