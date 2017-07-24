import { Transform } from 'stream';
import { FrameParser } from '../frame-parser';

const sodium = require('sodium');

export class SecureDecryptStream extends Transform {
    private key: Buffer;
    private enabled: boolean = false;
    private counter = 0; // TODO: 64 bit value!
    private frameParser = new FrameParser(2, 16);

    constructor() {
        super();
    }

    _transform(chunk: any, encoding: string, callback: Function) {
        if (this.enabled) {
            const frames = this.frameParser.update(chunk);
            if (frames.length > 0) {
                const chunks: Buffer[] = [];
                for (let i = 0; i < frames.length; i++) {
                    const frame = frames[i];
                    const nonce = Buffer.alloc(12);
                    nonce.writeUInt32LE(this.counter++, 4);

                    const decrypted = sodium.api.crypto_aead_chacha20poly1305_ietf_decrypt_detached(frame.encryptedData, frame.authTag, frame.additionalAuthenticatedData, nonce, this.key);
                    if (!decrypted) {
                        callback(new Error('could not decrypt incoming data.'));
                        return;
                    }
                    chunks.push(decrypted);
                }

                callback(null, Buffer.concat(chunks));
            }
        } else {
            callback(null, chunk);
        }
    }

    setKey(key: Buffer) {
        this.key = key;
    }

    getKey(): Buffer {
        return this.key;
    }

    isEnabled(): boolean {
        return this.enabled;
    }

    enable() {
        this.enabled = true;
    }

    disable() {
        this.enabled = false;
    }

}