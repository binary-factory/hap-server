import { Transform } from 'stream';
import { Logger } from '../util/logger';
import { SimpleLogger } from '../util/simple-logger';

const sodium = require('sodium');


export class SecureEncryptStream extends Transform {
    private logger: Logger = new SimpleLogger('SecureEncryptStream');

    private key: Buffer;
    private enabled: boolean = false;
    private counter = 0; //TODO: 64 bit value!

    constructor() {
        super();
    }

    _transform(chunk: any, encoding: string, callback: Function) {
        if (this.enabled) {
            console.log('\n--------------------------------------\n'
                + 'size: ' + chunk.length + '\n'
                + chunk.toString()
                + '\n--------------------------------------\n');

            // Split each message into frames no larger than 1024 bytes.
            const frames: Buffer[] = [];
            let offset = 0;
            let bytesLeft = chunk.length;
            while (bytesLeft > 0) {
                const bytes = Math.min(bytesLeft, 0x400);
                const message = chunk.slice(offset, offset + bytes);
                const additionalAuthenticatedData = Buffer.alloc(2);
                const nonce = Buffer.alloc(12);

                additionalAuthenticatedData.writeUInt16LE(bytes, 0);
                nonce.writeUInt32LE(this.counter++, 4);

                const encryptedMessage = sodium.api.crypto_aead_chacha20poly1305_ietf_encrypt(message, additionalAuthenticatedData, nonce, this.key);
                const frame = Buffer.concat([additionalAuthenticatedData, encryptedMessage]);
                frames.push(frame);
                console.log('\n--------------------------------------\n'
                    + 'slice: ' + offset + ' to ' + (offset + bytes) + '\n'
                    + 'message-plain: ' + message + '\n'
                    + 'bytes ' + bytes + '\n'
                    + 'nonce' + nonce.toString('hex') + '\n'
                    + 'additionalAuthenticatedData: ' + additionalAuthenticatedData.toString('hex') + '\n'
                    + '\n--------------------------------------\n');

                bytesLeft -= bytes;
                offset += bytes;
            }

            callback(null, Buffer.concat(frames));
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