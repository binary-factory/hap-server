import { SimpleCipher } from '../SimpleCipher';
import * as assert from 'assert';

export class ChaCha20 implements SimpleCipher {

    private state: Uint32Array;
    private message: Buffer;
    private remainder: Buffer;

    constructor(private key: Buffer,
                private nonce: Buffer,
                private blockCounter: number = 0) {

        assert.equal(key.length, 32, 'key should have a length of 256bit');
        assert.equal(nonce.length, 12, 'key should have a length of 96bit');

        // The first four words (0-3) are constants.
        this.state = new Uint32Array(16);
        this.state[0] = 0x61707865;
        this.state[1] = 0x3320646e;
        this.state[2] = 0x79622d32;
        this.state[3] = 0x6b206574;

        /* The next eight words (4-11) are taken from the 256-bit key by
         reading the bytes in little-endian order, in 4-byte chunks. */
        for (let i = 0; i < 8; i++) {
            this.state[4 + i] = key.readUInt32LE(i * 4);
        }

        this.state[12] = blockCounter;
        for (let i = 0; i < 3; i++) {
            this.state[13 + i] = nonce.readUInt32LE(i * 4);
        }
    }

    private shiftUInt32Left(value: number, count: number): number {
        return (value << count) | (value >>> (32 - count));

    }

    private quarterRound(x: Uint32Array, a: number, b: number, c: number, d: number) {
        x[a] += x[b];
        x[d] = this.shiftUInt32Left(x[d] ^ x[a], 16);

        x[c] += x[d];
        x[b] = this.shiftUInt32Left(x[b] ^ x[c], 12);

        x[a] += x[b];
        x[d] = this.shiftUInt32Left(x[d] ^ x[a], 8);

        x[c] += x[d];
        x[b] = this.shiftUInt32Left(x[b] ^ x[c], 7);
    }

    private innerBlock(x: Uint32Array) {
        this.quarterRound(x, 0, 4, 8, 12);
        this.quarterRound(x, 1, 5, 9, 13);
        this.quarterRound(x, 2, 6, 10, 14);
        this.quarterRound(x, 3, 7, 11, 15);
        this.quarterRound(x, 0, 5, 10, 15);
        this.quarterRound(x, 1, 6, 11, 12);
        this.quarterRound(x, 2, 7, 8, 13);
        this.quarterRound(x, 3, 4, 9, 14);
    }

    private serializeState(state: Uint32Array): Buffer {
        let serialized = Buffer.alloc(64);
        for (let i = 0; i < 16; i++) {
            serialized.writeUInt32LE(state[i], i * 4);
        }

        return serialized;
    }

    private nextState(): Uint32Array {
        let workingState = this.state.slice(0, this.state.length);

        for (let i = 0; i < 10; i++) {
            this.innerBlock(workingState);
        }

        for (let i = 0; i < this.state.length; i++) {
            workingState[i] += this.state[i];
        }

        // Increase counter.
        this.state[12] += 1;

        return workingState;
    }

    private encrypt(data: Buffer, offset: number = 0) {
        let length = data.length - offset;

        // TODO: Replace serializeState with a mapped XOR to improve performance.
        let key = this.serializeState(this.nextState());
        let encrypted = Buffer.alloc(length);
        for (let i = 0; i < length; i++) {
            encrypted[i] = data[offset + i] ^ key[i];
        }

        if (this.message) {
            this.message = Buffer.concat([this.message, encrypted]);
        } else {
            // Lazy initialization of the output message.
            this.message = encrypted;
        }
    }

    update(input: Buffer) {
        // Respect the remainder of previous operation(s).
        let data: Buffer;
        if (this.remainder) {
            data = Buffer.concat([this.remainder, input]);
        } else {
            data = input;
        }

        // Here we will encrypt whether we have a full block.
        let blockCount = Math.floor(data.length / 64);
        for (let i = 0; i < blockCount; i++) {
            this.encrypt(data, i * 64);
        }

        // Do we have a remainder?
        if (data.length % 64 !== 0) {
            this.remainder = data.slice(blockCount * 64, data.length);
        } else {
            this.remainder = null;
        }
    }

    final(): Buffer {
        if (this.remainder) {
            this.encrypt(this.remainder);
        }

        return this.message;
    }
}