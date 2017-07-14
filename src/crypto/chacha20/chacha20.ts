import { SimpleCipher } from '../SimpleCipher';
import * as assert from 'assert';
import { BlockChain } from '../BlockChain';

export class ChaCha20 extends BlockChain {

    private state: Uint32Array;
    private message: Buffer;

    constructor(private key: Buffer,
                private nonce: Buffer,
                private blockCounter: number = 0) {

        super(64);
        assert.equal(key.length, 32, 'key should have a length of 256bits.');
        assert.equal(nonce.length === 12 || nonce.length === 8, true, 'nonce should have a length of 96bits or 64bits.');

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
        if (nonce.length === 12) {
            for (let i = 0; i < nonce.length / 4; i++) {
                this.state[13 + i] = nonce.readUInt32LE(i * 4);
            }
        } else {
            this.state[13] = 0;
            for (let i = 0; i < nonce.length / 4; i++) {
                this.state[14 + i] = nonce.readUInt32LE(i * 4);
            }
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
        const serialized = Buffer.alloc(64);
        for (let i = 0; i < 16; i++) {
            serialized.writeUInt32LE(state[i], i * 4);
        }

        return serialized;
    }

    private nextState(): Uint32Array {
        const workingState = this.state.slice(0, this.state.length);

        for (let i = 0; i < 10; i++) {
            this.innerBlock(workingState);
        }

        for (let i = 0; i < this.state.length; i++) {
            workingState[i] += this.state[i];
        }

        // Increase counter.
        this.state[12] += 1;
        //TODO: Increment next 32bit if nonce is 64bit.

        return workingState;
    }

    protected processBlock(chunk: Buffer, start: number, end: number, length: number) {
        // TODO: Replace serializeState with a mapped XOR to improve performance.
        const key = this.serializeState(this.nextState());
        const encrypted = Buffer.alloc(length);
        for (let i = 0; i < length; i++) {
            encrypted[i] = chunk[start + i] ^ key[i];
        }

        if (this.message) {
            this.message = Buffer.concat([this.message, encrypted]);
        } else {
            // Lazy initialization of the output message.
            this.message = encrypted;
        }
    }

    protected finalize(): Buffer {
        return this.message;
    }
}