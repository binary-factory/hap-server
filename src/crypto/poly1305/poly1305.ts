import * as assert from 'assert';
import * as BigNum from 'bignum';
import { SimpleCipher } from '../SimpleCipher';

export class Poly1305 implements SimpleCipher {

    private one = new BigNum(1);
    private accumulator = new BigNum(0);
    private r: BigNum;
    private s: BigNum;
    private p: BigNum;
    private remainder: Buffer;

    constructor(private key: Buffer) {
        assert.equal(key.length, 32, 'key have to be 128bits long');

        const clampMask = new BigNum('0ffffffc0ffffffc0ffffffc0fffffff', 16);
        this.r = BigNum
            .fromBuffer(key.slice(0, 16), {
                endian: 'little',
                size: 16
            })
            .and(clampMask);

        this.s = BigNum
            .fromBuffer(key.slice(16, 32), {
                endian: 'little',
                size: 16
            });

        this.p = new BigNum('3fffffffffffffffffffffffffffffffb', 16);
        console.log(this.p.toString(16));
    }

    private accumulate(data: Buffer, offset: number = 0) {
        let length = Math.min(data.length - offset, 16);
        let block = data.slice(offset, offset + length);

        let n = BigNum
            .fromBuffer(block, {
                endian: 'little',
                size: 'auto'
            });

        this.accumulator = this.accumulator
            .add(n.add(this.one.shiftLeft(length * 8)))
            .mul(this.r)
            .mod(this.p);
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
        let blockCount = Math.floor(data.length / 16);
        for (let i = 0; i < blockCount; i++) {
            this.accumulate(data, i * 16);
        }

        // Do we have a remainder?
        if (data.length % 16 !== 0) {
            this.remainder = data.slice(blockCount * 16, data.length);
        } else {
            this.remainder = null;
        }

    }

    final(): Buffer {
        if (this.remainder) {
            this.accumulate(this.remainder);
        }

        return this.accumulator
            .add(this.s)
            .toBuffer({
                endian: 'little',
                size: 'auto'
            })
            .slice(0, 16);
    }
}