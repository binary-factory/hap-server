import * as assert from 'assert';
import * as BigNum from 'bignum';
import { BlockChain } from "../BlockChain";

export class Poly1305 extends BlockChain {

    private one = new BigNum(1);
    private accumulator = new BigNum(0);
    private r: BigNum;
    private s: BigNum;
    private p: BigNum;

    constructor(private key: Buffer) {
        super(16);
        assert.equal(key.length, 32, 'key should have a length of 128bits.');


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
    }

    protected processBlock(chunk: Buffer, start: number, end: number, length: number) {
        let block = chunk.slice(start, end);

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

    protected finalize(): Buffer {
        return this.accumulator
            .add(this.s)
            .toBuffer({
                endian: 'little',
                size: 'auto'
            })
            .slice(0, 16);
    }
}