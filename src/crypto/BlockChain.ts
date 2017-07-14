import { SimpleCipher } from './SimpleCipher';
export abstract class BlockChain implements SimpleCipher {

    protected remainder: Buffer;

    constructor(protected blockSize: number) {
    }

    protected abstract processBlock(chunk: Buffer, start: number, end: number, length: number);

    protected abstract finalize(): Buffer;

    public update(chunk: Buffer) {
        // Respect the remainder of previous operation(s).
        let data: Buffer;
        if (this.remainder) {
            data = Buffer.concat([this.remainder, chunk]);
        } else {
            data = chunk;
        }

        // Here we will encrypt whether we have a full block.
        const blockCount = Math.floor(data.length / this.blockSize);
        for (let i = 0; i < blockCount; i++) {
            const start = i * this.blockSize;
            const end = start + this.blockSize;
            this.processBlock(data, start, end, this.blockSize);
        }

        // Do we have a remainder?
        if (data.length % this.blockSize !== 0) {
            this.remainder = data.slice(blockCount * this.blockSize);
        } else {
            this.remainder = null;
        }
    }

    public final(): Buffer {
        if (this.remainder) {
            const length =  this.remainder.length;
            this.processBlock(this.remainder, 0, length, length);
        }

        return this.finalize();
    }
}