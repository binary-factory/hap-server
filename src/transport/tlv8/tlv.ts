export namespace TLV {
    export type TLVMap = Map<number, Buffer>;

    export function encode(tlv: TLVMap): Buffer {
        let output: Buffer = Buffer.alloc(0);

        tlv.forEach((value, type) => {
            let bytesLeft = value.length;
            let cursor = 0;
            while (bytesLeft > 0) {
                const bytes = Math.min(bytesLeft, 255);
                const tlvData = Buffer.alloc(2 + bytes);
                tlvData.writeUInt8(type, 0);
                tlvData.writeUInt8(type, 1);
                for (let i = 0; i < bytes; i++) {
                    tlvData[2 + i] = value[cursor++];
                }

                bytesLeft -= bytes;
                output = Buffer.concat([output, tlvData]);
            }
        });

        return output;
    }

    export function decode(tlvData: Buffer): TLVMap {
        const parsed: TLVMap = new Map();
        let cursor = 0;

        while (cursor < tlvData.length) {
            const type = tlvData.readUInt8(cursor++);
            const length = tlvData.readUInt8(cursor++);

            if (length > 0) {
                const end = cursor + length;

                const value = tlvData.slice(cursor, end);

                let item = parsed.get(type);
                if (item) {
                    item = Buffer.concat([item, value]);
                } else {
                    item = value;
                }
                parsed.set(type, item);

                cursor += length;
            }
        }

        return parsed;
    }
}