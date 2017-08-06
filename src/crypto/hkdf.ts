import * as crypto from 'crypto';

export function hkdf(algorithm: string, material: Buffer, salt: Buffer, info: Buffer, length: number) {
    const prk = crypto
        .createHmac(algorithm, salt)
        .update(material)
        .digest();

    let key: Buffer;
    let previous = Buffer.alloc(0);

    const blockCount = Math.ceil(length / prk.length);
    for (let i = 0; i < blockCount; i++) {
        const input = Buffer.concat([
            previous,
            info,
            Buffer.from([i + 1])
        ]);

        const hmac = crypto
            .createHmac(algorithm, prk)
            .update(input)
            .digest();

        previous = hmac;

        if (key) {
            key = Buffer.concat([key, hmac]);
        } else {
            key = hmac;
        }
    }

    return key.slice(0, length);
}