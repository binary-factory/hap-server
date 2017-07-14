import {ChaCha20} from './crypto/chacha20/chacha20';
import { Poly1305 } from './crypto/poly1305/poly1305';
import { mdns } from './transport/mdns/mdns';
import * as url from 'url';
/*
let key = Buffer.alloc(32);
for (let i = 0; i < key.length; i++) {
    key[i] = i;
}
let nonce = Buffer.alloc(12);
nonce.fill(0);
nonce[7] = 0x4a;

let input = Buffer.from(`Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.`);
input.toString('ascii');
let cipher = new ChaCha20(key, nonce, 1);
cipher.update(input);
let encrypted = cipher.final();
console.log(encrypted);
/*
let cipher2 = new ChaCha20(key, nonce, 1);
cipher2.update(encrypted);
console.log(cipher2.final());
*/

/*
let te = Buffer.alloc(32);
let a = '85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b';
let i = 0;
for (let b of a.split(':')) {
    te[i++] = parseInt(`0x${b}`);
}
let poly = new Poly1305(te);
poly.update(Buffer.from('Cryptographic Forum Research Group'));
console.log(poly.final());*/

function hex(str: string): Buffer {
    let hexValues = str.split(/[ :]+/);
    const buff = Buffer.allocUnsafe(hexValues.length);
    for (let i = 0; i < buff.length; i++) {
        buff[i] = parseInt(hexValues[i], 16);
    }

    return buff;
}

const sodium = require('sodium');

const message = hex(`4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c
   65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73
   73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63
   6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f
   6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20
   74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73
   63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69
   74 2e`);
const aad = hex('50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7');
const key = hex('80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f');
const nonce = hex('07 00 00 00 40 41 42 43 44 45 46 47'); console.log(nonce.length);
const ciphertext = Buffer.alloc(message.length + sodium.api.crypto_aead_chacha20poly1305_ietf_ABYTES);

let res = sodium.api.crypto_aead_chacha20poly1305_ietf_encrypt(message, aad, nonce, key);
console.log(res);

import * as http from 'http';


const requestHandler = (request, response) => {
    const pathname = url.parse(request.url).pathname;

    console.log(pathname);

    const chunks = [];
    request.on('data', (chunk) => {
        chunks.push(chunk);
    }).on('end', () => {
        const body = Buffer.concat(chunks);
        console.log(body);
    });
}
const server = http.createServer(requestHandler);

server.listen(3000, (err) => {
    if (err) {
        return console.log('something bad happened', err)
    }

    console.log(`server is listening on ${3000}`)
})

mdns.startAdvertising();