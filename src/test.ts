import {ChaCha20} from './crypto/chacha20/chacha20';
import { Poly1305 } from './crypto/poly1305/poly1305';
import { mdns } from './transport/mdns/mdns';

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



import * as http from 'http';


const requestHandler = (request, response) => {
    console.log(request.url)
    response.end('Hello Node.js Server!')
}
const server = http.createServer(requestHandler);

server.listen(3000, (err) => {
    if (err) {
        return console.log('something bad happened', err)
    }

    console.log(`server is listening on ${3000}`)
})

mdns.startAdvertising();