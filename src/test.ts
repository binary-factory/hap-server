import {ChaCha20} from './crypto/chacha20/chacha20';


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

let cipher2 = new ChaCha20(key, nonce, 1);
cipher2.update(encrypted);
console.log(cipher2.final());
