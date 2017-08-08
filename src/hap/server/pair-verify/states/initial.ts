import { PairVerifyStartResponse } from '../../messages/pair-verify/start-response';
import { PairVerifyState } from '../state';

const sodium = require('sodium');

export class PairVerifyInitialState extends PairVerifyState {
    start(clientPublicKey: Buffer): PairVerifyStartResponse {
        const keyPair = sodium.api.crypto_sign_ed25519_keypair();
        if (!keyPair) {
            throw new Error('could not generate key pairs.');
        }
        const accessoryPublicKey = sodium.api.crypto_sign_ed25519_pk_to_curve25519(keyPair.publicKey);
        const accessoryPrivateKey = sodium.api.crypto_sign_ed25519_sk_to_curve25519(keyPair.secretKey);
        const sharedSecret = sodium.api.crypto_scalarmult_curve25519(accessoryPrivateKey, clientPublicKey);

        const accessoryLongTimePrivateKey = this.longTimeKeyPair.privateKey;

        const accessoryPairingId = Buffer.from(this.configuration.deviceId);
        const accessoryInfo = Buffer.concat([accessoryPublicKey, accessoryPairingId, clientPublicKey]);
        const accessorySignature = sodium.api.crypto_sign_ed25519_detached(accessoryInfo, accessoryLongTimePrivateKey);
        if (!accessorySignature) {
            throw new Error('could not sign accessoryInfo.');
        }

        // Derive shared key from the Curve25519 shared secret.
        const pairVerifyEncryptSalt = Buffer.from('Pair-Verify-Encrypt-Salt');
        const pairVerifyEncryptInfo = Buffer.from('Pair-Verify-Encrypt-Info');
        const sessionKey = hkdf('sha512', sharedSecret, pairVerifyEncryptSalt, pairVerifyEncryptInfo, 32);

        const subTLV = new Map();
        subTLV.set(TLVType.Identifier, accessoryPairingId);
        subTLV.set(TLVType.Signature, accessorySignature);
        const subTLVData = tlv.encode(subTLV);

        const nonce = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x00]), Buffer.from('PV-Msg02')]);
        const encryptedSubTLV = sodium.api.crypto_aead_chacha20poly1305_ietf_encrypt(subTLVData, null, nonce, sessionKey);
        if (!encryptedSubTLV) {
            throw new Error('could not encrypt sub-tlv.');
        }

        const responseTLV: tlv.TLVMap = new Map();
        responseTLV.set(TLVType.State, Buffer.from([VerifyState.M2]));
        responseTLV.set(TLVType.PublicKey, accessoryPublicKey);
        responseTLV.set(TLVType.EncryptedData, encryptedSubTLV);
    }
}