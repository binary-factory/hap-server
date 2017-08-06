import { chacha20poly1305, hkdf } from '../../../crypto';
import * as tlv from '../../common/tlv';
import { TLVType } from '../../common/tlv';
import { AuthenticationError } from '../errors/authentication';
import { ExchangeResponse } from '../exchange-response';
import { PairSetupState } from '../state';
import { PairSetupStateFinished } from './finished';

const sodium = require('sodium');

export class PairSetupStateVerified extends PairSetupState {
    exchange(encryptedData: Buffer, accessoryLongTimePublicKey: Buffer, accessoryLongTimePrivateKey: Buffer, accessoryPairingId: Buffer): ExchangeResponse {

        const sessionKey = this._handle.sessionKey;
        // Decrypt sub-tlv.
        let decryptedData: Buffer;
        try {
            const nonceM5 = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x00]), Buffer.from('PS-Msg05')]);
            decryptedData = chacha20poly1305.decrypt(encryptedData, nonceM5, sessionKey, null);
        } catch (ex) {
            throw new AuthenticationError('could not decrypt data');
        }

        // Decode sub-tlv.
        const subTLV = tlv.decode(decryptedData);
        const devicePairingId = subTLV.get(TLVType.Identifier);
        const deviceLongTimePublicKey = subTLV.get(TLVType.PublicKey);
        const deviceSignature = subTLV.get(TLVType.Signature);

        // Derive deviceX from the SRP shared secret.
        const sharedSecret = this._handle.srp.getSessionKey();
        const pairSetupControllerSignSalt = Buffer.from('Pair-Setup-Controller-Sign-Salt');
        const pairSetupControllerSignInfo = Buffer.from('Pair-Setup-Controller-Sign-Info');
        const deviceX = hkdf('sha512', sharedSecret, pairSetupControllerSignSalt, pairSetupControllerSignInfo, 32);

        // Verify the signature of the constructed deviceInfo with the deviceLTPK from the decrypted sub-tlv.
        const deviceInfo = Buffer.concat([deviceX, devicePairingId, deviceLongTimePublicKey]);
        const verified = sodium.api.crypto_sign_ed25519_verify_detached(deviceSignature, deviceInfo, deviceLongTimePublicKey);
        if (!verified) {
            throw new AuthenticationError('device signature invalid.');
        }

        // Derive AccessoryX from the SRP shared secret.
        const pairSetupAccessorySignSalt = Buffer.from('Pair-Setup-Accessory-Sign-Salt');
        const pairSetupAccessorySignInfo = Buffer.from('Pair-Setup-Accessory-Sign-Info');
        const accessoryX = hkdf('sha512', sharedSecret, pairSetupAccessorySignSalt, pairSetupAccessorySignInfo, 32);

        // Signing AccessorySignature.
        const accessoryInfo = Buffer.concat([accessoryX, accessoryPairingId, accessoryLongTimePublicKey]);
        const accessorySignature = sodium.api.crypto_sign_ed25519_detached(accessoryInfo, accessoryLongTimePrivateKey);
        if (!accessorySignature) {
            throw new Error('could not sign accessoryInfo.');
        }

        const subTLV2 = new Map();
        subTLV2.set(TLVType.Identifier, accessoryPairingId);
        subTLV2.set(TLVType.PublicKey, accessoryLongTimePublicKey);
        subTLV2.set(TLVType.Signature, accessorySignature);
        const subTLVData = tlv.encode(subTLV2);

        const nonceM6 = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x00]), Buffer.from('PS-Msg06')]);
        const encryptedSubTLV = sodium.api.crypto_aead_chacha20poly1305_ietf_encrypt(subTLVData, null, nonceM6, sessionKey);
        if (!encryptedSubTLV) {
            throw new Error('could not encrypt sub-tlv.');
        }

        this._handle.state = new PairSetupStateFinished(this._handle);

        return { encryptedData: encryptedSubTLV };
    }
}