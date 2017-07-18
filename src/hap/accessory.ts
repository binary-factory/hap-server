import * as crypto from 'crypto';
import * as http from 'http';
import { hkdf } from '../crypto/hkdf/hkdf';
import { SRPConfigurations } from '../crypto/srp/configurations';
import { SecureRemotePassword } from '../crypto/srp/srp';
import { TLV } from '../transport/tlv';
import { Advertiser } from './advertiser';
import { ErrorCodes } from './constants/pairing/error-codes';
import { HTTPStatusCodes } from './constants/pairing/http-status-codes';
import { HTTPUrls } from './constants/pairing/http-urls';
import { TLVTypes } from './constants/pairing/tlv-types';
import { HTTPServer, Route } from './http-server';
import { SessionManager } from './session-manager';
const sodium = require('sodium');

interface Session {
    isPaired: boolean;
    pairState: number;
    srp: SecureRemotePassword;
    sharedSecret: Buffer;
    sessionKey: Buffer
}

export const defaultSession: Session = {
    isPaired: false,
    pairState: 1,
    srp: null,
    sharedSecret: null,
    sessionKey: null
};

export class Accessory {

    private httpServer: HTTPServer;

    private sessions: SessionManager<Session>;

    private advertiser: Advertiser;

    constructor(private deviceId: string,
                private modelName: string,
                private categoryIdentifier) {

        // TODO: Verify deviceId format.

        const routes: Route[] = [
            {
                pathname: HTTPUrls.PairSetup,
                method: 'POST',
                handler: this.handlePairSetup.bind(this)
            },
            {
                pathname: HTTPUrls.PairVerify,
                method: 'POST',
                handler: this.handlePairVerify.bind(this)
            },
            {
                pathname: HTTPUrls.Pairings,
                method: 'POST',
                handler: this.handlePairings.bind(this)
            }
        ];

        this.httpServer = new HTTPServer(routes);

        this.advertiser = new Advertiser(deviceId, modelName, categoryIdentifier, 1);

        this.sessions = new SessionManager(this.httpServer.nativeServer, defaultSession);
    }


    private async handlePairSetup(request: http.IncomingMessage, response: http.ServerResponse, body: Buffer) {
        const session = this.sessions.get(request.socket);
        const tlv = TLV.decode(body);
        const pairState = tlv.get(TLVTypes.State);
        /*
         if (!pairState || pairState.readUInt8(0) !== session.pairState) {
         response.writeHead(HTTPStatusCodes.BadRequest);
         response.end();
         return;
         }
         */

        switch (pairState.readUInt8(0)) {
            case 1:
                await this.handlePairSetupStepOne(tlv, response, session);
                break;

            case 3:
                await this.handlePairSetupStepThree(tlv, response, session);
                break;

            case 5:
                await this.handlePairSetupStepFive(tlv, response, session);
                break;

            default:
                response.writeHead(HTTPStatusCodes.BadRequest);
                response.end();
        }
    }

    private async handlePairSetupStepOne(tlv: TLV.TLVMap, response: http.ServerResponse, session: Session) {
        const method = tlv.get(TLVTypes.Method);
        if (!method || method.readUInt8(0) !== 0) {
            response.writeHead(HTTPStatusCodes.BadRequest);
            response.end();
        }

        const username = 'Pair-Setup';
        const password = '123-99-123';
        const serverPrivateKey = crypto.randomBytes(16);
        const salt = crypto.randomBytes(16);
        session.srp = new SecureRemotePassword(username, password, salt, SRPConfigurations[3072], serverPrivateKey);

        const state = new Buffer(1);
        state.writeUInt8(2, 0);
        const publicKey = session.srp.getServerPublicKey();

        const responseTLV: TLV.TLVMap = new Map();
        responseTLV.set(TLVTypes.State, state);
        responseTLV.set(TLVTypes.PublicKey, publicKey);
        responseTLV.set(TLVTypes.Salt, salt);

        response.writeHead(200, { 'Content-Type': 'application/pairing+tlv8' });
        response.write(TLV.encode(responseTLV));
        response.end();

        session.pairState = 2;
    }

    private async handlePairSetupStepThree(tlv: Map<number, Buffer>, response: http.ServerResponse, session: Session) {
        const srp = session.srp;
        const publicKey = tlv.get(TLVTypes.PublicKey);
        const clientProof = tlv.get(TLVTypes.Proof);
        if (!publicKey || !clientProof) {
            response.writeHead(HTTPStatusCodes.BadRequest);
            response.end();
        }

        // Verify client proof.
        srp.setClientPublicKey(publicKey);
        const sharedSecret = session.srp.getSessionKey();
        const verified = srp.verifyProof(clientProof);
        if (!verified) {
            session.pairState = 1;

            const responseTLV: TLV.TLVMap = new Map();
            responseTLV.set(TLVTypes.State, Buffer.from([0x04]));
            responseTLV.set(TLVTypes.Error, Buffer.from([ErrorCodes.Authentication]));

            response.writeHead(200, { 'Content-Type': 'application/pairing+tlv8' });
            response.write(TLV.encode(responseTLV));
            response.end();
            return;
        }

        // Derive session key from SRP shared secret.
        const salt = Buffer.from('Pair-Setup-Encrypt-Salt');
        const info = Buffer.from('Pair-Setup-Encrypt-Info');
        session.sessionKey = hkdf('sha512', sharedSecret, salt, info, 32);
        session.sharedSecret = sharedSecret;

        const serverProof = srp.getProof();
        const responseTLV: TLV.TLVMap = new Map();
        responseTLV.set(TLVTypes.State, Buffer.from([0x04]));
        responseTLV.set(TLVTypes.Proof, serverProof);

        response.writeHead(200, { 'Content-Type': 'application/pairing+tlv8' });
        response.write(TLV.encode(responseTLV));
        response.end();

        session.pairState = 4;
    }

    private async handlePairSetupStepFive(tlv: Map<number, Buffer>, response: http.ServerResponse, session: Session) {
        const encryptedData = tlv.get(TLVTypes.EncryptedData);
        if (!encryptedData) {
            response.writeHead(HTTPStatusCodes.BadRequest);
            response.end();
        }

        // Decrypt sub-TLV.
        const nonceM5 = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x00]), Buffer.from('PS-Msg05')]);
        const decryptedData = sodium.api.crypto_aead_chacha20poly1305_ietf_decrypt(encryptedData, null, nonceM5, session.sessionKey);
        if (!decryptedData) {
            session.pairState = 1;

            const responseTLV: TLV.TLVMap = new Map();
            responseTLV.set(TLVTypes.State, Buffer.from([0x05]));
            responseTLV.set(TLVTypes.Error, Buffer.from([ErrorCodes.Authentication]));

            response.writeHead(200, { 'Content-Type': 'application/pairing+tlv8' });
            response.write(TLV.encode(responseTLV));
            response.end();
            return;
        }

        // Decode sub-TLV.
        const subTLV = TLV.decode(decryptedData);
        const iOSDevicePairingId = subTLV.get(TLVTypes.Identifier);
        const iOSDeviceLTPK = subTLV.get(TLVTypes.PublicKey);
        const iOSDeviceSignature = subTLV.get(TLVTypes.Signature);

        // Derive iOSDeviceX from the SRP shared secret.
        const saltDevice = Buffer.from('Pair-Setup-Controller-Sign-Salt');
        const infoDevice = Buffer.from('Pair-Setup-Controller-Sign-Info');
        const iOSDeviceX = hkdf('sha512', session.sharedSecret, saltDevice, infoDevice, 32);

        // Verify the signature of the constructed iOSDeviceInfo with the iOSDeviceLTPK from the decrypted sub-TLV.
        const iOSDeviceInfo = Buffer.concat([iOSDeviceX, iOSDevicePairingId, iOSDeviceLTPK]);
        const verified = sodium.api.crypto_sign_ed25519_verify_detached(iOSDeviceSignature, iOSDeviceInfo, iOSDeviceLTPK);
        if (!verified) {
            session.pairState = 1;

            const responseTLV: TLV.TLVMap = new Map();
            responseTLV.set(TLVTypes.State, Buffer.from([0x06]));
            responseTLV.set(TLVTypes.Error, Buffer.from([ErrorCodes.Authentication]));

            response.writeHead(200, { 'Content-Type': 'application/pairing+tlv8' });
            response.write(TLV.encode(responseTLV));
            response.end();
            return;
        }

        // Generate accessories Ed25519 long-term public key, AccessoryLTPK, and long-term secret key, AccessoryLTSK.
        const keyPair = sodium.api.crypto_sign_ed25519_keypair();
        if (!keyPair) {
            throw new Error('could not generate key pairs.');
        }
        const accessoryLTPK = keyPair.publicKey;
        const accessoryLTSK = keyPair.secretKey;

        // Derive AccessoryX from the SRP shared secret.
        const saltAccessory = Buffer.from('Pair-Setup-Accessory-Sign-Salt');
        const infoAccessory = Buffer.from('Pair-Setup-Accessory-Sign-Info');
        const accessoryX = hkdf('sha512', session.sharedSecret, saltAccessory, infoAccessory, 32);

        // Signing AccessorySignature.
        const accessoryPairingId = Buffer.from(this.deviceId);
        const accessoryInfo = Buffer.concat([accessoryX, accessoryPairingId, accessoryLTPK]);
        const accessorySignature = sodium.api.crypto_sign_ed25519_detached(accessoryInfo, accessoryLTSK);
        if (!accessorySignature) {
            throw new Error('could not sign accessoryInfo.');
        }

        const subTLV2 = new Map();
        subTLV2.set(TLVTypes.Identifier, accessoryPairingId);
        subTLV2.set(TLVTypes.PublicKey, accessoryLTPK);
        subTLV2.set(TLVTypes.Signature, accessorySignature);
        const subTLVData = TLV.encode(subTLV2);

        const nonceM6 = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x00]), Buffer.from('PS-Msg06')]);
        const encryptedSubTLV = sodium.api.crypto_aead_chacha20poly1305_ietf_encrypt(subTLVData, null, nonceM6, session.sessionKey);
        if (!encryptedSubTLV) {
            throw new Error('could not encrypt sub-tlv.');
        }

        const responseTLV: TLV.TLVMap = new Map();
        responseTLV.set(TLVTypes.State, Buffer.from([0x06]));
        responseTLV.set(TLVTypes.EncryptedData, encryptedSubTLV);

        response.writeHead(200, { 'Content-Type': 'application/pairing+tlv8' });
        response.write(TLV.encode(responseTLV));
        response.end();

        session.pairState = 6;
    }

    private async handlePairVerify(request: http.IncomingMessage, response: http.ServerResponse, body: Buffer) {

    }

    private async handlePairings(request: http.IncomingMessage, response: http.ServerResponse, body: Buffer) {

    }

    async start() {
        const port = await this.httpServer.listen();
        const service = await this.advertiser.start(port);
        console.log(service);
        console.log(port);

    }

    reset() {

    }

    shutdown() {

    }

}