import * as crypto from 'crypto';
import * as http from 'http';
import { Transform } from 'stream';
import * as url from 'url';
import { hkdf } from '../crypto/hkdf/hkdf';
import { SRPConfigurations } from '../crypto/srp/configurations';
import { SecureRemotePassword } from '../crypto/srp/srp';
import { MemoryStorage } from '../services/memory-storage';
import { Storage } from '../services/storage';
import { HTTPHandler } from '../transport/http-handler';
import { HttpServer } from '../transport/http-server';
import { NetProxy, ProxyConnection } from '../transport/net-proxy';
import * as tlv from '../transport/tlv';
import { TLVMap } from '../transport/tlv';
import { Advertiser } from './advertiser';
import { ErrorCodes } from './constants/error-codes';
import { HTTPStatusCodes } from './constants/http-status-codes';
import { PairMethods } from './constants/pair-methods';
import { PairState } from './constants/pair-state';
import { TLVTypes } from './constants/tlv-types';
import { HAPUrls } from './constants/urls';
import { VerifyState } from './constants/verify-state';
import { SecureDecryptStream } from './secure-decrypt-stream';
import { SecureEncryptStream } from './secure-encrypt-stream';
import { SimpleLogger } from '../util/simple-logger';
import { LogLevel } from "../util/debug-level";
import { Logger } from '../util/logger';

const sodium = require('sodium');


export interface AccessoryLongTimeKeyPair {
    publicKey: Buffer;
    privateKey: Buffer;
}

export interface Pairing {
    devicePairingId: Buffer;
    deviceLongTimePublicKey: Buffer;
}

interface PairSetupContext {
    state: PairState;
    srp?: SecureRemotePassword;
    sharedSecret?: Buffer;
    sessionKey?: Buffer;
}

interface PairVerifyContext {
    state: VerifyState;
    devicePublicKey?: Buffer;
    accessoryPublicKey?: Buffer;
    sharedSecret?: Buffer;
    sessionKey?: Buffer;
}

export interface Session {
    authenticationAttempts: number;
    pairContext: PairSetupContext;
    verifyContext: PairVerifyContext;
    decryptStream?: SecureDecryptStream;
    encryptStream?: SecureEncryptStream;

}

const defaultSession: Session = {
    authenticationAttempts: 0,
    pairContext: {
        state: PairState.INITIAL
    },
    verifyContext: {
        state: VerifyState.INITIAL
    }
};

interface Route {
    pathname: HAPUrls;
    method: string;
    contentType: HAPContentTypes;
    handler: (session: Session, request: http.IncomingMessage, response: http.ServerResponse, body: tlv.TLVMap | any) => Promise<void>;
}

enum HAPContentTypes {
    TLV8 = 'application/pairing+tlv8',
    JSON = 'application/hap+json',
    EMPTY = ''
}

export class HAPServer implements HTTPHandler {

    private logger: Logger = new SimpleLogger('HAPServer');

    private storage: Storage = new MemoryStorage();

    private proxyServer: NetProxy = new NetProxy((connection) => {
        return this.createDecryptStream(connection);
    }, (connection) => {
        return this.createEncryptStream(connection);
    });

    private httpServer: HttpServer = new HttpServer(this);

    private advertiser: Advertiser;

    private sessions: Map<number, Session> = new Map();

    private longTimeKeyPair: AccessoryLongTimeKeyPair;


    public constructor(private deviceId: string,
                       private modelName: string,
                       private categoryIdentifier) {

        this.proxyServer.on('connect', (connection) => {
            this.handleProxyConnect(connection);
        });

        this.proxyServer.on('close', (rayId) => {
            this.handleProxyClose(rayId);
        });

        this.advertiser = new Advertiser(deviceId, modelName, categoryIdentifier, 1);
    }

    async handleRequest(request: http.IncomingMessage, response: http.ServerResponse, body: Buffer): Promise<void> {
        const proxyConnection = this.proxyConnectionFromRequest(request);
        if (!proxyConnection) {
            // We do not allow connections without proxy.
            request.socket.end();
            return;
        }

        const session = this.sessions.get(proxyConnection.rayId);

        // Route request.
        const requestPathname = url.parse(request.url).pathname;
        const requestMethod = request.method;
        const requestContentType = request.headers['content-type'] || HAPContentTypes.EMPTY;
        const routes: Route[] = [
            {
                pathname: HAPUrls.PairSetup,
                method: 'POST',
                contentType: HAPContentTypes.TLV8,
                handler: (session, request, response, body) => {
                    return this.handlePairSetup(session, request, response, body);
                }
            },
            {
                pathname: HAPUrls.PairVerify,
                method: 'POST',
                contentType: HAPContentTypes.TLV8,
                handler: (session, request, response, body) => {
                    return this.handlePairVerify(session, request, response, body);
                }
            },
            {
                pathname: HAPUrls.Pairings,
                method: 'POST',
                contentType: HAPContentTypes.TLV8,
                handler: (session, request, response, body) => {
                    return this.handlePairings(session, request, response, body);
                }
            },
            {
                pathname: HAPUrls.Accessories,
                method: 'GET',
                contentType: HAPContentTypes.EMPTY,
                handler: (session, request, response, body) => {
                    return this.handleAttributeDatabase(session, request, response);
                }
            },
            {
                pathname: HAPUrls.Characteristics,
                method: 'GET',
                contentType: HAPContentTypes.JSON,
                handler: () => new Promise((resolve, reject) => {
                })
            },
            {
                pathname: HAPUrls.Characteristics,
                method: 'PUT',
                contentType: HAPContentTypes.JSON,
                handler: () => new Promise((resolve, reject) => {
                })
            },
            {
                pathname: HAPUrls.Identify,
                method: 'POST',
                contentType: HAPContentTypes.EMPTY,
                handler: () => new Promise((resolve, reject) => {
                })
            }
        ];

        this.logger.info('Request on Ray:', proxyConnection.rayId);
        this.logger.logRequest(LogLevel.Info, request);

        // Math pathname.
        let matching: Route[] = routes.filter((route) => route.pathname === requestPathname);
        if (matching) {
            // Math method.
            matching = matching.filter((route) => {
                return route.method === requestMethod;
            });
            if (matching) {
                // Match content-type.
                matching = matching.filter((route) => {
                    return route.contentType === requestContentType;
                });
                if (matching) {
                    // There should be only one route left.
                    const matchingRoute = matching[0];

                    // Parse body if not empty.
                    let parsedBody: TLVTypes | any;
                    if (body.length > 0) {
                        try {
                            if (matchingRoute.contentType === HAPContentTypes.TLV8) {
                                this.logger.debug('parse body as TLV');
                                parsedBody = tlv.decode(body);
                                this.logger.logTLV(LogLevel.Debug, parsedBody);
                            } else if (matchingRoute.contentType === HAPContentTypes.JSON) {
                                this.logger.debug('parse body as JSON');
                                parsedBody = JSON.parse(body.toString());
                                this.logger.debug(body.toString());
                            }
                        } catch (err) {
                            this.logger.error('could not parse body', err);
                            response.writeHead(HTTPStatusCodes.BadRequest);
                        }
                    } else {
                        this.logger.debug('empty body');
                    }

                    // Call handler.
                    await matchingRoute.handler(session, request, response, parsedBody);

                } else {
                    // HTTP: Unsupported Media Type.
                    response.writeHead(415);
                }

            } else {
                response.writeHead(HTTPStatusCodes.MethodNotAllowed);
            }
        } else {
            response.writeHead(404);
        }


        response.end();
    }

    private createDecryptStream(connection: ProxyConnection): Transform {
        const session = this.sessions.get(connection.rayId);
        this.logger.debug(`creating decrypt-stream for rayId: ${connection.rayId}`);
        const decryptStream = new SecureDecryptStream();
        session.decryptStream = decryptStream;

        return decryptStream;
    }

    private createEncryptStream(connection: ProxyConnection): Transform {
        const session = this.sessions.get(connection.rayId);
        this.logger.debug(`creating encrypt-stream for rayId: ${connection.rayId}`);
        const encryptStream = new SecureEncryptStream();
        session.encryptStream = encryptStream;

        return encryptStream;
    }

    async start() {
        this.longTimeKeyPair = await this.getLongTimeKeyPair();

        // TODO: Move to index because will be singleton.
        const storageConnected = await  this.storage.connect();
        if (!storageConnected) {
            throw new Error('Storage not connected!');
        }

        const httpAddress = await this.httpServer.listen(0, '127.0.0.1');

        const proxyAddress = await this.proxyServer.listen(httpAddress.address, httpAddress.port);

        const service = await this.advertiser.start(proxyAddress.port);

    }

    private async getLongTimeKeyPair(): Promise<AccessoryLongTimeKeyPair> {
        // Generate accessories Ed25519 long-term public key, AccessoryLTPK, and long-term secret key, AccessoryLTSK.
        let longTimeKeyPair = await this.storage.getAccessoryLongTimeKeyPair(this.deviceId);
        if (!longTimeKeyPair) {
            const keyPair = sodium.api.crypto_sign_ed25519_keypair();
            if (!keyPair) {
                throw new Error('could not generate key pairs.');
            }

            longTimeKeyPair = {
                publicKey: keyPair.publicKey,
                privateKey: keyPair.secretKey
            };
        }

        return longTimeKeyPair;
    }

    private handleProxyConnect(connection: ProxyConnection) {
        this.logger.debug('proxy connected', connection.rayId);
        this.sessions.set(connection.rayId, defaultSession);
    }

    private handleProxyClose(rayId: number) {
        this.logger.debug('proxy closed', rayId);
        this.sessions.delete(rayId);
    }

    private proxyConnectionFromRequest(request: http.IncomingMessage): ProxyConnection {
        const proxyConnections = this.proxyServer.getConnections();
        for (const connection of proxyConnections) {
            const remoteSocket = connection.remoteSocket;
            const requestSocket = request.socket;
            if (remoteSocket.remoteAddress === requestSocket.localAddress
                && remoteSocket.remotePort === requestSocket.localPort) {
                return connection;
            }
        }
    }

    private assignTLVContains(tlv: tlv.TLVMap, types: number[]): boolean {
        for (const type of types) {
            if (!tlv.has(type)) {
                return false;
            }
        }
        return true;
    }

    private async handlePairSetup(session: Session, request: http.IncomingMessage, response: http.ServerResponse, body: tlv.TLVMap): Promise<void> {
        const tlvTypes = [TLVTypes.State];
        if (!this.assignTLVContains(body, tlvTypes)) {
            response.writeHead(HTTPStatusCodes.BadRequest);
            return;
        }

        const state: PairState = body.get(TLVTypes.State).readUInt8(0);
        if (state !== (session.pairContext.state + 1)) {
            session.pairContext = defaultSession.pairContext; // TODO: Object.assign({}, defaultSession.pairContext)
            response.writeHead(HTTPStatusCodes.BadRequest);
            return;
        }

        switch (state) {
            case PairState.M1:
                await this.handlePairSetupStepOne(session, request, response, body);
                break;

            case PairState.M3:
                await this.handlePairSetupStepThree(session, request, response, body);
                break;

            case PairState.M5:
                await this.handlePairSetupStepFive(session, request, response, body);
                break;
        }
    }

    private async handlePairSetupStepOne(session: Session, request: http.IncomingMessage, response: http.ServerResponse, body: TLVMap) {
        const tlvTypes = [TLVTypes.Method];
        if (!this.assignTLVContains(body, tlvTypes)) {
            response.writeHead(HTTPStatusCodes.BadRequest);
            return;
        }

        const method = body.get(TLVTypes.Method).readUInt8(0);
        if (method !== PairMethods.PairSetup) {
            //response.writeHead(HTTPStatusCodes.BadRequest);
            // return;
        }

        // Check authentication attempts.
        if (session.authenticationAttempts > 100) { // TODO: Use constant.
            // TODO: Implement.
        }

        const username = 'Pair-Setup'; // TODO: As property.
        const password = '123-99-123'; // TODO: As property.
        const serverPrivateKey = crypto.randomBytes(16);
        const salt = crypto.randomBytes(16);
        const srp = new SecureRemotePassword(username, password, salt, SRPConfigurations[3072], serverPrivateKey);


        const state = Buffer.from([PairState.M2]);
        const publicKey = srp.getServerPublicKey();

        const responseTLV: tlv.TLVMap = new Map();
        responseTLV.set(TLVTypes.State, state);
        responseTLV.set(TLVTypes.PublicKey, publicKey);
        responseTLV.set(TLVTypes.Salt, salt);

        response.writeHead(HTTPStatusCodes.OK, { 'Content-Type': HAPContentTypes.TLV8 });
        response.write(tlv.encode(responseTLV));

        session.pairContext.state = PairState.M2;
        session.pairContext.srp = srp;
    }

    private async handlePairSetupStepThree(session: Session, request: http.IncomingMessage, response: http.ServerResponse, body: TLVMap) {
        const srp = session.pairContext.srp;
        const tlvTypes = [TLVTypes.PublicKey, TLVTypes.Proof];
        if (!this.assignTLVContains(body, tlvTypes)) {
            response.writeHead(HTTPStatusCodes.BadRequest);
            return;
        }

        const deviceSRPPublicKey = body.get(TLVTypes.PublicKey);
        const deviceSRPProof = body.get(TLVTypes.Proof);

        // Verify client proof.
        srp.setClientPublicKey(deviceSRPPublicKey);
        const sharedSecret = srp.getSessionKey();
        const verified = srp.verifyProof(deviceSRPProof);
        if (!verified) {
            session.pairContext = defaultSession.pairContext;

            const responseTLV: tlv.TLVMap = new Map();
            responseTLV.set(TLVTypes.State, Buffer.from([PairState.M4]));
            responseTLV.set(TLVTypes.Error, Buffer.from([ErrorCodes.Authentication]));

            response.writeHead(HTTPStatusCodes.OK, { 'Content-Type': HAPContentTypes.TLV8 });
            response.write(tlv.encode(responseTLV));
            return;
        }

        // Derive session key from SRP shared secret.
        const pairSetupEncryptSalt = Buffer.from('Pair-Setup-Encrypt-Salt');
        const pairSetupEncryptInfo = Buffer.from('Pair-Setup-Encrypt-Info');
        const sessionKey = hkdf('sha512', sharedSecret, pairSetupEncryptSalt, pairSetupEncryptInfo, 32);


        const accessorySRPProof = srp.getProof();
        const responseTLV: tlv.TLVMap = new Map();
        responseTLV.set(TLVTypes.State, Buffer.from([0x04]));
        responseTLV.set(TLVTypes.Proof, accessorySRPProof);

        response.writeHead(HTTPStatusCodes.OK, { 'Content-Type': HAPContentTypes.TLV8 });
        response.write(tlv.encode(responseTLV));

        session.pairContext.state = PairState.M4;
        session.pairContext.sharedSecret = sharedSecret;
        session.pairContext.sessionKey = sessionKey;
    }

    private async handlePairSetupStepFive(session: Session, request: http.IncomingMessage, response: http.ServerResponse, body: TLVMap) {
        const tlvTypes = [TLVTypes.EncryptedData];
        if (!this.assignTLVContains(body, tlvTypes)) {
            response.writeHead(HTTPStatusCodes.BadRequest);
            return;
        }

        // Check for any errors.
        const clientError = body.get(TLVTypes.Error);
        if (clientError) {
            session.pairContext = defaultSession.pairContext;
            return;
        }

        const encryptedData = body.get(TLVTypes.EncryptedData);

        // Decrypt sub-tlv.
        const nonceM5 = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x00]), Buffer.from('PS-Msg05')]);
        const decryptedData = sodium.api.crypto_aead_chacha20poly1305_ietf_decrypt(encryptedData, null, nonceM5, session.pairContext.sessionKey);
        if (!decryptedData) {
            session.pairContext = defaultSession.pairContext;

            const responseTLV: tlv.TLVMap = new Map();
            responseTLV.set(TLVTypes.State, Buffer.from([PairState.M5]));
            responseTLV.set(TLVTypes.Error, Buffer.from([ErrorCodes.Authentication]));

            response.writeHead(HTTPStatusCodes.BadRequest, { 'Content-Type': HAPContentTypes.TLV8 });
            response.write(tlv.encode(responseTLV));
            return;
        }

        // Decode sub-tlv.
        const subTLV = tlv.decode(decryptedData);
        const devicePairingId = subTLV.get(TLVTypes.Identifier);
        console.log('devicePairingId', devicePairingId.toString());
        const deviceLongTimePublicKey = subTLV.get(TLVTypes.PublicKey);
        const deviceSignature = subTLV.get(TLVTypes.Signature);

        // Derive deviceX from the SRP shared secret.
        const pairSetupControllerSignSalt = Buffer.from('Pair-Setup-Controller-Sign-Salt');
        const pairSetupControllerSignInfo = Buffer.from('Pair-Setup-Controller-Sign-Info');
        const deviceX = hkdf('sha512', session.pairContext.sharedSecret, pairSetupControllerSignSalt, pairSetupControllerSignInfo, 32);

        // Verify the signature of the constructed deviceInfo with the deviceLTPK from the decrypted sub-tlv.
        const deviceInfo = Buffer.concat([deviceX, devicePairingId, deviceLongTimePublicKey]);
        const verified = sodium.api.crypto_sign_ed25519_verify_detached(deviceSignature, deviceInfo, deviceLongTimePublicKey);
        if (!verified) {
            session.pairContext = defaultSession.pairContext;

            const responseTLV: tlv.TLVMap = new Map();
            responseTLV.set(TLVTypes.State, Buffer.from([PairState.M6]));
            responseTLV.set(TLVTypes.Error, Buffer.from([ErrorCodes.Authentication]));

            response.writeHead(HTTPStatusCodes.OK, { 'Content-Type': HAPContentTypes.TLV8 });
            response.write(tlv.encode(responseTLV));
            return;
        }

        const accessoryLongTimePublicKey = this.longTimeKeyPair.publicKey;
        const accessoryLongTimePrivateKey = this.longTimeKeyPair.privateKey;

        // Derive AccessoryX from the SRP shared secret.
        const pairSetupAccessorySignSalt = Buffer.from('Pair-Setup-Accessory-Sign-Salt');
        const pairSetupAccessorySignInfo = Buffer.from('Pair-Setup-Accessory-Sign-Info');
        const accessoryX = hkdf('sha512', session.pairContext.sharedSecret, pairSetupAccessorySignSalt, pairSetupAccessorySignInfo, 32);

        // Signing AccessorySignature.
        const accessoryPairingId = Buffer.from(this.deviceId);
        const accessoryInfo = Buffer.concat([accessoryX, accessoryPairingId, accessoryLongTimePublicKey]);
        const accessorySignature = sodium.api.crypto_sign_ed25519_detached(accessoryInfo, accessoryLongTimePrivateKey);
        if (!accessorySignature) {
            throw new Error('could not sign accessoryInfo.');
        }

        const subTLV2 = new Map();
        subTLV2.set(TLVTypes.Identifier, accessoryPairingId);
        subTLV2.set(TLVTypes.PublicKey, accessoryLongTimePublicKey);
        subTLV2.set(TLVTypes.Signature, accessorySignature);
        const subTLVData = tlv.encode(subTLV2);

        const nonceM6 = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x00]), Buffer.from('PS-Msg06')]);
        const encryptedSubTLV = sodium.api.crypto_aead_chacha20poly1305_ietf_encrypt(subTLVData, null, nonceM6, session.pairContext.sessionKey);
        if (!encryptedSubTLV) {
            throw new Error('could not encrypt sub-tlv.');
        }

        const responseTLV: tlv.TLVMap = new Map();
        responseTLV.set(TLVTypes.State, Buffer.from([PairState.M6]));
        responseTLV.set(TLVTypes.EncryptedData, encryptedSubTLV);

        response.writeHead(HTTPStatusCodes.OK, { 'Content-Type': HAPContentTypes.TLV8 });
        response.write(tlv.encode(responseTLV));

        const saved = await this.storage.persistControllerLongTimePublicKey(devicePairingId.toString(), deviceLongTimePublicKey);
        if (!saved) {
            throw new Error('could not write device long time key to storage.');
        }

        session.pairContext.state = PairState.M6;
    }

    private async handlePairVerify(session: Session, request: http.IncomingMessage, response: http.ServerResponse, body: tlv.TLVMap): Promise<void> {
        const tlvTypes = [TLVTypes.State];
        if (!this.assignTLVContains(body, tlvTypes)) {
            response.writeHead(HTTPStatusCodes.BadRequest);
            return;
        }

        const state: VerifyState = body.get(TLVTypes.State).readUInt8(0);
        console.log('verify step', state);
        if (state !== (session.verifyContext.state + 1)) {
            session.verifyContext = defaultSession.verifyContext;
            response.writeHead(HTTPStatusCodes.BadRequest);
            return;
        }

        switch (state) {
            case VerifyState.M1:
                await this.handlePairVerifyStepOne(session, request, response, body);
                break;

            case VerifyState.M3:
                await this.handlePairVerifyStepThree(session, request, response, body);
                break;
        }
    }

    private async handlePairVerifyStepOne(session: Session, request: http.IncomingMessage, response: http.ServerResponse, body: TLVMap) {
        const tlvTypes = [TLVTypes.PublicKey];
        if (!this.assignTLVContains(body, tlvTypes)) {
            response.writeHead(HTTPStatusCodes.BadRequest);
            return;
        }

        const clientPublicKey = body.get(TLVTypes.PublicKey);

        const keyPair = sodium.api.crypto_sign_ed25519_keypair();
        if (!keyPair) {
            throw new Error('could not generate key pairs.');
        }
        const accessoryPublicKey = sodium.api.crypto_sign_ed25519_pk_to_curve25519(keyPair.publicKey);
        const accessoryPrivateKey = sodium.api.crypto_sign_ed25519_sk_to_curve25519(keyPair.secretKey);
        const sharedSecret = sodium.api.crypto_scalarmult_curve25519(accessoryPrivateKey, clientPublicKey);

        const accessoryLongTimePrivateKey = this.longTimeKeyPair.privateKey;

        const accessoryPairingId = Buffer.from(this.deviceId);
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
        subTLV.set(TLVTypes.Identifier, accessoryPairingId);
        subTLV.set(TLVTypes.Signature, accessorySignature);
        const subTLVData = tlv.encode(subTLV);

        const nonce = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x00]), Buffer.from('PV-Msg02')]);
        const encryptedSubTLV = sodium.api.crypto_aead_chacha20poly1305_ietf_encrypt(subTLVData, null, nonce, sessionKey);
        if (!encryptedSubTLV) {
            throw new Error('could not encrypt sub-tlv.');
        }

        const responseTLV: tlv.TLVMap = new Map();
        responseTLV.set(TLVTypes.State, Buffer.from([VerifyState.M2]));
        responseTLV.set(TLVTypes.PublicKey, accessoryPublicKey);
        responseTLV.set(TLVTypes.EncryptedData, encryptedSubTLV);

        response.writeHead(HTTPStatusCodes.OK, { 'Content-Type': HAPContentTypes.TLV8 });
        response.write(tlv.encode(responseTLV));

        session.verifyContext.state = VerifyState.M2;
        session.verifyContext.devicePublicKey = clientPublicKey;
        session.verifyContext.accessoryPublicKey = accessoryPublicKey;
        session.verifyContext.sharedSecret = sharedSecret;
        session.verifyContext.sessionKey = sessionKey;
    }

    private async handlePairVerifyStepThree(session: Session, request: http.IncomingMessage, response: http.ServerResponse, body: TLVMap) {
        const tlvTypes = [TLVTypes.EncryptedData];
        if (!this.assignTLVContains(body, tlvTypes)) {
            response.writeHead(HTTPStatusCodes.BadRequest);
            return;
        }

        const encryptedData = body.get(TLVTypes.EncryptedData);

        // Decrypt sub-tlv.
        const sessionKey = session.verifyContext.sessionKey;
        const nonce = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x00]), Buffer.from('PV-Msg03')]);
        const decryptedData = sodium.api.crypto_aead_chacha20poly1305_ietf_decrypt(encryptedData, null, nonce, sessionKey);
        if (!decryptedData) {
            session.verifyContext = defaultSession.verifyContext;

            const responseTLV: tlv.TLVMap = new Map();
            responseTLV.set(TLVTypes.State, Buffer.from([VerifyState.M4]));
            responseTLV.set(TLVTypes.Error, Buffer.from([ErrorCodes.Authentication]));

            response.writeHead(HTTPStatusCodes.BadRequest, { 'Content-Type': HAPContentTypes.TLV8 });
            response.write(tlv.encode(responseTLV));
            return;
        }

        // Decode sub-tlv.
        const subTLV = tlv.decode(decryptedData);
        const subTLVTypes = [TLVTypes.Identifier, TLVTypes.Signature];
        if (!this.assignTLVContains(subTLV, subTLVTypes)) {
            response.writeHead(HTTPStatusCodes.BadRequest);
            return;
        }

        const devicePairingId = subTLV.get(TLVTypes.Identifier);
        console.log('devicePairingId', devicePairingId.toString());
        const deviceSignature = subTLV.get(TLVTypes.Signature);
        const deviceLongTimePublicKey = await this.storage.getControllerLongTimePublicKey(devicePairingId.toString());
        if (!deviceLongTimePublicKey) {
            const responseTLV: tlv.TLVMap = new Map();
            responseTLV.set(TLVTypes.State, Buffer.from([VerifyState.M4]));
            responseTLV.set(TLVTypes.Error, Buffer.from([ErrorCodes.Authentication]));

            response.writeHead(HTTPStatusCodes.BadRequest, { 'Content-Type': HAPContentTypes.TLV8 });
            response.write(tlv.encode(responseTLV));
            return;
        }


        const devicePublicKey = session.verifyContext.devicePublicKey;
        const accessoryPublicKey = session.verifyContext.accessoryPublicKey;
        const deviceInfo = Buffer.concat([devicePublicKey, devicePairingId, accessoryPublicKey]);

        const verified = sodium.api.crypto_sign_ed25519_verify_detached(deviceSignature, deviceInfo, deviceLongTimePublicKey);
        if (!verified) {
            session.verifyContext = defaultSession.verifyContext;

            const responseTLV: tlv.TLVMap = new Map();
            responseTLV.set(TLVTypes.State, Buffer.from([PairState.M6]));
            responseTLV.set(TLVTypes.Error, Buffer.from([ErrorCodes.Authentication]));

            response.writeHead(HTTPStatusCodes.OK, { 'Content-Type': HAPContentTypes.TLV8 });
            response.write(tlv.encode(responseTLV));
            return;
        }

        const responseTLV: tlv.TLVMap = new Map();
        responseTLV.set(TLVTypes.State, Buffer.from([VerifyState.M4]));

        response.writeHead(HTTPStatusCodes.OK, { 'Content-Type': HAPContentTypes.TLV8 });
        response.write(tlv.encode(responseTLV));


        const sharedSecret = session.verifyContext.sharedSecret;
        const controlSalt = Buffer.from('Control-Salt');
        const controlReadEncryptionKey = Buffer.from('Control-Read-Encryption-Key');
        const controlWriteEncryptionKey = Buffer.from('Control-Write-Encryption-Key');
        const accessoryToControllerKey = hkdf('sha512', sharedSecret, controlSalt, controlReadEncryptionKey, 32);
        const controllerToAccessoryKey = hkdf('sha512', sharedSecret, controlSalt, controlWriteEncryptionKey, 32);

        session.verifyContext.state = VerifyState.M4;
        session.decryptStream.setKey(controllerToAccessoryKey);
        session.decryptStream.enable();
        session.encryptStream.setKey(accessoryToControllerKey);
        session.decryptStream.once('data', () => {
            session.encryptStream.enable();
        });
    }

    private async handlePairings(session: Session, request: http.IncomingMessage, response: http.ServerResponse, body: tlv.TLVMap): Promise<void> {
        const tlvTypes = [TLVTypes.State, TLVTypes.Method]; //, TLVTypes.Identifier, TLVTypes.PublicKey, TLVTypes.Permissions];
        if (!this.assignTLVContains(body, tlvTypes)) {
            response.writeHead(HTTPStatusCodes.BadRequest);
            return;
        }

        const state = body.get(TLVTypes.State);
        const method = body.get(TLVTypes.Method);
        /*
                const deviceIdentifier = body.get(TLVTypes.Identifier);
                const devicePublicKey = body.get(TLVTypes.PublicKey);
                const devicePermissions = body.get(TLVTypes.Permissions);
                */
        console.log(method);

        //console.log(deviceIdentifier);
        //console.log(devicePermissions);
        const responseTLV: tlv.TLVMap = new Map();
        responseTLV.set(TLVTypes.State, Buffer.from([0x02]));

        response.writeHead(HTTPStatusCodes.OK, { 'Content-Type': HAPContentTypes.TLV8 });
        response.write(tlv.encode(responseTLV));
    }

    private async handleAttributeDatabase(session: Session, request: http.IncomingMessage, response: http.ServerResponse): Promise<void> {
        const db = {
            "accessories": [{
                "aid": 1,
                "services": [{
                    "iid": 1,
                    "type": "0000003E-0000-1000-8000-0026BB765291",
                    "characteristics": [{
                        "iid": 2,
                        "type": "00000014-0000-1000-8000-0026BB765291",
                        "perms": ["pw"],
                        "format": "bool",
                        "description": "Identify"
                    }, {
                        "iid": 3,
                        "type": "00000020-0000-1000-8000-0026BB765291",
                        "perms": ["pr"],
                        "format": "string",
                        "value": "Sample Company",
                        "description": "Manufacturer"
                    }, {
                        "iid": 4,
                        "type": "00000021-0000-1000-8000-0026BB765291",
                        "perms": ["pr"],
                        "format": "string",
                        "value": "Default-Model",
                        "description": "Model"
                    }, {
                        "iid": 5,
                        "type": "00000023-0000-1000-8000-0026BB765291",
                        "perms": ["pr"],
                        "format": "string",
                        "value": "Fan",
                        "description": "Name"
                    }, {
                        "iid": 6,
                        "type": "00000030-0000-1000-8000-0026BB765291",
                        "perms": ["pr"],
                        "format": "string",
                        "value": "Default-SerialNumber",
                        "description": "Serial Number"
                    }]
                }, {
                    "iid": 7,
                    "type": "00000040-0000-1000-8000-0026BB765291",
                    "characteristics": [{
                        "iid": 8,
                        "type": "00000023-0000-1000-8000-0026BB765291",
                        "perms": ["pr"],
                        "format": "string",
                        "value": "Fan",
                        "description": "Name"
                    }, {
                        "iid": 9,
                        "type": "00000025-0000-1000-8000-0026BB765291",
                        "perms": ["pr", "pw", "ev"],
                        "format": "bool",
                        "value": false,
                        "description": "On"
                    }, {
                        "iid": 10,
                        "type": "00000029-0000-1000-8000-0026BB765291",
                        "perms": ["pr", "pw", "ev"],
                        "format": "float",
                        "value": 0,
                        "description": "Rotation Speed",
                        "unit": "percentage",
                        "maxValue": 100,
                        "minValue": 0,
                        "minStep": 1
                    }]
                }]
            }]
        };

        const out = JSON.stringify(db);
        response.writeHead(200, {
            'Content-Type': HAPContentTypes.JSON
        });

        response.write(out);
    }
}