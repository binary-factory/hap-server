import * as crypto from 'crypto';
import * as http from 'http';
import * as url from 'url';
import { hkdf } from '../crypto/hkdf/hkdf';
import { SRPConfigurations } from '../crypto/srp/configurations';
import { SecureRemotePassword } from '../crypto/srp/srp';
import { Advertiser } from './advertiser';
import { ErrorCodes } from './constants/error-codes';
import { HTTPStatusCodes } from './constants/http-status-codes';
import { TLVTypes } from './constants/tlv-types';
import { HAPUrls } from './constants/urls';
import { HTTPHandler } from '../transport/http-handler';
import { HttpServer } from '../transport/http-server';
import { NetProxy, ProxyConnection } from '../transport/net-proxy';
import { ProxyHandler } from '../transport/proxy-handler';
import * as tlv from '../transport/tlv';
import { TLVMap } from '../transport/tlv';
import { SimpleLogger } from '../util/simple-logger';
import { PairState } from './constants/pair-state';
import { PairMethods } from './constants/pair-methods';
import { VerifyState } from './constants/verify-state';

const sodium = require('sodium');

export interface HAPSession {
    pairState: PairState;
    verifyState: VerifyState;
    authenticationAttempts: number;
    srp?: SecureRemotePassword;
    sessionKey?: Buffer;
    sharedSecret?: Buffer;
}

const defaultSession: HAPSession = {
    pairState: PairState.INITIAL,
    verifyState: VerifyState.INITIAL,
    authenticationAttempts: 0
};

interface Route {
    pathname: HAPUrls;
    method: string;
    contentType: HAPContentTypes;
    handler: (session: HAPSession, request: http.IncomingMessage, response: http.ServerResponse, body: tlv.TLVMap | any) => Promise<void>;
}

enum HAPContentTypes {
    TLV8 = 'application/pairing+tlv8',
    JSON = 'application/hap+json',
    EMPTY = ''
}

interface HAPPairing {
    accessoryPairingId: Buffer;
    accessoryLTPK: Buffer;
    accessoryLTSK: Buffer;
    iOSDevicePairingId: Buffer;
    iOSDeviceLTPK: Buffer;
}

export class HAPServer implements ProxyHandler, HTTPHandler {

    private logger: SimpleLogger = new SimpleLogger('HAPServer');

    private proxyServer: NetProxy = new NetProxy(this);

    private httpServer: HttpServer = new HttpServer(this);

    private advertiser: Advertiser;

    private sessions: Map<number, HAPSession> = new Map();

    private pairing: HAPPairing;

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

    async transformIncomingData(connection: ProxyConnection, chunk: Buffer, encoding: string): Promise<Buffer> {
        const session = this.sessions.get(connection.rayId);
        console.log('incoming data');
        return chunk;
    }

    async transformOutgoingData(connection: ProxyConnection, chunk: Buffer, encoding: string): Promise<Buffer> {
        const session = this.sessions.get(connection.rayId);
        console.log('outgoing data');
        return chunk;
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
        console.log(requestPathname);
        console.log(requestMethod);
        console.log(requestContentType);

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
                    if (body.length) {
                        try {
                            if (matchingRoute.contentType === HAPContentTypes.TLV8) {
                                parsedBody = tlv.decode(body);
                            } else if (matchingRoute.contentType === HAPContentTypes.JSON) {
                                parsedBody = JSON.parse(body.toString());
                            }
                        } catch (err) {
                            response.writeHead(HTTPStatusCodes.BadRequest);
                        }
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


    async listen() {

        const httpAddress = await this.httpServer.listen(0, '127.0.0.1');

        const proxyAddress = await this.proxyServer.listen(httpAddress.address, httpAddress.port);

        const service = await this.advertiser.start(proxyAddress.port);
    }

    private handleProxyConnect(connection: ProxyConnection) {
        console.log('proxy connected', connection.rayId);
        this.sessions.set(connection.rayId, defaultSession);
    }

    private handleProxyClose(rayId: number) {
        console.log('proxy closed', rayId);
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

    private async handlePairSetup(session: HAPSession, request: http.IncomingMessage, response: http.ServerResponse, body: tlv.TLVMap): Promise<void> {
        console.log('handlePairSetup');
        const tlvTypes = [TLVTypes.State];
        if (!this.assignTLVContains(body, tlvTypes)) {
            response.writeHead(HTTPStatusCodes.BadRequest);
            return;
        }

        const state: PairState = body.get(TLVTypes.State).readUInt8(0);
        console.log('state', state);
        if (state !== (session.pairState + 1)) {
            console.log('state missmatch', session.pairState);
            session.pairState = PairState.INITIAL;
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

    private async handlePairSetupStepOne(session: HAPSession, request: http.IncomingMessage, response: http.ServerResponse, body: TLVMap) {
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
        session.srp = new SecureRemotePassword(username, password, salt, SRPConfigurations[3072], serverPrivateKey);


        const state = Buffer.from([PairState.M2]);
        const publicKey = session.srp.getServerPublicKey();

        const responseTLV: tlv.TLVMap = new Map();
        responseTLV.set(TLVTypes.State, state);
        responseTLV.set(TLVTypes.PublicKey, publicKey);
        responseTLV.set(TLVTypes.Salt, salt);

        response.writeHead(HTTPStatusCodes.OK, { 'Content-Type': HAPContentTypes.TLV8 });
        response.write(tlv.encode(responseTLV));

        session.pairState = PairState.M2;
    }

    private async handlePairSetupStepThree(session: HAPSession, request: http.IncomingMessage, response: http.ServerResponse, body: TLVMap) {
        const tlvTypes = [TLVTypes.PublicKey, TLVTypes.Proof];
        if (!this.assignTLVContains(body, tlvTypes)) {
            response.writeHead(HTTPStatusCodes.BadRequest);
            return;
        }

        const publicKey = body.get(TLVTypes.PublicKey);
        const clientProof = body.get(TLVTypes.Proof);

        // Verify client proof.
        const srp = session.srp;
        srp.setClientPublicKey(publicKey);
        const sharedSecret = session.srp.getSessionKey();
        const verified = srp.verifyProof(clientProof);
        if (!verified) {
            session.pairState = PairState.INITIAL;

            const responseTLV: tlv.TLVMap = new Map();
            responseTLV.set(TLVTypes.State, Buffer.from([PairState.M4]));
            responseTLV.set(TLVTypes.Error, Buffer.from([ErrorCodes.Authentication]));

            response.writeHead(HTTPStatusCodes.OK, { 'Content-Type': HAPContentTypes.TLV8 });
            response.write(tlv.encode(responseTLV));
            return;
        }

        // Derive session key from SRP shared secret.
        const salt = Buffer.from('Pair-Setup-Encrypt-Salt');
        const info = Buffer.from('Pair-Setup-Encrypt-Info');
        session.sessionKey = hkdf('sha512', sharedSecret, salt, info, 32);
        session.sharedSecret = sharedSecret;

        const serverProof = srp.getProof();
        const responseTLV: tlv.TLVMap = new Map();
        responseTLV.set(TLVTypes.State, Buffer.from([0x04]));
        responseTLV.set(TLVTypes.Proof, serverProof);

        response.writeHead(HTTPStatusCodes.OK, { 'Content-Type': HAPContentTypes.TLV8 });
        response.write(tlv.encode(responseTLV));

        session.pairState = PairState.M4;
    }

    private async handlePairSetupStepFive(session: HAPSession, request: http.IncomingMessage, response: http.ServerResponse, body: TLVMap) {
        const tlvTypes = [TLVTypes.EncryptedData];
        if (!this.assignTLVContains(body, tlvTypes)) {
            response.writeHead(HTTPStatusCodes.BadRequest);
            return;
        }

        // Check for any errors.
        const clientError = body.get(TLVTypes.Error);
        if (clientError) {
            session.pairState = PairState.INITIAL;
            return;
        }

        const encryptedData = body.get(TLVTypes.EncryptedData);

        // Decrypt sub-tlv.
        const nonceM5 = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x00]), Buffer.from('PS-Msg05')]);
        const decryptedData = sodium.api.crypto_aead_chacha20poly1305_ietf_decrypt(encryptedData, null, nonceM5, session.sessionKey);
        if (!decryptedData) {
            session.pairState = PairState.INITIAL;

            const responseTLV: tlv.TLVMap = new Map();
            responseTLV.set(TLVTypes.State, Buffer.from([PairState.M5]));
            responseTLV.set(TLVTypes.Error, Buffer.from([ErrorCodes.Authentication]));

            response.writeHead(HTTPStatusCodes.BadRequest, { 'Content-Type': HAPContentTypes.TLV8 });
            response.write(tlv.encode(responseTLV));
            return;
        }

        // Decode sub-tlv.
        const subTLV = tlv.decode(decryptedData);
        const iOSDevicePairingId = subTLV.get(TLVTypes.Identifier);
        const iOSDeviceLTPK = subTLV.get(TLVTypes.PublicKey);
        const iOSDeviceSignature = subTLV.get(TLVTypes.Signature);

        // Derive iOSDeviceX from the SRP shared secret.
        const saltDevice = Buffer.from('Pair-Setup-Controller-Sign-Salt');
        const infoDevice = Buffer.from('Pair-Setup-Controller-Sign-Info');
        const iOSDeviceX = hkdf('sha512', session.sharedSecret, saltDevice, infoDevice, 32);

        // Verify the signature of the constructed iOSDeviceInfo with the iOSDeviceLTPK from the decrypted sub-tlv.
        const iOSDeviceInfo = Buffer.concat([iOSDeviceX, iOSDevicePairingId, iOSDeviceLTPK]);
        const verified = sodium.api.crypto_sign_ed25519_verify_detached(iOSDeviceSignature, iOSDeviceInfo, iOSDeviceLTPK);
        if (!verified) {
            session.pairState = PairState.INITIAL;

            const responseTLV: tlv.TLVMap = new Map();
            responseTLV.set(TLVTypes.State, Buffer.from([PairState.M6]));
            responseTLV.set(TLVTypes.Error, Buffer.from([ErrorCodes.Authentication]));

            response.writeHead(HTTPStatusCodes.OK, { 'Content-Type': HAPContentTypes.TLV8 });
            response.write(tlv.encode(responseTLV));
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
        const subTLVData = tlv.encode(subTLV2);

        const nonceM6 = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x00]), Buffer.from('PS-Msg06')]);
        const encryptedSubTLV = sodium.api.crypto_aead_chacha20poly1305_ietf_encrypt(subTLVData, null, nonceM6, session.sessionKey);
        if (!encryptedSubTLV) {
            throw new Error('could not encrypt sub-tlv.');
        }

        const responseTLV: tlv.TLVMap = new Map();
        responseTLV.set(TLVTypes.State, Buffer.from([PairState.M6]));
        responseTLV.set(TLVTypes.EncryptedData, encryptedSubTLV);

        response.writeHead(HTTPStatusCodes.OK, { 'Content-Type': HAPContentTypes.TLV8 });
        response.write(tlv.encode(responseTLV));

        session.pairState = PairState.M6;

        // Save pairing.
        const pairing: HAPPairing = {
            accessoryPairingId,
            accessoryLTPK,
            accessoryLTSK,
            iOSDevicePairingId,
            iOSDeviceLTPK,
        };

        // TODO: Really save!
        this.pairing = pairing;
    }

    private async handlePairVerify(session: HAPSession, request: http.IncomingMessage, response: http.ServerResponse, body: tlv.TLVMap): Promise<void> {
        const tlvTypes = [TLVTypes.State];
        if (!this.assignTLVContains(body, tlvTypes)) {
            response.writeHead(HTTPStatusCodes.BadRequest);
            return;
        }

        const state: VerifyState = body.get(TLVTypes.State).readUInt8(0);
        console.log('verify step', state);
        if (state !== (session.verifyState + 1)) {
            session.verifyState = VerifyState.INITIAL;
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

    private async handlePairVerifyStepOne(session: HAPSession, request: http.IncomingMessage, response: http.ServerResponse, body: TLVMap) {
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
        const accessoryPK = sodium.api.crypto_sign_ed25519_pk_to_curve25519(keyPair.publicKey);
        const accessorySK = sodium.api.crypto_sign_ed25519_sk_to_curve25519(keyPair.secretKey);
        session.sharedSecret = sodium.api.crypto_scalarmult_curve25519(accessorySK, clientPublicKey);

        const accessoryPairingId = this.pairing.accessoryPairingId;
        const accessoryInfo = Buffer.concat([accessoryPK, accessoryPairingId, clientPublicKey]);
        const accessoryLTSK = this.pairing.accessoryLTSK;
        const accessorySignature = sodium.api.crypto_sign_ed25519_detached(accessoryInfo, accessoryLTSK);
        if (!accessorySignature) {
            throw new Error('could not sign accessoryInfo.');
        }

        // Derive shared key from the Curve25519 shared secret.
        const salt = Buffer.from('Pair-Verify-Encrypt-Salt');
        const info = Buffer.from('Pair-Verify-Encrypt-Info');
        session.sessionKey = hkdf('sha512', session.sharedSecret, salt, info, 32);

        const subTLV = new Map();
        subTLV.set(TLVTypes.Identifier, accessoryPairingId);
        subTLV.set(TLVTypes.Signature, accessorySignature);
        const subTLVData = tlv.encode(subTLV);

        const nonce = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x00]), Buffer.from('PV-Msg02')]);
        const encryptedSubTLV = sodium.api.crypto_aead_chacha20poly1305_ietf_encrypt(subTLVData, null, nonce, session.sessionKey);
        if (!encryptedSubTLV) {
            throw new Error('could not encrypt sub-tlv.');
        }

        const responseTLV: tlv.TLVMap = new Map();
        responseTLV.set(TLVTypes.State, Buffer.from([VerifyState.M2]));
        responseTLV.set(TLVTypes.PublicKey, accessoryPK);
        responseTLV.set(TLVTypes.EncryptedData, encryptedSubTLV);

        response.writeHead(HTTPStatusCodes.OK, { 'Content-Type': HAPContentTypes.TLV8 });
        response.write(tlv.encode(responseTLV));

        session.verifyState = VerifyState.M2;
    }

    private async handlePairVerifyStepThree(session: HAPSession, request: http.IncomingMessage, response: http.ServerResponse, body: TLVMap) {
        const tlvTypes = [TLVTypes.EncryptedData];
        if (!this.assignTLVContains(body, tlvTypes)) {
            response.writeHead(HTTPStatusCodes.BadRequest);
            return;
        }

        const encryptedData = body.get(TLVTypes.EncryptedData);

        // Decrypt sub-tlv.
        const nonce = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x00]), Buffer.from('PV-Msg03')]);
        const decryptedData = sodium.api.crypto_aead_chacha20poly1305_ietf_decrypt(encryptedData, null, nonce, session.sessionKey);
        if (!decryptedData) {
            session.verifyState = VerifyState.INITIAL;

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

        const iOSDevicePairingId = subTLV.get(TLVTypes.Identifier);
        const iOSDeviceSignature = subTLV.get(TLVTypes.Signature);
        const iOSDeviceLTPK = this.pairing.iOSDeviceLTPK;
        const accessoryLTPK = this.pairing.accessoryLTPK;
        const iOSDeviceInfo = Buffer.concat([iOSDeviceLTPK, iOSDevicePairingId, accessoryLTPK]); // TODO: FALSCH

        const verified = sodium.api.crypto_sign_ed25519_verify_detached(iOSDeviceSignature, iOSDeviceInfo, iOSDeviceLTPK);
        if (!verified) {
            session.verifyState = VerifyState.INITIAL;

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

        session.verifyState = VerifyState.M4;
    }

    private async handlePairings(session: HAPSession, request: http.IncomingMessage, response: http.ServerResponse, body: tlv.TLVMap): Promise<void> {

    }

    private async handleAttributeDatabase(session: HAPSession, request: http.IncomingMessage, response: http.ServerResponse): Promise<void> {

    }
}