import * as crypto from 'crypto';
import * as http from 'http';
import * as querystring from 'querystring';
import { Transform } from 'stream';
import * as url from 'url';
import { hkdf } from '../../crypto/hkdf/hkdf';
import { SRPConfigurations } from '../../crypto/srp/configurations';
import { SecureRemotePassword } from '../../crypto/srp/srp';
import { AccessoryLongTimeKeyPair } from '../../entity';
import { MemoryStorage, Storage } from '../../services';
import { HTTPHandler, HttpServer, HTTPStatusCode } from '../../transport/http';
import { ProxyConnection, ProxyServer } from '../../transport/proxy';
import { Logger, LogLevel, SimpleLogger } from '../../util/logger';
import { Accessory } from '../accessory';
import { Advertiser } from '../advertiser';
import {
    CharacteristicCapability,
    CharacteristicConfiguration,
    CharacteristicFormat,
    CharacteristicUnit
} from '../characteristic';
import { CharacteristicReadValueResult } from '../characteristic/read-value-result';
import { DeviceConfiguration, InstanceIdPool, StatusCode } from '../common';
import { TLVType } from '../common/tlv';
import * as tlv from '../common/tlv/tlv';
import { CharacteristicReadRequest } from './characteristic-read-request';
import { CharacteristicWriteRequest } from './characteristic-write-request';
import { ContentType } from './content-type';
import { PairErrorCode } from './pair-error-code';
import { PairMethod } from './pair-method';
import { PairSetupState } from './pair-setup-state';
import { VerifyState } from './pair-verify-state';
import { Route } from './route';
import { SecureDecryptStream } from './secure-decrypt-stream';
import { SecureEncryptStream } from './secure-encrypt-stream';
import { Session } from './session';
import { Urls } from './url';

const sodium = require('sodium');


const defaultSession: Session = {
    authenticationAttempts: 0,
    pairContext: {
        state: PairSetupState.INITIAL
    },
    verifyContext: {
        state: VerifyState.INITIAL
    }
};


export class HAPServer implements HTTPHandler {

    private logger: Logger = new SimpleLogger('HAPServer');

    private storage: Storage = new MemoryStorage();

    private longTimeKeyPair: AccessoryLongTimeKeyPair;

    private proxyServer: ProxyServer;

    private httpServer: HttpServer = new HttpServer(this);

    private advertiser: Advertiser = new Advertiser(this.configuration);

    private sessions: Map<number, Session> = new Map();

    private accessories: Map<number, Accessory> = new Map();

    private accessoryInstanceIdPool: InstanceIdPool = new InstanceIdPool(1);

    private defaultAccessory: Accessory;

    public constructor(private configuration: DeviceConfiguration, private pinCode: string) {

        // TODO: Move to property initialization and use may a "ProxyTransformProvider" interface?
        this.proxyServer = new ProxyServer((connection) => {
            return this.createDecryptStream(connection);
        }, (connection) => {
            return this.createEncryptStream(connection);
        });

        this.proxyServer.on('connect', (connection) => {
            this.handleProxyConnect(connection);
        });

        this.proxyServer.on('close', (rayId) => {
            this.handleProxyClose(rayId);
        });

        // Push necessary default AccessoryInformation service.
        this.defaultAccessory = this.addAccessory();
        const accessoryInformationService = this.defaultAccessory.addService({ type: '0000003E-0000-1000-8000-0026BB765291' });
        const characteristicIdentify: CharacteristicConfiguration = {
            type: '00000014-0000-1000-8000-0026BB765291',
            capabilities: [CharacteristicCapability.PairedWrite],
            format: CharacteristicFormat.Boolean,
            description: 'Identify'
        };
        const characteristicManufacturer: CharacteristicConfiguration = {
            type: '00000020-0000-1000-8000-0026BB765291',
            capabilities: [CharacteristicCapability.PairedRead],
            format: CharacteristicFormat.String,
            value: 'Manu',
            description: 'Manufacturer'
        };
        const characteristicModel: CharacteristicConfiguration = {
            type: '00000021-0000-1000-8000-0026BB765291',
            capabilities: [CharacteristicCapability.PairedRead],
            format: CharacteristicFormat.String,
            // constrains: { maximumLength: 64 },
            value: 'Model',
            description: 'Model'
        };
        const characteristicName: CharacteristicConfiguration = {
            type: '00000023-0000-1000-8000-0026BB765291',
            capabilities: [CharacteristicCapability.PairedRead],
            format: CharacteristicFormat.String,
            // constrains: { maximumLength: 64 },
            value: 'Name',
            description: 'Name'
        };
        const characteristicSerialnumber: CharacteristicConfiguration = {
            type: '00000030-0000-1000-8000-0026BB765291',
            capabilities: [CharacteristicCapability.PairedRead],
            format: CharacteristicFormat.String,
            // constrains: { maximumLength: 64 },
            value: 'Serial',
            description: 'Serial Number'
        };
        /*
                const characteristicFirmwareRevision: CharacteristicConfiguration = {
                    type: '52',
                    capabilities: [CharacteristicCapability.PairedRead],
                    format: CharacteristicFormat.String,
                    value: '1.2.3',
                    description: 'Revision'
                };*/
        accessoryInformationService.addCharacteristic(characteristicIdentify);
        accessoryInformationService.addCharacteristic(characteristicManufacturer);
        accessoryInformationService.addCharacteristic(characteristicModel);
        accessoryInformationService.addCharacteristic(characteristicName);
        accessoryInformationService.addCharacteristic(characteristicSerialnumber);
        //accessoryInformationService.addCharacteristic(characteristicFirmwareRevision);

        const accessoryFanService = this.defaultAccessory.addService({ type: '00000040-0000-1000-8000-0026BB765291' });
        const characteristicOn: CharacteristicConfiguration = {
            type: '00000025-0000-1000-8000-0026BB765291',
            capabilities: [CharacteristicCapability.PairedRead, CharacteristicCapability.PairedWrite, CharacteristicCapability.Events],
            format: CharacteristicFormat.Boolean,
            value: false,
            description: 'On'
        };
        accessoryFanService.addCharacteristic(characteristicOn);

        const accessoriesArray = Array.from(this.accessories.values());
        console.log(JSON.stringify({ 'accessories': accessoriesArray }));
    }

    addAccessory(): Accessory {
        const aid = this.accessoryInstanceIdPool.nextInstanceId();
        const accessory = new Accessory(aid);

        this.accessories.set(aid, accessory);
        return accessory;
    }

    async handleRequest(request: http.IncomingMessage, response: http.ServerResponse, body: Buffer): Promise<void> {
        const proxyConnection = this.proxyConnectionFromRequest(request);
        if (!proxyConnection) {
            // We do not allow connections without proxy.
            request.socket.end();
            return;
        }

        const session = this.sessions.get(proxyConnection.rayId);
        if (!session) {
            this.logger.debug('no session found for rayId', proxyConnection.rayId);
            request.socket.end();
            return;
        }

        // Route request.
        const requestPathname = url.parse(request.url).pathname;
        const requestMethod = request.method;
        const requestContentType = request.headers['content-type'] || ContentType.EMPTY;
        // TODO: Build only once.
        const routes: Route[] = [
            {
                pathname: Urls.PairSetup,
                method: 'POST',
                contentType: ContentType.TLV8,
                handler: (session, request, response, body) => {
                    return this.handlePairSetup(session, request, response, body);
                }
            },
            {
                pathname: Urls.PairVerify,
                method: 'POST',
                contentType: ContentType.TLV8,
                handler: (session, request, response, body) => {
                    return this.handlePairVerify(session, request, response, body);
                }
            },
            {
                pathname: Urls.Pairings,
                method: 'POST',
                contentType: ContentType.TLV8,
                handler: (session, request, response, body) => {
                    return this.handlePairings(session, request, response, body);
                }
            },
            {
                pathname: Urls.Accessories,
                method: 'GET',
                contentType: ContentType.EMPTY,
                handler: (session, request, response, body) => {
                    return this.handleAttributeDatabase(session, request, response);
                }
            },
            {
                pathname: Urls.Characteristics,
                method: 'GET',
                contentType: ContentType.EMPTY,
                handler: (session, request, response, body) => {
                    return this.handleCharacteristicRead(session, request, response, body);
                }
            },
            {
                pathname: Urls.Characteristics,
                method: 'PUT',
                contentType: ContentType.JSON,
                handler: (session, request, response, body) => {
                    return this.handleCharacteristicWrite(session, request, response, body);
                }
            },
            {
                pathname: Urls.Identify,
                method: 'POST',
                contentType: ContentType.EMPTY,
                handler: (session, request, response, body) => {
                    return this.handleIdentify(session, request, response, body);
                }
            }
        ];

        this.logger.info('Request on Ray:', proxyConnection.rayId);
        this.logger.logRequest(LogLevel.Info, request);

        // Math pathname.
        let matching: Route[] = routes.filter((route) => route.pathname === requestPathname);
        if (matching.length) {
            // Math method.
            matching = matching.filter((route) => {
                return route.method === requestMethod;
            });
            if (matching.length) {
                // Match content-type.
                matching = matching.filter((route) => {
                    return route.contentType === requestContentType;
                });
                if (matching.length) {
                    // There should be only one route left.
                    const matchingRoute = matching[0];

                    // Parse body if not empty.
                    let parsedBody: TLVType | any;
                    if (body.length > 0) {
                        try {
                            if (matchingRoute.contentType === ContentType.TLV8) {
                                this.logger.debug('parse body as TLV');
                                parsedBody = tlv.decode(body);
                                this.logger.logTLV(LogLevel.Debug, parsedBody);
                            } else if (matchingRoute.contentType === ContentType.JSON) {
                                this.logger.debug('parse body as JSON');
                                parsedBody = JSON.parse(body.toString());
                                this.logger.debug(body.toString());
                            }
                        } catch (err) {
                            this.logger.error('could not parse body', err);
                            response.writeHead(HTTPStatusCode.BadRequest);
                        }
                    } else {
                        this.logger.debug('empty body');
                    }

                    // Call handler.
                    await matchingRoute.handler(session, request, response, parsedBody);

                } else {
                    response.writeHead(HTTPStatusCode.UnsupportedMediaType);
                }

            } else {
                response.writeHead(HTTPStatusCode.MethodNotAllowed);
            }
        } else {
            this.logger.warn('unresolved route', requestPathname);
            response.writeHead(HTTPStatusCode.NotFound);
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
        const storageConnected = await this.storage.connect();
        if (!storageConnected) {
            throw new Error('Storage not connected!');
        }

        const httpAddress = await this.httpServer.listen(0, '127.0.0.1');
        this.logger.info(`http-server listening at: ${httpAddress.address}:${httpAddress.port}`);

        const proxyAddress = await this.proxyServer.listen(httpAddress.address, httpAddress.port);
        this.logger.info(`proxy-server listening at: ${proxyAddress.address}:${proxyAddress.port}`);

        const service = await this.advertiser.start(proxyAddress.port);
        this.logger.info(`advertisement started`);
    }

    // TODO: Move a generic crypto namespace.
    private async getLongTimeKeyPair(): Promise<AccessoryLongTimeKeyPair> {
        // Generate accessories Ed25519 long-term public key, AccessoryLTPK, and long-term secret key, AccessoryLTSK.
        let longTimeKeyPair = await this.storage.getAccessoryLongTimeKeyPair(this.configuration.deviceId);
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
        const tlvTypes = [TLVType.State];
        if (!this.assignTLVContains(body, tlvTypes)) {
            response.writeHead(HTTPStatusCode.BadRequest);
            return;
        }

        const state: PairSetupState = body.get(TLVType.State).readUInt8(0);
        if (state > (session.pairContext.state + 1)) {
            session.pairContext = Object.assign({}, defaultSession.pairContext);
            response.writeHead(HTTPStatusCode.BadRequest);
            return;
        }

        switch (state) {
            case PairSetupState.M1:
                await this.handlePairSetupStepOne(session, request, response, body);
                break;

            case PairSetupState.M3:
                await this.handlePairSetupStepThree(session, request, response, body);
                break;

            case PairSetupState.M5:
                await this.handlePairSetupStepFive(session, request, response, body);
                break;
        }
    }

    private async handlePairSetupStepOne(session: Session, request: http.IncomingMessage, response: http.ServerResponse, body: tlv.TLVMap) {
        const tlvTypes = [TLVType.Method];
        if (!this.assignTLVContains(body, tlvTypes)) {
            response.writeHead(HTTPStatusCode.BadRequest);
            return;
        }

        const method = body.get(TLVType.Method).readUInt8(0);
        if (method !== PairMethod.PairSetup) {
            //response.writeHead(HTTPStatusCode.BadRequest);
            // return;
        }

        // Check authentication attempts.
        if (session.authenticationAttempts > 100) { // TODO: Use constant.
            // TODO: Implement.
        }

        const username = 'Pair-Setup';
        const password = this.pinCode;
        const serverPrivateKey = crypto.randomBytes(16);
        const salt = crypto.randomBytes(16);
        const srp = new SecureRemotePassword(username, password, salt, SRPConfigurations[3072], serverPrivateKey);


        const state = Buffer.from([PairSetupState.M2]);
        const publicKey = srp.getServerPublicKey();

        const responseTLV: tlv.TLVMap = new Map();
        responseTLV.set(TLVType.State, state);
        responseTLV.set(TLVType.PublicKey, publicKey);
        responseTLV.set(TLVType.Salt, salt);

        response.writeHead(HTTPStatusCode.OK, { 'Content-Type': ContentType.TLV8 });
        response.write(tlv.encode(responseTLV));

        session.pairContext.state = PairSetupState.M2;
        session.pairContext.srp = srp;
    }

    private async handlePairSetupStepThree(session: Session, request: http.IncomingMessage, response: http.ServerResponse, body: tlv.TLVMap) {
        const srp = session.pairContext.srp;
        const tlvTypes = [TLVType.PublicKey, TLVType.Proof];
        if (!this.assignTLVContains(body, tlvTypes)) {
            response.writeHead(HTTPStatusCode.BadRequest);
            return;
        }

        const deviceSRPPublicKey = body.get(TLVType.PublicKey);
        const deviceSRPProof = body.get(TLVType.Proof);

        // Verify client proof.
        srp.setClientPublicKey(deviceSRPPublicKey);
        const sharedSecret = srp.getSessionKey();
        const verified = srp.verifyProof(deviceSRPProof);
        if (!verified) {
            session.pairContext = defaultSession.pairContext; //TODO: Change everywhere Object.assign({}, defaultSession.pairContext); Or implement a reset() method?

            const responseTLV: tlv.TLVMap = new Map();
            responseTLV.set(TLVType.State, Buffer.from([PairSetupState.M4]));
            responseTLV.set(TLVType.Error, Buffer.from([PairErrorCode.Authentication]));

            response.writeHead(HTTPStatusCode.OK, { 'Content-Type': ContentType.TLV8 });
            response.write(tlv.encode(responseTLV));
            return;
        }

        // Derive session key from SRP shared secret.
        const pairSetupEncryptSalt = Buffer.from('Pair-Setup-Encrypt-Salt');
        const pairSetupEncryptInfo = Buffer.from('Pair-Setup-Encrypt-Info');
        const sessionKey = hkdf('sha512', sharedSecret, pairSetupEncryptSalt, pairSetupEncryptInfo, 32);


        const accessorySRPProof = srp.getProof();
        const responseTLV: tlv.TLVMap = new Map();
        responseTLV.set(TLVType.State, Buffer.from([0x04]));
        responseTLV.set(TLVType.Proof, accessorySRPProof);

        response.writeHead(HTTPStatusCode.OK, { 'Content-Type': ContentType.TLV8 });
        response.write(tlv.encode(responseTLV));

        session.pairContext.state = PairSetupState.M4;
        session.pairContext.sharedSecret = sharedSecret;
        session.pairContext.sessionKey = sessionKey;
    }

    private async handlePairSetupStepFive(session: Session, request: http.IncomingMessage, response: http.ServerResponse, body: tlv.TLVMap) {
        const tlvTypes = [TLVType.EncryptedData];
        if (!this.assignTLVContains(body, tlvTypes)) {
            response.writeHead(HTTPStatusCode.BadRequest);
            return;
        }

        // Check for any errors.
        const clientError = body.get(TLVType.Error);
        if (clientError) {
            session.pairContext = defaultSession.pairContext;
            return;
        }

        const encryptedData = body.get(TLVType.EncryptedData);

        // Decrypt sub-tlv.
        const nonceM5 = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x00]), Buffer.from('PS-Msg05')]);
        const decryptedData = sodium.api.crypto_aead_chacha20poly1305_ietf_decrypt(encryptedData, null, nonceM5, session.pairContext.sessionKey);
        if (!decryptedData) {
            session.pairContext = defaultSession.pairContext;

            const responseTLV: tlv.TLVMap = new Map();
            responseTLV.set(TLVType.State, Buffer.from([PairSetupState.M5]));
            responseTLV.set(TLVType.Error, Buffer.from([PairErrorCode.Authentication]));

            response.writeHead(HTTPStatusCode.BadRequest, { 'Content-Type': ContentType.TLV8 });
            response.write(tlv.encode(responseTLV));
            return;
        }

        // Decode sub-tlv.
        const subTLV = tlv.decode(decryptedData);
        const devicePairingId = subTLV.get(TLVType.Identifier);
        const deviceLongTimePublicKey = subTLV.get(TLVType.PublicKey);
        const deviceSignature = subTLV.get(TLVType.Signature);

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
            responseTLV.set(TLVType.State, Buffer.from([PairSetupState.M6]));
            responseTLV.set(TLVType.Error, Buffer.from([PairErrorCode.Authentication]));

            response.writeHead(HTTPStatusCode.OK, { 'Content-Type': ContentType.TLV8 });
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
        const accessoryPairingId = Buffer.from(this.configuration.deviceId);
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
        const encryptedSubTLV = sodium.api.crypto_aead_chacha20poly1305_ietf_encrypt(subTLVData, null, nonceM6, session.pairContext.sessionKey);
        if (!encryptedSubTLV) {
            throw new Error('could not encrypt sub-tlv.');
        }

        const responseTLV: tlv.TLVMap = new Map();
        responseTLV.set(TLVType.State, Buffer.from([PairSetupState.M6]));
        responseTLV.set(TLVType.EncryptedData, encryptedSubTLV);

        response.writeHead(HTTPStatusCode.OK, { 'Content-Type': ContentType.TLV8 });
        response.write(tlv.encode(responseTLV));

        const saved = await this.storage.persistControllerLongTimePublicKey(devicePairingId.toString(), deviceLongTimePublicKey);
        if (!saved) {
            throw new Error('could not write device long time key to storage.');
        }

        session.pairContext.state = PairSetupState.M6;
    }

    private async handlePairVerify(session: Session, request: http.IncomingMessage, response: http.ServerResponse, body: tlv.TLVMap): Promise<void> {
        const tlvTypes = [TLVType.State];
        if (!this.assignTLVContains(body, tlvTypes)) {
            response.writeHead(HTTPStatusCode.BadRequest);
            return;
        }

        const state: VerifyState = body.get(TLVType.State).readUInt8(0);
        if (state > (session.verifyContext.state + 1)) {
            session.verifyContext = defaultSession.verifyContext;
            response.writeHead(HTTPStatusCode.BadRequest);
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

    private async handlePairVerifyStepOne(session: Session, request: http.IncomingMessage, response: http.ServerResponse, body: tlv.TLVMap) {
        const tlvTypes = [TLVType.PublicKey];
        if (!this.assignTLVContains(body, tlvTypes)) {
            response.writeHead(HTTPStatusCode.BadRequest);
            return;
        }

        const clientPublicKey = body.get(TLVType.PublicKey);

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

        response.writeHead(HTTPStatusCode.OK, { 'Content-Type': ContentType.TLV8 });
        response.write(tlv.encode(responseTLV));

        session.verifyContext.state = VerifyState.M2;
        session.verifyContext.devicePublicKey = clientPublicKey;
        session.verifyContext.accessoryPublicKey = accessoryPublicKey;
        session.verifyContext.sharedSecret = sharedSecret;
        session.verifyContext.sessionKey = sessionKey;
    }

    private async handlePairVerifyStepThree(session: Session, request: http.IncomingMessage, response: http.ServerResponse, body: tlv.TLVMap) {
        const tlvTypes = [TLVType.EncryptedData];
        if (!this.assignTLVContains(body, tlvTypes)) {
            response.writeHead(HTTPStatusCode.BadRequest);
            return;
        }

        const encryptedData = body.get(TLVType.EncryptedData);

        // Decrypt sub-tlv.
        const sessionKey = session.verifyContext.sessionKey;
        const nonce = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x00]), Buffer.from('PV-Msg03')]);
        const decryptedData = sodium.api.crypto_aead_chacha20poly1305_ietf_decrypt(encryptedData, null, nonce, sessionKey);
        if (!decryptedData) {
            session.verifyContext = defaultSession.verifyContext;

            const responseTLV: tlv.TLVMap = new Map();
            responseTLV.set(TLVType.State, Buffer.from([VerifyState.M4]));
            responseTLV.set(TLVType.Error, Buffer.from([PairErrorCode.Authentication]));

            response.writeHead(HTTPStatusCode.BadRequest, { 'Content-Type': ContentType.TLV8 });
            response.write(tlv.encode(responseTLV));
            return;
        }

        // Decode sub-tlv.
        const subTLV = tlv.decode(decryptedData);
        const subTLVTypes = [TLVType.Identifier, TLVType.Signature];
        if (!this.assignTLVContains(subTLV, subTLVTypes)) {
            response.writeHead(HTTPStatusCode.BadRequest);
            return;
        }

        const devicePairingId = subTLV.get(TLVType.Identifier);
        const deviceSignature = subTLV.get(TLVType.Signature);
        const deviceLongTimePublicKey = await this.storage.getControllerLongTimePublicKey(devicePairingId.toString());
        if (!deviceLongTimePublicKey) {
            const responseTLV: tlv.TLVMap = new Map();
            responseTLV.set(TLVType.State, Buffer.from([VerifyState.M4]));
            responseTLV.set(TLVType.Error, Buffer.from([PairErrorCode.Authentication]));

            response.writeHead(HTTPStatusCode.BadRequest, { 'Content-Type': ContentType.TLV8 }); //TODO: Maybe other HTTP-Code?
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
            responseTLV.set(TLVType.State, Buffer.from([PairSetupState.M6]));
            responseTLV.set(TLVType.Error, Buffer.from([PairErrorCode.Authentication]));

            response.writeHead(HTTPStatusCode.OK, { 'Content-Type': ContentType.TLV8 });
            response.write(tlv.encode(responseTLV));
            return;
        }

        const responseTLV: tlv.TLVMap = new Map();
        responseTLV.set(TLVType.State, Buffer.from([VerifyState.M4]));

        response.writeHead(HTTPStatusCode.OK, { 'Content-Type': ContentType.TLV8 });
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
        session.decryptStream.once('data', () => { // TODO: Method params.
            session.encryptStream.enable();
        });
    }

    private async handlePairings(session: Session, request: http.IncomingMessage, response: http.ServerResponse, body: tlv.TLVMap): Promise<void> {
        const tlvTypes = [TLVType.State, TLVType.Method]; //, TLVType.Identifier, TLVType.PublicKey, TLVType.Permissions];
        if (!this.assignTLVContains(body, tlvTypes)) {
            response.writeHead(HTTPStatusCode.BadRequest);
            return;
        }

        const state = body.get(TLVType.State);
        const method = body.get(TLVType.Method);
        /*
                const deviceIdentifier = body.get(TLVType.Identifier);
                const devicePublicKey = body.get(TLVType.PublicKey);
                const devicePermissions = body.get(TLVType.Permissions);
                */
        console.log(method);

        //console.log(deviceIdentifier);
        //console.log(devicePermissions);
        const responseTLV: tlv.TLVMap = new Map();
        responseTLV.set(TLVType.State, Buffer.from([0x02]));

        response.writeHead(HTTPStatusCode.OK, { 'Content-Type': ContentType.TLV8 });
        response.write(tlv.encode(responseTLV));
        // TODO: Implement.
    }

    private async handleAttributeDatabase(session: Session, request: http.IncomingMessage, response: http.ServerResponse): Promise<void> {
        const accessoriesArray = Array.from(this.accessories.values());
        const responseJSON = JSON.stringify({ 'accessories': accessoriesArray });
        response.writeHead(HTTPStatusCode.OK, { 'Content-Type': ContentType.JSON });
        response.write(responseJSON);
    }

    private async handleCharacteristicRead(session: Session, request: http.IncomingMessage, response: http.ServerResponse, body: any): Promise<void> {
        const query = url.parse(request.url).query;
        const characteristicRead: CharacteristicReadRequest = querystring.parse(query);

        // Parse extra query parameters.
        const includeMeta = characteristicRead.meta === '1';
        const includeCapability = characteristicRead.perms === '1';
        const includeType = characteristicRead.type === '1';
        const includeEventStatus = characteristicRead.ev === '1';

        // Extract read tasks from query.
        type ReadTask = {
            accessoryInstanceId: number;
            characteristicInstanceId: number;
        };
        const readTasks: ReadTask[] = [];
        const commaSeparatedList = characteristicRead.id.split(',');
        for (const listItem of commaSeparatedList) {
            const dataPair = listItem.split('.');

            // We expect exact two items.
            if (dataPair.length !== 2) {
                this.logger.warn('an item of the read request was malformed.');
                continue;
            }

            // Parse the Ids.
            const accessoryInstanceId = parseInt(dataPair[0]);
            const characteristicInstanceId = parseInt(dataPair[1]);

            // Check if was successful.
            if (isNaN(accessoryInstanceId) || isNaN(characteristicInstanceId)) {
                this.logger.warn('accessoryInstanceId or characteristicInstanceId was malformed.');
                continue;
            }

            const readTask: ReadTask = {
                accessoryInstanceId,
                characteristicInstanceId
            };
            readTasks.push(readTask);
        }

        // Now we process each task.
        type ReadTaskResult = {
            aid: number;
            iid: number;
            status?: StatusCode;
            value?: any;
            format?: CharacteristicFormat;
            unit?: CharacteristicUnit;
            minValue?: number;
            maxValue?: number;
            minStep?: number;
            maxLen?: number;
        };

        const pendingReadTasks: Promise<CharacteristicReadValueResult>[] = [];
        const pendingReadTaskMappings: Map<number, ReadTaskResult> = new Map();
        const readTaskResults: ReadTaskResult[] = [];
        for (const readTask of readTasks) {
            const readTaskResult: ReadTaskResult = {
                aid: readTask.accessoryInstanceId,
                iid: readTask.characteristicInstanceId
            };

            readTaskResults.push(readTaskResult);

            const accessory = this.accessories.get(readTask.accessoryInstanceId);
            if (!accessory) {
                this.logger.warn('rejecting characteristic read: Accessory not found!');
                readTaskResult.status = StatusCode.NotFound;
                continue;
            }

            const characteristic = accessory.getCharacteristicByInstanceId(readTask.characteristicInstanceId);
            if (!characteristic) {
                this.logger.warn('rejecting characteristic read: Characteristic not found!');
                readTaskResult.status = StatusCode.NotFound;
                continue;
            }

            if (!characteristic.isReadable()) {
                this.logger.warn('rejecting characteristic read: Not readable!');
                readTaskResult.status = StatusCode.CannotRead;
                continue;
            }

            if (characteristic.isBusy()) {
                this.logger.warn('rejecting characteristic read: Busy!');
                readTaskResult.status = StatusCode.Busy;
                continue;
            }

            if (includeMeta) {
                // TODO: Implement.
            }

            if (includeCapability) {
                // TODO: Implement.
            }

            if (includeType) {
                // TODO: Implement.
            }

            if (includeEventStatus) {
                // TODO: Implement.
            }

            const pendingReadTask = characteristic.readValue();
            const length = pendingReadTasks.push(pendingReadTask);
            const index = length - 1;
            pendingReadTaskMappings.set(index, readTaskResult);
        }


        // Waiting for all pending read tasks to finish.
        this.logger.debug('waiting for all read operations to complete.');
        const pendingReadTasksResult = await Promise.all(pendingReadTasks);
        this.logger.debug('all read operations returned.');

        // Assign results to readTaskResults.
        for (let i = 0; i < pendingReadTasksResult.length; i++) {
            const pendingReadTaskResult = pendingReadTasksResult[i];
            const readTaskResult = pendingReadTaskMappings.get(i);

            if (pendingReadTaskResult.status === StatusCode.Success) {
                readTaskResult.value = pendingReadTaskResult.value;
            } else {
                readTaskResult.status = pendingReadTaskResult.status;
            }
        }

        // Now we count the unsuccessful read operations.
        const errorCount = readTaskResults.filter((readTaskResult) => readTaskResult.hasOwnProperty('status')).length;

        // Send back the result.
        const responseJSON = JSON.stringify({ characteristics: readTaskResults });
        if (errorCount > 0) {
            this.logger.warn(`${errorCount} of ${readTaskResults.length} read operations failed!`);
            response.writeHead(HTTPStatusCode.MultiStatus, { 'Content-Type': ContentType.JSON });

        } else {
            this.logger.debug('all read operations succeeded!');
            response.writeHead(HTTPStatusCode.OK, { 'Content-Type': ContentType.JSON });
        }

        response.write(responseJSON);
    }

    private async handleCharacteristicWrite(session: Session, request: http.IncomingMessage, response: http.ServerResponse, body: CharacteristicWriteRequest): Promise<void> {
        const writeTasks = body.characteristics;

        type WriteTaskResult = {
            aid: number;
            iid: number;
            status?: StatusCode;
        };

        const pendingWriteTasks: Promise<StatusCode>[] = [];
        const pendingWriteTaskMappings: Map<number, WriteTaskResult> = new Map();
        const writeTaskResults: WriteTaskResult[] = [];
        for (const writeTask of writeTasks) {
            const writeTaskResult: WriteTaskResult = {
                aid: writeTask.aid,
                iid: writeTask.iid
            };

            writeTaskResults.push(writeTaskResult);

            const accessory = this.accessories.get(writeTask.aid);
            if (!accessory) {
                this.logger.warn('rejecting characteristic write: Accessory not found!');
                writeTaskResult.status = StatusCode.NotFound;
                continue;
            }

            const characteristic = accessory.getCharacteristicByInstanceId(writeTask.iid);
            if (!characteristic) {
                this.logger.warn('rejecting characteristic write: Characteristic not found!');
                writeTaskResult.status = StatusCode.NotFound;
                continue;
            }

            if (characteristic.isBusy()) {
                this.logger.warn('rejecting characteristic write: Busy!');
                writeTaskResult.status = StatusCode.Busy;
                continue;
            }

            if (writeTask.hasOwnProperty('value')) {
                // Controller want to write the value.
                if (!characteristic.isWriteable()) {
                    this.logger.warn('rejecting characteristic write: Not writable!');
                    writeTaskResult.status = StatusCode.CannotWrite;
                    continue;
                }

                this.logger.debug(`writing value to: ${writeTask.aid}:${writeTask.iid}`);

                const pendingWriteTask = characteristic.writeValue(writeTask.value);
                const length = pendingWriteTasks.push(pendingWriteTask);
                const index = length - 1;
                pendingWriteTaskMappings.set(index, writeTaskResult);

            } else if (writeTask.hasOwnProperty('ev')) {
                // Controller wants to subscribe for notification events.
                if (!characteristic.isNotificationSupported()) {
                    this.logger.warn('rejecting characteristic write: No event support!');
                    writeTaskResult.status = StatusCode.NotificationNotSupported;
                    continue;
                }

                this.logger.info(`subscription to: ${writeTask.aid}:${writeTask.iid}`);

            } else {
                writeTaskResult.status = StatusCode.InvalidRequest;
            }
        }


        // Waiting for all pending write tasks to finish.
        this.logger.debug('waiting for all write operations to complete.');
        const pendingWriteTasksResult = await Promise.all(pendingWriteTasks);
        this.logger.debug('all write operations returned.');

        // Assign results to readTaskResults.
        for (let i = 0; i < pendingWriteTasksResult.length; i++) {
            const pendingWriteTaskResult = pendingWriteTasksResult[i];
            const writeTaskResult = pendingWriteTaskMappings.get(i);

            writeTaskResult.status = pendingWriteTaskResult;
        }

        // Now we count the unsuccessful read operations.
        const errorCount = writeTaskResults.filter((writeTaskResult) => writeTaskResult.status !== StatusCode.Success).length;

        // Send back the result.
        if (errorCount > 0) {
            this.logger.warn(`${errorCount} of ${body.characteristics.length} write operation failed!`);

            const responseJSON = JSON.stringify({ characteristics: writeTaskResults });
            this.logger.debug('some write operations failed!', responseJSON);
            response.writeHead(HTTPStatusCode.MultiStatus, { 'Content-Type': ContentType.JSON });
            response.write(responseJSON);

        } else {
            response.writeHead(HTTPStatusCode.NoContent);
            this.logger.debug('all write operations succeeded!');
        }
    }

    private async handleIdentify(session: Session, request: http.IncomingMessage, response: http.ServerResponse, body: any): Promise<void> {
        this.logger.debug('characteristic identify', body);
        response.writeHead(HTTPStatusCode.NoContent, { 'Content-Type': ContentType.JSON });
        // TODO: Implement.
    }
}