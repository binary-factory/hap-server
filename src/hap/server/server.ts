import * as http from 'http';
import * as querystring from 'querystring';
import { Transform } from 'stream';
import * as url from 'url';
import { hkdf } from '../../crypto';
import { AccessoryLongTimeKeyPair } from '../../entity';
import { MemoryStorage, Storage } from '../../services';
import { HTTPHandler, HttpServer, HTTPStatusCode } from '../../transport/http';
import { ProxyConnection, ProxyServer } from '../../transport/proxy';
import * as tlv from '../../transport/tlv/tlv';
import { Logger, SimpleLogger } from '../../util/logger';
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
import { ContentType } from '../constants/content-type';
import { PairErrorCode } from '../constants/pair-error-code';
import { PairMethod } from '../constants/pair-method';
import { PairSetupState } from '../constants/pair-setup-state';
import { VerifyState } from '../constants/pair-verify-state';
import { TLVType } from '../constants/types';
import { HAPRequest } from './hap-request';
import { CharacteristicReadRequest, CharacteristicWriteRequest } from './messages/characteristic';
import { PairSetupExchangeResponse, PairSetupVerifyResponse } from './messages/pair-setup';
import { PairSetupContext } from './pair-setup/context';
import { Router, RouterHandler } from './router';
import { SecureDecryptStream } from './secure-decrypt-stream';
import { SecureEncryptStream } from './secure-encrypt-stream';
import { Session } from './session';

const sodium = require('sodium');


const defaultSession: Session = {
    pairContext: new PairSetupContext(),
    verifyContext: {
        state: VerifyState.INITIAL
    }
};


export class HAPServer implements HTTPHandler, RouterHandler {

    private logger: Logger = new SimpleLogger('HAPServer');

    private storage: Storage = new MemoryStorage();

    private longTimeKeyPair: AccessoryLongTimeKeyPair;

    private proxyServer: ProxyServer;

    private httpServer: HttpServer = new HttpServer(this);

    private router: Router = new Router(this);

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

        this.httpServer.getNativeServer().setTimeout(0, () => {
        });

        // Push necessary default AccessoryInformation service.
        this.defaultAccessory = this.addAccessory();
        const accessoryInformationService = this.defaultAccessory.addService({ type: '0000003E-0000-1000-8000-0026BB765291' });
        const characteristicIdentify: CharacteristicConfiguration = {
            type: '14',
            capabilities: [CharacteristicCapability.PairedWrite],
            format: CharacteristicFormat.Boolean,
            description: 'Identify'
        };
        const characteristicManufacturer: CharacteristicConfiguration = {
            type: '20',
            capabilities: [CharacteristicCapability.PairedRead],
            format: CharacteristicFormat.String,
            value: 'Manu',
            description: 'Manufacturer'
        };
        const characteristicModel: CharacteristicConfiguration = {
            type: '21',
            capabilities: [CharacteristicCapability.PairedRead],
            format: CharacteristicFormat.String,
            // constrains: { maximumLength: 64 },
            value: 'Model',
            description: 'Model'
        };
        const characteristicName: CharacteristicConfiguration = {
            type: '23',
            capabilities: [CharacteristicCapability.PairedRead],
            format: CharacteristicFormat.String,
            // constrains: { maximumLength: 64 },
            value: 'Name',
            description: 'Name'
        };
        const characteristicSerialnumber: CharacteristicConfiguration = {
            type: '30',
            capabilities: [CharacteristicCapability.PairedRead],
            format: CharacteristicFormat.String,
            // constrains: { maximumLength: 64 },
            value: 'Serial',
            description: 'Serial Number'
        };
        /*
                constants characteristicFirmwareRevision: CharacteristicConfiguration = {
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

        /*
        constants accessoryFanService = this.defaultAccessory.addService({ type: '40' });
        constants characteristicOn: CharacteristicConfiguration = {
            type: '00000025-0000-1000-8000-0026BB765291',
            capabilities: [CharacteristicCapability.PairedRead, CharacteristicCapability.PairedWrite, CharacteristicCapability.Events],
            format: CharacteristicFormat.Boolean,
            value: false,
            description: 'On'
        };
        constants characteristicRotationSpeed: CharacteristicConfiguration = {
            type: '29',
            capabilities: [CharacteristicCapability.PairedRead, CharacteristicCapability.PairedWrite, CharacteristicCapability.Events],
            format: CharacteristicFormat.Float64,
            value: 50,
            unit: CharacteristicUnit.Percentage,
            constrains: {
                minimumValue:0,
                maximumValue: 100,
                minimumStep: 1
            }
        };
        accessoryFanService.addCharacteristic(characteristicOn);
        accessoryFanService.addCharacteristic(characteristicRotationSpeed);
        */

        const accessoryLightbulbService = this.defaultAccessory.addService({ type: '43' });
        const characteristicOn: CharacteristicConfiguration = {
            type: '25',
            capabilities: [
                CharacteristicCapability.PairedRead,
                CharacteristicCapability.PairedWrite,
                CharacteristicCapability.Events
            ],
            format: CharacteristicFormat.Boolean,
            value: false
        };
        const characteristicBrightness: CharacteristicConfiguration = {
            type: '8',
            capabilities: [
                CharacteristicCapability.PairedRead,
                CharacteristicCapability.PairedWrite,
                CharacteristicCapability.Events
            ],
            format: CharacteristicFormat.Int32,
            unit: CharacteristicUnit.Percentage,
            constrains: {
                minimumValue: 0,
                maximumValue: 100,
                minimumStep: 1
            },
            value: 0
        };
        const characteristicHue: CharacteristicConfiguration = {
            type: '13',
            capabilities: [
                CharacteristicCapability.PairedRead,
                CharacteristicCapability.PairedWrite,
                CharacteristicCapability.Events
            ],
            format: CharacteristicFormat.Float64,
            unit: CharacteristicUnit.Arcdegrees,
            constrains: {
                minimumValue: 0,
                maximumValue: 360,
                minimumStep: 1
            },
            value: 0
        };
        const characteristicSaturation: CharacteristicConfiguration = {
            type: '2F',
            capabilities: [
                CharacteristicCapability.PairedRead,
                CharacteristicCapability.PairedWrite,
                CharacteristicCapability.Events
            ],
            format: CharacteristicFormat.Float64,
            unit: CharacteristicUnit.Percentage,
            constrains: {
                minimumValue: 0,
                maximumValue: 100,
                minimumStep: 1
            },
            value: 0
        };
        accessoryLightbulbService.addCharacteristic(characteristicOn);
        accessoryLightbulbService.addCharacteristic(characteristicBrightness);
        accessoryLightbulbService.addCharacteristic(characteristicHue);
        accessoryLightbulbService.addCharacteristic(characteristicSaturation);
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

        const hapRequest: HAPRequest = {
            proxyConnection,
            session,
            rawBody: body,
            http: request
        };


        await this.router.route(hapRequest, response);

        response.end();
    }

    async handlePairSetup(request: HAPRequest, response: http.ServerResponse) {
    }

    async handlePairVerify(request: HAPRequest, response: http.ServerResponse) {
    }

    async handlePairings(request: HAPRequest, response: http.ServerResponse) {
    }

    async handleAttributeDatabase(request: HAPRequest, response: http.ServerResponse) {
    }

    async handleCharacteristicRead(request: HAPRequest, response: http.ServerResponse) {
    }

    async handleCharacteristicWrite(request: HAPRequest, response: http.ServerResponse) {
    }

    async handleIdentify(request: HAPRequest, response: http.ServerResponse) {
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
        this.sessions.set(connection.rayId, defaultSession); //TODO: Use factory function !
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
        /*
        if (state > (session.pairContext.state + 1)) {
            session.pairContext = Object.assign({}, defaultSession.pairContext);
            response.writeHead(HTTPStatusCode.BadRequest);
            return;
        }
        */

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

        const srpStartResponse = session.pairContext.start(this.pinCode);
        const responseTLV: tlv.TLVMap = new Map();
        responseTLV.set(TLVType.State, Buffer.from([PairSetupState.M2]));
        responseTLV.set(TLVType.PublicKey, srpStartResponse.accessorySRPPublicKey);
        responseTLV.set(TLVType.Salt, srpStartResponse.accessorySRPSalt);

        response.writeHead(HTTPStatusCode.OK, { 'Content-Type': ContentType.TLV8 });
        response.write(tlv.encode(responseTLV));
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
        let srpVerifyResponse: PairSetupVerifyResponse;
        try {
            srpVerifyResponse = session.pairContext.verify(deviceSRPPublicKey, deviceSRPProof);
        } catch (ex) {
            const responseTLV: tlv.TLVMap = new Map();
            responseTLV.set(TLVType.State, Buffer.from([PairSetupState.M4]));
            responseTLV.set(TLVType.Error, Buffer.from([PairErrorCode.Authentication]));

            response.writeHead(HTTPStatusCode.OK, { 'Content-Type': ContentType.TLV8 });
            response.write(tlv.encode(responseTLV));
            return;
        }

        const responseTLV: tlv.TLVMap = new Map();
        responseTLV.set(TLVType.State, Buffer.from([0x04]));
        responseTLV.set(TLVType.Proof, srpVerifyResponse.accessorySRPProof);

        response.writeHead(HTTPStatusCode.OK, { 'Content-Type': ContentType.TLV8 });
        response.write(tlv.encode(responseTLV));
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

        const ltkp = await this.getLongTimeKeyPair();

        let srpExchangeResponse: PairSetupExchangeResponse;
        try {
            srpExchangeResponse = session.pairContext.exchange(encryptedData, ltkp.publicKey, ltkp.privateKey, Buffer.from(this.configuration.deviceId));
        } catch (ex) {
            const responseTLV: tlv.TLVMap = new Map();
            responseTLV.set(TLVType.State, Buffer.from([PairSetupState.M5]));
            responseTLV.set(TLVType.Error, Buffer.from([PairErrorCode.Authentication]));

            response.writeHead(HTTPStatusCode.OK, { 'Content-Type': ContentType.TLV8 });
            response.write(tlv.encode(responseTLV));
            return;
        }

        const responseTLV: tlv.TLVMap = new Map();
        responseTLV.set(TLVType.State, Buffer.from([PairSetupState.M6]));
        responseTLV.set(TLVType.EncryptedData, srpExchangeResponse.encryptedData);

        response.writeHead(HTTPStatusCode.OK, { 'Content-Type': ContentType.TLV8 });
        response.write(tlv.encode(responseTLV));

        /*
        constants saved = await this.storage.persistControllerLongTimePublicKey(devicePairingId.toString(), deviceLongTimePublicKey);
        if (!saved) {
            throw new Error('could not write device long time key to storage.');
        }
        */
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
                constants deviceIdentifier = body.get(TLVType.Identifier);
                constants devicePublicKey = body.get(TLVType.PublicKey);
                constants devicePermissions = body.get(TLVType.Permissions);
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
        const responseJSON = JSON.stringify({ accessories: accessoriesArray });

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
                writeTaskResult.status = StatusCode.Success;

            } else {
                writeTaskResult.status = StatusCode.InvalidRequest;
            }
        }


        // Waiting for all pending write tasks to finish.
        this.logger.debug('waiting for all write operations to complete.');
        const pendingWriteTasksResult = await Promise.all(pendingWriteTasks);
        this.logger.debug('all write operations returned.');

        // Assign results to writeTaskResults.
        for (let i = 0; i < pendingWriteTasksResult.length; i++) {
            const pendingWriteTaskResult = pendingWriteTasksResult[i];
            const writeTaskResult = pendingWriteTaskMappings.get(i);

            writeTaskResult.status = pendingWriteTaskResult;
        }

        // Now we count the unsuccessful read operations.
        const errorCount = writeTaskResults.filter((writeTaskResult) => writeTaskResult.status !== StatusCode.Success).length;

        // Send back the result.
        if (errorCount > 0) {
            this.logger.warn(`${errorCount} of ${body.characteristics.length} write operations failed!`);

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