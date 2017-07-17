import * as http from 'http';
import { Advertiser } from '../hap/advertiser';
import { TLV } from '../transport/tlv8/tlv';
import { HTTPStatusCodes } from './constants/pairing/http-status-codes';
import { HTTPUrls } from './constants/pairing/http-urls';
import { TLVTypes } from './constants/pairing/tlv-types';
import { HTTPServer, Route } from './http-server';
import { SessionManager } from './session-manager';

interface Session {
    isPaired: boolean;
    pairState: number;
}

export const defaultSession: Session = {
    isPaired: false,
    pairState: 1
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
        const session = this.sessions.get(request.socket); console.log(session);
        const tlv = TLV.decode(body);
        const pairState = tlv.get(TLVTypes.State);

        if (!pairState || pairState.readUInt8(0) !== session.pairState) {
            response.writeHead(HTTPStatusCodes.BadRequest);
            response.end();
            return;
        }

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

        const responseTLV: TLV.TLVMap = new Map();
        responseTLV.set(TLVTypes.State, new Buffer(2));
        responseTLV.set(TLVTypes.PublicKey, new Buffer(0));
        responseTLV.set(TLVTypes.Salt, new Buffer(0));

        response.writeHead(200, { 'Content-Type': 'application/pairing+tlv8' });
        response.write(TLV.encode(responseTLV));
        session.pairState++;
    }

    private async handlePairSetupStepThree(tlv: Map<number, Buffer>, response: http.ServerResponse, session: Session) {
        console.log('iam here');
    }

    private async handlePairSetupStepFive(tlv: Map<number, Buffer>, response: http.ServerResponse, session: Session) {

    }

    private async handlePairVerify(request: http.IncomingMessage, response: http.ServerResponse, body: Buffer) {

    }

    private async handlePairings(request: http.IncomingMessage, response: http.ServerResponse, body: Buffer) {

    }

    async start() {
        const port = await this.httpServer.listen();
        const service = await this.advertiser.start(port);
        console.log(service);

    }

    reset() {

    }

    shutdown() {

    }

}