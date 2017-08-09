import * as http from 'http';
import { ProxyConnection } from '../../transport/proxy';
import { Session } from './session';

export interface HAPRequest {
    proxyConnection: ProxyConnection;
    session: Session;
    rawBody: Buffer;
    http: http.IncomingMessage;
}