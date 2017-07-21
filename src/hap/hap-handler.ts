import * as http from 'http';
import { Session } from './hap-server';

export interface HAPHandler {

    handleAttributeDatabase(session: Session, request: http.IncomingMessage, response: http.ServerResponse): Promise<void>
}