import * as http from 'http';
import { HAPSession } from './hap-server';

export interface HAPHandler {

    handleAttributeDatabase(session: HAPSession, request: http.IncomingMessage, response: http.ServerResponse): Promise<void>
}