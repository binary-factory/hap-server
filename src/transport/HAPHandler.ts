import * as http from 'http';
import { HAPSession } from './HAPServer';

export interface HAPHandler {

    handleAttributeDatabase(session: HAPSession, request: http.IncomingMessage, response: http.ServerResponse): Promise<void>
}