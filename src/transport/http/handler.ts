import * as http from 'http';

export interface HTTPHandler {

    handleRequest(request: http.IncomingMessage, response: http.ServerResponse, body: Buffer): Promise<void>;
}