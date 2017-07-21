import * as http from 'http';
import { Address } from './address';
import { HTTPHandler } from './http-handler';

export class HttpServer {

    private nativeServer: http.Server;

    constructor(private handler: HTTPHandler) {
        this.nativeServer = http.createServer((request, response) => {
            this.handleRequest(request, response);
        });
    }

    listen(port?: number, hostname?: string): Promise<Address> {
        return new Promise((resolve, reject) => {
            this.nativeServer.listen(port, hostname, (err) => {
                if (err) {
                    return reject(err);
                }

                resolve(this.nativeServer.address());
            });
        });
    }

    stop(): Promise<void> {
        // TODO: Resolve on 'close' event?
        /**
         * Stops the server from accepting new connections and keeps existing connections.
         * This function is asynchronous, the server is finally closed when all connections are ended and the server emits a 'close' event.
         */
        return new Promise<void>((resolve, reject) => {
            this.nativeServer.close((err) => {
                if (err) {
                    reject(err);
                }

                resolve();
            });
        });
    }

    getHandler(): HTTPHandler {
        return this.handler;
    }

    getNativeServer(): http.Server {
        return this.nativeServer;
    }

    private handleRequest(request: http.IncomingMessage, response: http.ServerResponse) {
        let chunks: Buffer[] = [];

        request.on('data', (chunk: Buffer) => {
            chunks.push(chunk);
        });

        request.on('end', () => {
            const body = Buffer.concat(chunks);
            chunks = [];
            this.handler.handleRequest(request, response, body)
                .catch((err) => {
                    console.log('500', err);
                    response.writeHead(500);
                    response.end();
                });
        });
    }

}