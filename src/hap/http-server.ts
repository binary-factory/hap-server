import * as http from 'http';
import * as url from 'url';

export type RequestHandler = (request: http.IncomingMessage, response: http.ServerResponse, body: Buffer) => void;

export interface Route {
    pathname: string;
    method: string;
    handler: RequestHandler;
}

export class HTTPServer {
    private server: http.Server;

    constructor(private routes: Route[]) {
        this.server = http.createServer(this.handleRequest.bind(this));
    }

    private handleRequest(request: http.IncomingMessage, response: http.ServerResponse) {
        const chunks = [];

        request.on('data', (chunk) => {
            chunks.push(chunk);
        });

        request.on('end', () => {
            const pathname = url.parse(request.url).pathname;
            const body = Buffer.concat(chunks);

            // Route request
            const matchingUrlRoutes = this.routes.filter((route) => route.pathname === pathname);
            if (matchingUrlRoutes.length) {

                const matchingMethodRoutes = matchingUrlRoutes.filter((route) => route.method === request.method);
                const handlers = matchingMethodRoutes.map((route) => route.handler(request, response, body));

                if (matchingMethodRoutes.length) {
                    Promise.all(handlers).catch((err) => {
                        console.log(err);
                        response.writeHead(500); //TODO: Can this fail ? If so will it break app?
                        response.end();
                    });

                } else {
                    response.writeHead(405);
                    response.end();
                }
            } else {
                response.writeHead(404);
                response.end();
            }
        });

    }

    listen(port: number = 0): Promise<number> {
        return new Promise((resolve, reject) => {
            this.server.listen(port, (err) => {
                if (err) {
                    return reject(err);
                }
               resolve(this.server.address().port);
            });
        });
    }

    get nativeServer(): http.Server {
        return this.server;
    }
}