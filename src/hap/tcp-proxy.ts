import * as net from 'net';
import { Transform } from 'stream';
import EventEmitter = NodeJS.EventEmitter;

export type TCPProxyInterceptor = (connection: TCPProxyConnection, localSocket: net.Socket, remoteSocket: net.Socket, chunk: string | Buffer, encoding: string) => Promise<string | Buffer>;

export interface TCPProxyConnection {
    localSocket: net.Socket;
    remoteSocket: net.Socket;
    rayId: number;
}

export class TCPProxy extends EventEmitter {

    private server: net.Server;
    private remoteHost: string;
    private remotePort: number;

    private connections: Map<number, TCPProxyConnection> = new Map();
    private rayIdCounter: number = 0;

    constructor(private readInterceptor: TCPProxyInterceptor,
                private writeInterceptor: TCPProxyInterceptor) {

        super();

        this.server = net.createServer(this.handleConnection.bind(this));
    }

    get nativeServer(): net.Server {
        return this.server;
    }

    listen(remoteHost: string, remotePort: number, port: number = 0): Promise<number> {
        return new Promise((resolve, reject) => {
            this.remoteHost = remoteHost;
            this.remotePort = remotePort;

            this.server.listen(port, (err) => {
                if (err) {
                    return reject(err);
                }
                resolve(this.server.address().port);
            });
        });
    }

    getConnectionByRemote(remoteAddress: string, remotePort: number): TCPProxyConnection {
        let result: TCPProxyConnection = null;

        this.connections.forEach((connection, rayId) => {
            const address = connection.remoteSocket.address();
            if (address.address === remoteAddress && address.port == remotePort) {
                result = connection;
            }
        });

        return result;
    }

    getConnectionByRemoteSocket(socket: net.Socket): TCPProxyConnection {
        return this.getConnectionByRemote(socket.remoteAddress, socket.remotePort);
    }

    private handleConnection(localSocket: net.Socket) {
        const rayId = this.rayIdCounter++;
        const remoteSocket = net.connect(this.remotePort, this.remoteHost);

        const connection: TCPProxyConnection = {
            localSocket,
            remoteSocket,
            rayId
        };

        const readTransform = new Transform({
            transform: (chunk, encoding, callback) => {
                this.readInterceptor(connection, localSocket, remoteSocket, chunk, encoding)
                    .then((chunk) => {
                        callback(null, chunk);
                    })
                    .catch((err) => {
                        callback(err);
                    });
            }
        });

        const writeTransform = new Transform({
            transform: (chunk, encoding, callback) => {
                this.writeInterceptor(connection, localSocket, remoteSocket, chunk, encoding)
                    .then((chunk) => {
                        callback(null, chunk);
                    })
                    .catch((err) => {
                        callback(err);
                    });
            }
        });

        // Save connection.
        this.connections.set(rayId, connection);

        localSocket
            .pipe(readTransform)
            .pipe(remoteSocket);

        remoteSocket
            .pipe(writeTransform)
            .pipe(localSocket);

        localSocket.on('close', (had_error) => {
            this.teardown(rayId);
        });

        remoteSocket.on('close', (had_error) => {
            this.teardown(rayId);
        });

        localSocket.on('error', (err) => {
            console.log('socket error', err);
        });

        remoteSocket.on('error', (err) => {
            console.log('proxy error', err);
        });

        this.emit('connection', connection);
    }

    private teardown(rayId: number) {
        const connection = this.connections.get(rayId);

        connection.localSocket.end();
        connection.remoteSocket.end();

        this.connections.delete(rayId);

        this.emit('end', connection);
    }
}