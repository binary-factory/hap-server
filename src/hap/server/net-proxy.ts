import * as events from 'events';
import * as net from 'net';
import { Transform } from 'stream';
import { Address } from '../../transport/address';

export class ProxyConnection {
    rayId: number;
    localSocket: net.Socket;
    remoteSocket: net.Socket;
}

export type ProxyTransformFactory = (connection: ProxyConnection) => Transform;

export class NetProxy extends events.EventEmitter {

    private nativeServer: net.Server;

    private remoteHost: string;

    private remotePort: number;

    private rayIdCounter = 0;

    private connections: ProxyConnection[] = [];

    constructor(private incomingTransformFactory: ProxyTransformFactory,
                private outgoingTransformFactory: ProxyTransformFactory) {

        super();

        this.nativeServer = net.createServer((socket: net.Socket) => {
            this.handleConnection(socket);
        });
    }

    listen(remoteHost: string, remotePort: number): Promise<Address> {
        return new Promise((resolve, reject) => {
            this.nativeServer.listen((err) => {
                if (err) {
                    return reject(err);
                }

                this.remoteHost = remoteHost;
                this.remotePort = remotePort;

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


    getNativeServer(): net.Server {
        return this.nativeServer;
    }

    getConnections(): ProxyConnection[] {
        return this.connections.slice();
    }

    private handleConnection(localSocket: net.Socket) {
        const remoteSocket = net.connect(this.remotePort, this.remoteHost);
        const rayId = this.rayIdCounter++;
        const connection: ProxyConnection = {
            rayId,
            localSocket,
            remoteSocket
        };
        this.emit('connect', connection);

        const incomingTransform = this.incomingTransformFactory(connection);
        const outgoingTransform = this.outgoingTransformFactory(connection);

        localSocket
            .pipe(incomingTransform)
            .on('error', (err) => {
                localSocket.end();
                remoteSocket.end();
            })
            .pipe(remoteSocket);

        remoteSocket
            .pipe(outgoingTransform)
            .on('error', (err) => {
                localSocket.end();
                remoteSocket.end();
            })
            .pipe(localSocket);


        remoteSocket.on('close', () => {
            localSocket.end();
            this.removeConnection(connection);
        });

        localSocket.on('close', () => {
            remoteSocket.end();
            this.removeConnection(connection);
        });

        localSocket.on('error', (err) => {
            remoteSocket.destroy();
        });

        remoteSocket.on('error', (err) => {
            localSocket.destroy();
        });

        this.connections.push(connection);
    }

    private removeConnection(connection: ProxyConnection) {
        const index = this.connections.indexOf(connection);
        if (index) {
            this.connections = this.connections.splice(index, 1);
            this.emit('close', connection.rayId);
        }
    }

}