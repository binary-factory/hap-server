import * as net from 'net';

export interface ProxyConnection {
    rayId: number;
    localSocket: net.Socket;
    remoteSocket: net.Socket;
}