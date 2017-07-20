import * as net from 'net';

export class SessionManager<T> {

    sessions: Map<net.Socket, T> = new Map();

    constructor(private server: net.Server,
                private defaultSession: T) {

        server.on('connection', this.handleConnect.bind(this));
    }

    private handleConnect(socket: net.Socket) {
        const address = socket.address();
        this.sessions.set(socket, this.defaultSession);
        socket.on('close', (hadError) => {
            console.info(`destroying session for ${address.address}:${address.port}`);
            this.sessions.delete(socket);
        });
    }

    get(socket: net.Socket): T {
        return this.sessions.get(socket);
    }
}