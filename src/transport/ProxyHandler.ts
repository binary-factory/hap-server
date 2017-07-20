import { ProxyConnection } from './NetProxy';

export interface ProxyHandler {

    transformIncomingData(connection: ProxyConnection, chunk: Buffer, encoding: string): Promise<Buffer>;

    transformOutgoingData(connection: ProxyConnection, chunk: Buffer, encoding: string): Promise<Buffer>;
}