import { AccessoryLongTimeKeyPair } from '../hap/server/hap-server';

export interface Storage {

    connect(): Promise<boolean>;

    persistAccessoryLongTimeKeyPair(accessoryId: string, accessoryLongTimeKeyPair: AccessoryLongTimeKeyPair): Promise<boolean>;

    getAccessoryLongTimeKeyPair(accessoryId: string): Promise<AccessoryLongTimeKeyPair>;

    persistControllerLongTimePublicKey(deviceId: string, deviceLongTimePublicKey: Buffer): Promise<boolean>;

    getControllerLongTimePublicKey(deviceId: string): Promise<Buffer>;
}