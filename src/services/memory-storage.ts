import { Storage } from './storage';
import { AccessoryLongTimeKeyPair } from '../hap/common/accessory-longtime-keypair';

export class MemoryStorage implements Storage {

    private accessoryLongTimeKeyPairs: Map<string, AccessoryLongTimeKeyPair> = new Map();

    private controllerLongTimePublicKeys: Map<string, Buffer> = new Map();

    async connect(): Promise<boolean> {
        return true;
    }

    async persistAccessoryLongTimeKeyPair(accessoryId: string, accessoryLongTimeKeyPair: AccessoryLongTimeKeyPair): Promise<boolean> {
        this.accessoryLongTimeKeyPairs.set(accessoryId, accessoryLongTimeKeyPair);
        return true;
    }

    async getAccessoryLongTimeKeyPair(accessoryId: string): Promise<AccessoryLongTimeKeyPair> {
        return this.accessoryLongTimeKeyPairs.get(accessoryId);
    }

    async persistControllerLongTimePublicKey(deviceId: string, deviceLongTimePublicKey: Buffer): Promise<boolean> {
        this.controllerLongTimePublicKeys.set(deviceId, deviceLongTimePublicKey);
        return true;
    }

    async getControllerLongTimePublicKey(deviceId: string): Promise<Buffer> {
        return this.controllerLongTimePublicKeys.get(deviceId);
    }

}