import { AccessoryCategory } from '../accessory';

export interface DeviceInformation {
    deviceId: string;
    modelName: string;
    primaryFunction: AccessoryCategory
}