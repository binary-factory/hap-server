import { AccessoryCategory } from '../accessory';

export interface DeviceConfiguration {
    deviceId: string;
    modelName: string;
    primaryFunction: AccessoryCategory
}