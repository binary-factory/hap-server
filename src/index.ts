import { AccessoryCategory } from './hap/accessory';
import { DeviceInformation } from './hap/common';
import { HAPServer } from './hap/server';

const deviceInformation: DeviceInformation = {
    deviceId: 'C9:A9:93:E4:A5:CA',
    modelName: 'Device1,1',
    primaryFunction: AccessoryCategory.Fan
};
const pinCode = '123-99-123';
const accessory = new HAPServer(deviceInformation, pinCode);

accessory.start()
    .then(() => {
        console.log('up!');
    })
    .catch((err) => console.log('error botting device', err));