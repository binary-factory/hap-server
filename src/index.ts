import { AccessoryCategory } from './hap/accessory';
import { DeviceInformation } from './hap/common';
import { HAPServer } from './hap/server';

const deviceInformation: DeviceInformation = {
    deviceId: 'C9:22:11:33:15:CA',
    modelName: 'Device1,1',
    primaryFunction: AccessoryCategory.Fan
};
const pinCode = '123-99-123';
const server = new HAPServer(deviceInformation, pinCode);
setInterval(() => {
    console.log('CONNECTION COUNT: ' + server['proxyServer'].getConnections().length);
}, 2500);
server.start()
    .then(() => {
        console.log('up!');
    })
    .catch((err) => console.log('error botting device', err));