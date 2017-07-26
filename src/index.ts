import { AccessoryCategory } from './hap/accessory';
import { DeviceConfiguration } from './hap/common';
import { HAPServer } from './hap/server';

const deviceConfiguration: DeviceConfiguration = {
    deviceId: '77:33:57:44:45:69',
    modelName: 'Device1,1',
    primaryFunction: AccessoryCategory.Fan
};
const pinCode = '123-99-123';
const server = new HAPServer(deviceConfiguration, pinCode);
server.start()
    .then(() => {
        console.log('up!');
    })
    .catch((err) => console.log('error botting device', err));
/*
setInterval(() => {
    console.log('CONNECTION COUNT: ' + server['proxyServer'].getConnections().length);
}, 2500);
*/