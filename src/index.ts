import { AccessoryCategory } from './hap/accessory';
import { DeviceConfiguration } from './hap/common';
import { HAPServer } from './hap/server';

const deviceConfiguration: DeviceConfiguration = {
    deviceId: '12:33:57:44:45:78',
    modelName: 'Olva2',
    primaryFunction: AccessoryCategory.Lightbulb
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