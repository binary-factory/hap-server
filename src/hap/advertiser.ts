import * as mdns from 'mdns';
import { DeviceInformation } from './common';

export class Advertiser {

    private advertisement: mdns.Advertisement;

    constructor(private deviceInformation: DeviceInformation) {
    }

    start(port: number): Promise<mdns.Service> {
        return new Promise((resolve, reject) => {
            const options: mdns.AdvertisementOptions = {
                name: this.deviceInformation.modelName,
                txtRecord: {
                    md: this.deviceInformation.modelName,
                    pv: '1.0',
                    id: this.deviceInformation.deviceId,
                    'c#': 1, // TODO: Implement configuration number.
                    's#': '1',
                    'ff': '0',
                    'ci': this.deviceInformation.primaryFunction,
                    'sf': '1'//this.accessoryInfo.paired() ? "0" : "1" // "sf == 1" means "discoverable by HomeKit iOS clients"
                }
            };

            const serviceType = mdns.tcp('hap');
            this.advertisement = mdns.createAdvertisement(serviceType, port, options, (error, service) => {
                if (error) {
                    return reject(error);
                }
                resolve(service);
            });
            this.advertisement.start();
        });
    }

    stop() {
        this.advertisement.stop();
    }
}