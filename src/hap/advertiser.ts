import * as mdns from 'mdns';

export class Advertiser {

    private advertisement: mdns.Advertisement;

    constructor(
        private deviceId: string,
        private modelName: string,
        private categoryIdentifier,
        private configurationVersion
    ) { }

    start(port: number): Promise<mdns.Service> {
        return new Promise((resolve, reject) => {
            let options: mdns.AdvertisementOptions = {
                name: this.modelName,
                txtRecord: {
                    md: this.modelName,
                    pv: '1.0',
                    id: this.deviceId,
                    'c#': this.configurationVersion.toString(),
                    's#': '1',
                    'ff': '0',
                    'ci': this.categoryIdentifier,
                    'sf': '1'//this.accessoryInfo.paired() ? "0" : "1" // "sf == 1" means "discoverable by HomeKit iOS clients"
                }
            };

            let serviceType = mdns.tcp('hap');
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