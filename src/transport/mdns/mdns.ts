import * as _mdns from 'mdns';

export namespace mdns {


    export function startAdvertising() {
        let displayName = 'Test';
        let username = 'CC:22:3D:E3:CE:F6';

        const options: _mdns.AdvertisementOptions = {
            name: displayName,
            txtRecord: {
                md: displayName,
                pv: "1.0",
                id: username,
                "c#": "2",//this.accessoryInfo.configVersion + "", // "accessory conf" - represents the "configuration version" of an Accessory. Increasing this "version number" signals iOS devices to re-fetch /accessories data.
                "s#": "1", // "accessory state"
                "ff": "0",
                "ci": "1",//this.accessoryInfo.category,
                "sf": "1"//this.accessoryInfo.paired() ? "0" : "1" // "sf == 1" means "discoverable by HomeKit iOS clients"
            }
        };

        const advertisement = _mdns.createAdvertisement(_mdns.tcp('hap'), 3000, options, (error, service)=> {
            if (error) {
                console.error(error);
                return;
            }
        });
        advertisement.start();

    }
}
