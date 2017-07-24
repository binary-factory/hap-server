import { HAPServer } from './hap-server';
import { Advertiser } from './advertiser';
import { Service } from './service';
import { InstanceIdPool } from './instance-id-pool';

export class Accessory {

    private server: HAPServer;

    private advertiser: Advertiser;

    /** Integer assigned by the HAP Accessory Server to uniquely identify the HAP Accessory object, see Instance IDs (page 30). */
    private instanceId: number;

    /** Array of Service objects. Must not be empty. The maximum number of services must not exceed 100. */
    private services: Map<number, Service> = new Map();

    private instanceIdPool: InstanceIdPool = new InstanceIdPool();

    constructor(
        private deviceId: string,
        private modelName: string,
        private categoryIdentifier
    ) {
        this.server = new HAPServer(deviceId);
        this.advertiser = new Advertiser(deviceId, modelName, categoryIdentifier, 1);
    }

    addService(service :Service): Service {
        const iid = this.instanceIdPool.nextInstanceId();
        this.services.set(iid, service);

        return service;
    }


    async start() {
        const hap = await this.server.start();
        const service = this.advertiser.start(hap.proxyAddress.port);
    }

    public toJSON() : Object {
        const serviceArray = Array.from(this.services.values());
        const accessoryObject = {
            'aid': this.instanceId,
            'services': JSON.stringify(serviceArray)
        };

        return accessoryObject;
    }
}