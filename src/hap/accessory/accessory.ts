import { Characteristic } from '../characteristic';
import { InstanceIdPool } from '../common/instance-id-pool';
import { Service, ServiceConfiguration } from '../service';

export class Accessory {

    private instanceIdPool: InstanceIdPool = new InstanceIdPool(1);

    /** Array of Service objects. Must not be empty. The maximum number of services must not exceed 100. */
    private services: Map<number, Service> = new Map();

    constructor(/** Integer assigned by the HAP Accessory Server to uniquely identify the HAP Accessory object, see Instance IDs (page 30). */
                private instanceId: number) {
    }

    addService(serviceConfiguration: ServiceConfiguration): Service {
        const instanceId = this.instanceIdPool.nextInstanceId();
        const service = new Service(this, instanceId, serviceConfiguration);

        this.services.set(instanceId, service);
        return service;
    }

    getCharacteristicByInstanceId(instanceId: number): Characteristic {
        let characteristic = null;
        this.services.forEach((service) => {
            if (!characteristic) {
                characteristic = service.getCharacteristicByInstanceId(instanceId);
            }
        });

        return characteristic;
    }

    getInstanceIdPool(): InstanceIdPool {
        return this.instanceIdPool;
    }

    toJSON(): Object {
        const serviceArray = Array.from(this.services.values());
        const accessoryObject = {
            aid: this.instanceId,
            services: serviceArray
        };

        return accessoryObject;
    }
}