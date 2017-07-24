import { Characteristic } from './characteristic';
import { InstanceIdPool } from './instance-id-pool';

export class Service {

    /** String that defines the type of the service. See Service and Characteristic Types (page 72). */
    private type: string;

    /** Integer assigned by the HAP Accessory Server to uniquely identify the HAP Service object, see Instance IDs (page 30). */
    private instanceId: number;

    /**
     *  Array of Characteristic objects. Must not be empty.
     *  The maximum number of characteristics must not exceed 100, and each characteristic in the array must have a unique type.
     */
    private characteristics: Map<number, Characteristic> = new Map();

    /** CONDITIONAL. When set to True, this service is not visible to user. */
    private hidden: boolean;

    /** OPTIONAL. When set to True, this is the primary service on the accessory. */
    private primary: boolean;

    /** OPTIONAL. An array of Numbers containing the instance ids of the services that this service links to. */
    private linkedServices: number[];

    constructor(private instanceIdPool: InstanceIdPool) {

    }

    addCharacteristic(characteristic: Characteristic): Characteristic {
        const iid = this.instanceIdPool.nextInstanceId();
        this.characteristics.set(iid, characteristic);

        return characteristic;
    }

    toJSON(): Object {
        const characteristicArray = Array.from(this.characteristics.values());
        const serviceObject = {
            'type': this.type,
            'iid': this.instanceId,
            'characteristics': JSON.stringify(characteristicArray),
            'hidden': this.hidden,
            'primary': this.primary,
            'linked': this.linkedServices
        };

        return serviceObject;
    }
}