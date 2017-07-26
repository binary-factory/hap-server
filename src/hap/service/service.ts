import { Accessory } from '../accessory';
import { Characteristic, CharacteristicConfiguration } from '../characteristic';
import { ServiceConfiguration } from './configuration';

export class Service {


    /**
     *  Array of Characteristic objects. Must not be empty.
     *  The maximum number of characteristics must not exceed 100, and each characteristic in the array must have a unique type.
     */
    private characteristics: Map<number, Characteristic> = new Map();


    /** OPTIONAL. An array of Numbers containing the instance ids of the services that this service links to. */
    private linkedServices: number[];

    constructor(private parent: Accessory,
                /** Integer assigned by the HAP Accessory Server to uniquely identify the HAP Service object, see Instance IDs (page 30). */
                private instanceId: number,
                private configuration: ServiceConfiguration) {

    }

    addCharacteristic(characteristicConfiguration: CharacteristicConfiguration): Characteristic {
        const instanceId = this.parent.getInstanceIdPool().nextInstanceId();
        const characteristic = new Characteristic(this, instanceId, characteristicConfiguration);

        this.characteristics.set(instanceId, characteristic);
        return characteristic;
    }

    getCharacteristicByInstanceId(instanceId: number): Characteristic {
        return this.characteristics.get(instanceId);
    }

    setCharacteristicByType(type: string, value: any) {

    }

    toJSON(): Object {
        const characteristicArray = Array.from(this.characteristics.values());
        const serviceObject = {
            iid: this.instanceId,
            type: this.configuration.type,
            characteristics: characteristicArray,
            hidden: this.configuration.hidden,
            primary: this.configuration.primary,
            linked: this.linkedServices
        };

        return serviceObject;
    }
}