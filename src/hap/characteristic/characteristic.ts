import { Service } from '../service';
import { CharacteristicCapability } from './capability';
import { CharacteristicConfiguration } from './configuration';

export class Characteristic {

    value: any; // TODO: Just for testing.

    constructor(private parent: Service,
                /** REQUIRED. Integer assigned by the HAP Accessory Server to uniquely identify the HAP Characteristic object, see Instance IDs (page 30). */
                private instanceId: number,
                private configuration: CharacteristicConfiguration) {

        this.value = configuration.value;

    }

    toJSON(): Object {
        // Required properties.
        let characteristicObject = {
            'iid': this.instanceId,
            'type': this.configuration.type,
            'perms': this.configuration.capabilities,
            'format': this.configuration.format
        };

        // Conditional properties.
        const hasPairedReadCapability = this.configuration.capabilities.find((capability) => {
            return capability === CharacteristicCapability.PairedRead;
        });
        if (hasPairedReadCapability) {
            characteristicObject = Object.assign(characteristicObject, { 'value': this.configuration.value });
        }

        // Optional properties.
        if (this.configuration.unit) {
            characteristicObject = Object.assign(characteristicObject, { 'unit': this.configuration.unit });
        }

        if (this.configuration.eventNotifications) {
            characteristicObject = Object.assign(characteristicObject, { 'ev': this.configuration.eventNotifications });
        }

        if (this.configuration.description) {
            characteristicObject = Object.assign(characteristicObject, { 'description': this.configuration.description });
        }

        if (this.configuration.constrains && this.configuration.constrains.minimumValue) {
            characteristicObject = Object.assign(characteristicObject, { 'minValue': this.configuration.constrains.minimumValue });
        }

        if (this.configuration.constrains && this.configuration.constrains.maximumValue) {
            characteristicObject = Object.assign(characteristicObject, { 'maxValue': this.configuration.constrains.maximumValue });
        }

        if (this.configuration.constrains && this.configuration.constrains.minimumStep) {
            characteristicObject = Object.assign(characteristicObject, { 'minStep': this.configuration.constrains.minimumStep });
        }

        if (this.configuration.constrains && this.configuration.constrains.maximumLength) {
            characteristicObject = Object.assign(characteristicObject, { 'maxLen': this.configuration.constrains.maximumLength });
        }

        if (this.configuration.constrains && this.configuration.constrains.maximumDataLength) {
            characteristicObject = Object.assign(characteristicObject, { 'maxDataLen': this.configuration.constrains.maximumDataLength });
        }

        if (this.configuration.constrains && this.configuration.constrains.validValues) {
            characteristicObject = Object.assign(characteristicObject, { 'valid-values': this.configuration.constrains.validValues });
        }

        if (this.configuration.constrains && this.configuration.constrains.validValuesRange) {
            characteristicObject = Object.assign(characteristicObject, { 'valid-values-range': this.configuration.constrains.validValuesRange });
        }

        return characteristicObject;
    }
}