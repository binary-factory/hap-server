import * as events from 'events';
import { StatusCode } from '../server/status-code';
import { Service } from '../service';
import { CharacteristicCapability } from './capability';
import { CharacteristicConfiguration } from './configuration';
import { CharacteristicFormat } from './format';
import { CharacteristicReadValueResult } from './read-value-result';

export class Characteristic extends events.EventEmitter {

    // TODO: Implement
    private busy: boolean = false;

    private value: any;

    constructor(private parent: Service,
                /** REQUIRED. Integer assigned by the HAP Accessory Server to uniquely identify the HAP Characteristic object, see Instance IDs (page 30). */
                private instanceId: number,
                private configuration: CharacteristicConfiguration) {

        super();

        if (!this.verifyValue(configuration.value)) {
            throw new Error('invalid default value!');
        }
        this.value = configuration.value;
    }

    verifyValue(value: any): boolean {
        if (this.configuration.format === CharacteristicFormat.Boolean) {

        } else if (this.configuration.format === CharacteristicFormat.UInt8) {

        } else if (this.configuration.format === CharacteristicFormat.UInt16) {

        } else if (this.configuration.format === CharacteristicFormat.UInt32) {

        } else if (this.configuration.format === CharacteristicFormat.UInt64) {

        } else if (this.configuration.format === CharacteristicFormat.Int32) {

        } else if (this.configuration.format === CharacteristicFormat.Float64) {

        } else if (this.configuration.format === CharacteristicFormat.String) {

        } else if (this.configuration.format === CharacteristicFormat.TLV8) {

        } else if (this.configuration.format === CharacteristicFormat.Data) {

        }
        return true;
    }

    async readValue(): Promise<CharacteristicReadValueResult> {
        const value = this.value;
        if (!this.verifyValue(value)) {
            // TODO: Warn written value has invalid format!
        }


        return { value, status: StatusCode.Success };
    }

    async writeValue(value: any): Promise<StatusCode> {
        if (!this.verifyValue(value)) {
            return StatusCode.InvalidRequest;
        }
        this.value = value;
        return StatusCode.Success;
    }

    isBusy(): boolean {
        return this.busy;
    }

    isWriteable(): boolean {
        return this.configuration.capabilities.indexOf(CharacteristicCapability.PairedWrite) > -1;
    }

    isReadable(): boolean {
        return this.configuration.capabilities.indexOf(CharacteristicCapability.PairedRead) > -1;
    }

    isNotificationSupported(): boolean {
        return this.configuration.capabilities.indexOf(CharacteristicCapability.Events) > -1;
    }

    toJSON(): Object {
        // Required properties.
        let characteristicObject = {
            iid: this.instanceId,
            type: this.configuration.type,
            perms: this.configuration.capabilities,
            format: this.configuration.format
        };

        // Conditional properties.
        const hasPairedReadCapability = this.configuration.capabilities.find((capability) => {
            return capability === CharacteristicCapability.PairedRead;
        });
        if (hasPairedReadCapability) {
            characteristicObject = Object.assign(characteristicObject, { value: this.configuration.value });
        }

        // Optional properties.
        if (this.configuration.unit) {
            characteristicObject = Object.assign(characteristicObject, { unit: this.configuration.unit });
        }

        if (this.configuration.eventNotifications) {
            characteristicObject = Object.assign(characteristicObject, { ev: this.configuration.eventNotifications });
        }

        if (this.configuration.description) {
            characteristicObject = Object.assign(characteristicObject, { description: this.configuration.description });
        }

        if (this.configuration.constrains && this.configuration.constrains.minimumValue) {
            characteristicObject = Object.assign(characteristicObject, { minValue: this.configuration.constrains.minimumValue });
        }

        if (this.configuration.constrains && this.configuration.constrains.maximumValue) {
            characteristicObject = Object.assign(characteristicObject, { maxValue: this.configuration.constrains.maximumValue });
        }

        if (this.configuration.constrains && this.configuration.constrains.minimumStep) {
            characteristicObject = Object.assign(characteristicObject, { minStep: this.configuration.constrains.minimumStep });
        }

        if (this.configuration.constrains && this.configuration.constrains.maximumLength) {
            characteristicObject = Object.assign(characteristicObject, { maxLen: this.configuration.constrains.maximumLength });
        }

        if (this.configuration.constrains && this.configuration.constrains.maximumDataLength) {
            characteristicObject = Object.assign(characteristicObject, { maxDataLen: this.configuration.constrains.maximumDataLength });
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