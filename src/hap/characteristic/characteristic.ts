import { CharacteristicFormat } from './format';
import { CharacteristicCapability } from './capability';
import { CharacteristicUnit } from './unit';
import { CharacteristicValueConstrains } from './value-constrains';

export class Characteristic {
    /** REQUIRED. String that defines the type of the characteristic. See Service and Characteristic Types (page 72). */
    private type: string;

    /** REQUIRED. Integer assigned by the HAP Accessory Server to uniquely identify the HAP Characteristic object, see Instance IDs (page 30). */
    private instanceId: number;

    /** REQUIRED. Array of permission strings describing the capabilities of the characteristic. See Table 5-4 (page 67). */
    private capabilities: CharacteristicCapability[];

    /**
     * REQUIRED. The value of the characteristic, which must conform to the "format" property.
     * The literal value null may also be used if the characteristic has no value.
     * This property must be present if and only if the characteristic contains the Paired Read permission, see Table 5-4 (page 67).
     */
    private value: any;

    /** REQUIRED. Format of the value, e.g. "float". See Table 5-5 (page 67). */
    private format: CharacteristicFormat;

    /** OPTIONAL. Unit of the value, e.g. "celsius". See Table 5-6 (page 68). */
    private unit: CharacteristicUnit;

    /** OPTIONAL. Boolean indicating if event notifications are enabled for this characteristic. */
    private eventNotifications: boolean;

    /** OPTIONAL. String describing the characteristic on a manufacturer-specific basis, such as an indoor versus outdoor temperature reading.*/
    private description: string;

    /** OPTIONAL. Constrains for the value. */
    private constrains: CharacteristicValueConstrains;

    toJSON(): Object {
        // Required properties.
        let characteristicObject = {
            'type': this.type,
            'iid': this.instanceId,
            'perms': this.capabilities,
            'format': this.format
        };

        // Conditional properties.
        const hasPairedReadCapability = this.capabilities.find((capability) => {
            return capability === CharacteristicCapability.PairedRead;
        });
        if (hasPairedReadCapability) {
            characteristicObject = Object.assign(characteristicObject, { 'value': this.value });
        }

        // Optional properties.
        if (this.unit) {
            characteristicObject = Object.assign(characteristicObject, { 'unit': this.unit });
        }

        if (this.eventNotifications) {
            characteristicObject = Object.assign(characteristicObject, { 'ev': this.eventNotifications });
        }

        if (this.description) {
            characteristicObject = Object.assign(characteristicObject, { 'description': this.description });
        }

        if (this.constrains && this.constrains.minimumValue) {
            characteristicObject = Object.assign(characteristicObject, { 'minValue': this.constrains.minimumValue });
        }

        if (this.constrains && this.constrains.maximumValue) {
            characteristicObject = Object.assign(characteristicObject, { 'maxValue': this.constrains.maximumValue });
        }

        if (this.constrains && this.constrains.minimumStep) {
            characteristicObject = Object.assign(characteristicObject, { 'minStep': this.constrains.minimumStep });
        }

        if (this.constrains && this.constrains.maximumLength) {
            characteristicObject = Object.assign(characteristicObject, { 'maxLen': this.constrains.maximumLength });
        }

        if (this.constrains && this.constrains.maximumDataLength) {
            characteristicObject = Object.assign(characteristicObject, { 'maxDataLen': this.constrains.maximumDataLength });
        }

        if (this.constrains && this.constrains.validValues) {
            characteristicObject = Object.assign(characteristicObject, { 'valid-values': this.constrains.validValues });
        }

        if (this.constrains && this.constrains.validValuesRange) {
            characteristicObject = Object.assign(characteristicObject, { 'valid-values-range': this.constrains.validValuesRange });
        }

        return characteristicObject;
    }
}