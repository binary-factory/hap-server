export enum CharacteristicFormat {
    /** Boolean value expressed as one of the following: true, false, 0 (false), and 1(true). */
    Boolean = 'bool',

        /** Unsigned 8-bit integer. */
    UInt8 = 'uint8',

        /** Unsigned 16-bit integer. */
    UInt16 = 'uint16',

        /** Unsigned 32-bit integer. */
    UInt32 = 'uint32',

        /** Unsigned 64-bit integer. */
    UInt64 = 'uint64',

        /** Signed 32-bit integer. */
    Int32 = 'int',

        /** Signed 64-bit floating point number. */
    Float64 = 'float',

        /**
         * Sequence of zero or more Unicode characters, encoded as UTF-8.
         * Maximum length is 64 bytes unless overridden by the "maxLen" property.
         * */
    String = 'string',

        /** Base64-encoded set of one or more TLV8's. */
    TLV8 = 'tlv8',

        /** Base64-encoded data blob. Maximum length is 2,097,152 bytes unless overridden by the "maxDataLen" property. */
    Data = 'data'
}

export enum CharacteristicUnit {
    /** The unit is only "degrees Celsius". */
    Celsius = 'celsius',

        /** The unit is in percentage "%". */
    Percentage = 'percentage',

        /** The unit is in arc degrees. */
    Arcdegrees = 'arcdegrees',

        /** The unit is in lux. */
    Lux = 'lux',

        /** The unit is in seconds. */
    Seconds = 'seconds'
}

export interface CharacteristicValueConstrains {
    /** Minimum value for the characteristic, which is only appropriate for characteristics that have a format of "int" or "float". */
    minimumValue?: number;

    /** Maximum value for the characteristic, which is only appropriate for characteristics that have a format of "int" or "float".*/
    maximumValue?: number;

    /**
     * Minimum step value for the characteristic, which is only appropriate for characteristics that have a format of "int" or "float".
     * For example, if this were 0.15, the characteristic value can be incremented from the minimum value in multiples of 0.15.
     *
     */
    minimumStep?: number;

    /**
     * Maximum number of characters if the format is "string".
     * If this property is omitted for "string" formats, then the default value is 64.
     * The maximum value allowed is 256.
     */
    maximumLength?: number;

    /**
     * Maximum number of characters if the format is "data".
     * If this property is omitted for "data" formats, then the default value is 2097152.
     */
    maximumDataLength?: number;

    /** An array of Numbers where each element represents a valid value. */
    validValues?: number[];

    /** A 2 element array representing the starting value and ending value of the range of valid values. */
    validValuesRange?: number[];
}

export enum CharacteristicCapability {
    /** This characteristic can only be read by paired controllers. */
    PairedRead = 'pr',

        /** This characteristic can only bewritten by paired controllers. */
    PairedWrite = 'pw',

        /** This characteristic supports events. The HAP Characteristic object must contain the "ev" key if it supports events. */
    Events = 'ev',

        /** This characteristic supports additional authorization data */
    AdditionalAuthorization = 'aa',

        /** This characteristic supports timed write procedure */
    TimedWrite = 'tw',

        /** This characteristic is hidden from the user */
    Hidden = 'hd'
}

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