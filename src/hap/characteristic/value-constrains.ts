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