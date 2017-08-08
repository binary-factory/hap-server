export interface CharacteristicReadRequest {
    /**
     * The identifiers for the characteristics to be read must be formatted as <AccessoryInstance ID>.
     * <Characteristic Instance ID>, as a comma-separated list.
     * For example, to read the values of characteristics with instance ID "4" and "8" on an accessory
     * with an instanceID of "1" the URL parameter would be id=1.4,1.8.
     * id is required for all GET requests.
     */
    id: string;

    /**
     * Boolean value that determines whether or not the response should include metadata.
     * If meta is not present it must be assumed to be "0". If meta is "1",
     * then the response must include the following properties if they exist for the characteristic:
     * "format", "unit", "minValue", "maxValue", "minStep", and "maxLen".
     */
    meta?: '1' | '0';

    /**
     * Boolean value that determines whether or not the response should include the permissions of the characteristic.
     * If perms is not present it must be assumed to be "0".
     */
    perms?: '1' | '0';

    /**
     * Boolean value that determines whether or not the response should include the type of characteristic.
     * If type is not present it must be assumed to be "0".
     */
    type?: '1' | '0';

    /**
     * Boolean value that determines whether or not the "ev" property of the characteristic should be included in the response.
     * If ev is not present it must be assumed to be "0".
     */
    ev?: '1' | '0';
}