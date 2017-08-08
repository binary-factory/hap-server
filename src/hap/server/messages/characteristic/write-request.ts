// NOTE: At least one of "value" or "ev" will be present in the characteristic write request object.
export interface CharacteristicWriteRequest {
    characteristics: [{
        /** The instance ID of the accessory that contains the characteristic to be written. Required. */
        aid: number;

        /**
         * The instance ID of the characteristic to be written.
         * If a provided instance ID is not a Characteristic
         * object, the accessory must respond with an "Invalid Parameters" error.
         * See Table 5-12 (page 80).Required.
         */
        iid: number;

        /** Optional property that contains the value to be written to the characteristic. */
        value?: any;

        /** Optional property that indicates the state of event notifications for the characteristic. */
        ev?: boolean;

        /** Optional property that contains a base 64 encoded string of the authorization data associated with the characteristic. */
        authData?: string;

        /**
         * Optional property that indicates if remote access was used to send the request.
         * A value of true indicates remote access was used.
         */
        remote?: boolean;
    }]
}