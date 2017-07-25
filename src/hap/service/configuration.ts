export interface ServiceConfiguration {
    /** String that defines the type of the service. See Service and Characteristic Types (page 72). */
    type: string;

    /**
     * CONDITIONAL. When set to True, this service is not visible to user.
     * Mandatory if accessory exposes custom services for proprietary controls on the accessory, optional otherwise.
     */
    hidden?: boolean;

    /** OPTIONAL. When set to True, this is the primary service on the accessory. */
    primary?: boolean;
}