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