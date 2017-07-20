export enum HAPUrls {
    /** Used for Pair Setup. */
    PairSetup = '/pair-setup',

        /** Used for Pair Verify. */
    PairVerify = '/pair-verify',

        /**
         * Used for adding, removing, and listing pairings. Always sends HTTP POST with TLV8
         * payloads defined in Add Pairing (page 51), Remove Pairing (page 53), and List Pairings (page 55).
         */
    Pairings = '/pairings',

        /**
         * Retrieve the accessory attribute database from the accessory.
         * Only valid from paired controllers. See IP Accessory Attribute
         * Database (page 71).
         */
    Accessories = '/accessories',

        /** Reads characteristic data. See Reading Characteristics (page 84). */
    Characteristics = '/characteristics',

        /**
         * Request the accessory to run its identify routine. Only valid if the
         * accessory is unpaired. See Identify HTTP URL (page 88).
         */
    Identify = '/identify'
}
