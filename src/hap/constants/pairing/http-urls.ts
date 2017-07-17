export enum HTTPUrls {
    /** Used for Pair Setup. */
    PairSetup = '/pair-setup',

    /** Used for Pair Verify. */
    PairVerify = '/pair-verify',

    /**
     * Used for adding, removing, and listing pairings. Always sends HTTP POST with TLV8
     * payloads defined in Add Pairing (page 51), Remove Pairing (page 53), and List Pairings (page 55).
     */
    Pairings = '/pairings'
}
