export enum ErrorCodes {
    /** Generic error to handle unexpected errors. */
    Unknown = 0x01,

    /** Setup code or signature verification failed. */
    Authentication = 0x02,

    /** Client must look at the retry delay TLV item and wait that many seconds before retrying. */
    Backoff = 0x03,

    /** Server cannot accept any more pairings. */
    MaxPeers = 0x04,

    /** Server reached its maximum number of authentication attempts. */
    MaxTries = 0x05,

    /** Server pairing method is unavailable. */
    Unavailable = 0x06,

    /** Server is busy and cannot accept a pairing request at this time. */
    Busy = 0x07
}