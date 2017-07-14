export enum TLVTypes {
    /** Method to use for pairing. Format: Integer */
    Method = 0x00,

    /** Identifier for authentication. Format: UTF-8 */
    Identifier = 0x01,

    /** 16+ bytes of random salt. Format: Bytes */
    Salt = 0x02,

    /** Curve25519, SRP public key, or signed Ed25519 key. Format: Bytes */
    PublicKey = 0x03,

    /** Ed25519 or SRP proof. Format: Bytes */
    Proof = 0x04,

    /** Encrypted data with auth tag at end. Format: Bytes */
    EncryptedData = 0x05,

    /** Encrypted data with auth tag at end. Format: Integer */
    State = 0x06,

    /** Error code. Must only be present if error code is not 0. Format: Integer */
    Error = 0x07,

    /** Seconds to delay until retrying a setup code. Format: Integer */
    RetryDelay = 0x08,

    /** X.509 Certificate. Format: Bytes */
    Certificate = 0x09,

    /** Ed25519. Format: Bytes */
    Signature = 0x0a,

    /**
     * Bit value describing permissions of the controller being added.
     * None (0x00) : Regular user
     * Bit 1 (0x01) : Admin that is able to add and remove pairings against the accessory.
     */
    Permissions = 0x0b,

    /** Non-last fragment of data. If length is 0, it's an ACK. Format: Bytes */
    FragmentData = 0x0c,

    /** Last fragment of data. Format: Bytes */
    FragmentLast = 0x0d,

    /** Zero-length TLV that separates different TLVs in a list. Format: Null */
    Seperator = 0xff
}