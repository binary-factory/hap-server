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