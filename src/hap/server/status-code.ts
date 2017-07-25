export enum StatusCode {
    /** This specifies a success for the request. */
    Success = 0,

        /** Request denied due to insufficient privileges. */
    RequestDenied = -70401,

        /** Unable to communicate with requested service.ts, e.g. the power to the accessory was turned off. */
    ServiceUnavailable = -70402,

        /** Resource is busy, try again. */
    Busy = -70403,

        /** Cannot write to read only characteristic. */
    CannotWrite = -70404,

        /** Cannot read from a write only characteristic. */
    CannotRead = -70405,

        /** Notification is not supported for characteristic. */
    NotificationNotSupported = -70406,

        /** Out of resources to process request. */
    OutOfResources = -70407,

        /** Operation timed out. */
    Timeout = -70408,

        /** Resource does not exist. */
    NotFound = -70409,

        /** Accessory received an invalid value in a write request. */
    InvalidRequest = -70410,

        /** Insufficient Authorization. */
    InsufficientAuthorization = -70411
}