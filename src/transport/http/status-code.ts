export enum HTTPStatusCode {
    /** Success. */
    OK = 200,

    /** Generic error for a problem with the request, e.g. bad TLV, state error, etc. */
    BadRequest = 400,

    /** Wrong HTTP request method, e.g. GET when expecting POST. */
    MethodNotAllowed = 405,

    /** Server cannot handle any more requests of this type, e.g. attempt to pair while already pairing. */
    TooManyRequests = 429,

    /** Request to secure resource made without establishing security, e.g. didn't perform Pair Verify. */
    ConnectionAuthorizationRequired = 470,

    /** Server had a problem, e.g. ran out of memory. */
    InternalServerError = 500,

    NotFound = 404,

    UnsupportedMediaType = 415,

    NoContent = 204,

    MultiStatus = 207
}