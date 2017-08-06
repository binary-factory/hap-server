export interface StartResponse {
    setupCode: string;
    accessorySRPPublicKey: Buffer;
    accessorySRPSalt: Buffer;
}