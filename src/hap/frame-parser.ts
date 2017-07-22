import * as events from 'events';


export interface Frame {
    additionalAuthenticatedData: Buffer;
    encryptedData: Buffer;
    authTag: Buffer;
}

enum ReadState {
    Length,
    EncryptedData,
    AuthTag
}

export class FrameParser extends events.EventEmitter {

    private readState = ReadState.Length;

    private remainder: Buffer = Buffer.alloc(0);

    private messageLength: number;

    private additionalAuthenticatedData: Buffer;

    private encryptedData: Buffer;

    private authTag: Buffer;

    constructor(private lengthBytes: number,
                private authenticationCodeBytes: number) {
        super();
    }

    update(chunk: Buffer) {
        let buffer: Buffer;
        if (chunk) {
            buffer = Buffer.concat([this.remainder, chunk]);
        } else {
            buffer = this.remainder;
        }

        let bytesRead = 0;

        switch (this.readState) {
            case ReadState.Length:
                if (buffer.length >= this.lengthBytes) {
                    this.readState = ReadState.EncryptedData;
                    this.additionalAuthenticatedData = buffer.slice(0, 2);
                    this.messageLength = buffer.readUIntLE(0, this.lengthBytes);
                    bytesRead = this.lengthBytes;
                }
                break;

            case ReadState.EncryptedData:
                if (buffer.length >= this.messageLength) {
                    this.readState = ReadState.AuthTag;
                    this.encryptedData = buffer.slice(0, this.messageLength);
                    bytesRead = this.messageLength;
                }
                break;

            case ReadState.AuthTag:
                if (buffer.length >= this.authenticationCodeBytes) {
                    this.readState = ReadState.Length;
                    this.authTag = buffer.slice(0, this.authenticationCodeBytes);
                    bytesRead = this.authenticationCodeBytes;
                }

                const encryptedMessage: Frame = {
                    additionalAuthenticatedData: this.additionalAuthenticatedData,
                    encryptedData: this.encryptedData,
                    authTag: this.authTag
                };

                this.emit('encryptedData', encryptedMessage);
                break;
        }

        this.remainder = buffer.slice(bytesRead);

        // Rerun on bytes read.
        if (bytesRead > 0) {
            process.nextTick(() => {
                this.update(null);
            });
        }
    }
}