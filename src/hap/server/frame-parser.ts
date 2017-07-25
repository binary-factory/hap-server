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

export class FrameParser {

    private readState = ReadState.Length;

    private remainder: Buffer = Buffer.alloc(0);

    private messageLength: number;

    private additionalAuthenticatedData: Buffer;

    private encryptedData: Buffer;

    private authTag: Buffer;

    constructor(private lengthBytes: number,
                private authenticationCodeBytes: number) {

    }

    update(chunk: Buffer): Frame[] {
        let frames: Frame[] = [];
        let buffer = Buffer.concat([this.remainder, chunk]);
        let bytesRead: number;

        do {
            bytesRead = 0;
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

                    const frame: Frame = {
                        additionalAuthenticatedData: this.additionalAuthenticatedData,
                        encryptedData: this.encryptedData,
                        authTag: this.authTag
                    };

                    frames.push(frame);
                    break;
            }

            buffer = buffer.slice(bytesRead);
        } while (bytesRead > 0);

        this.remainder = buffer;
        return frames;
    }
}