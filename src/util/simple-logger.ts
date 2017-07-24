import { Logger } from './logger';
import { LogLevel } from './debug-level';
import { TLVMap } from '../transport/tlv';
import * as http from 'http';
import { TLVTypes } from '../hap/constants/tlv-types';
import { isUndefined } from 'util';

export class SimpleLogger implements Logger {

    private logLevel: LogLevel = LogLevel.Silly;

    constructor(private identifier: string) {

    }

    private prefix(logLevel: LogLevel): string {
        const now = new Date();
        let logLevelLiteral: string;
        switch (logLevel) {
            case LogLevel.Error:
                logLevelLiteral = 'ERROR';
                break;
            case LogLevel.Warn:
                logLevelLiteral = 'WARN';
                break;
            case LogLevel.Info:
                logLevelLiteral = 'INFO';
                break;
            case LogLevel.Verbose:
                logLevelLiteral = 'VERBOSE';
                break;
            case LogLevel.Debug:
                logLevelLiteral = 'DEBUG';
                break;
            case LogLevel.Silly:
                logLevelLiteral = 'SILLY';
                break;
        }

        return `[${now.toLocaleString()}][${this.identifier}][${logLevelLiteral}]:`;
    }

    log(logLevel: LogLevel, message?: any, ...optionalParams: any[]) {
        switch (logLevel) {
            case LogLevel.Error:
                this.error(message, optionalParams);
                break;
            case LogLevel.Warn:
                this.warn(message, optionalParams);
                break;
            case LogLevel.Info:
                this.info(message, optionalParams);
                break;
            case LogLevel.Verbose:
                this.verbose(message, optionalParams);
                break;
            case LogLevel.Debug:
                this.debug(message, optionalParams);
                break;
            case LogLevel.Silly:
                this.silly(message, optionalParams);
                break;
        }
    }

    error(message?: any, ...optionalParams: any[]) {
        const minimumLogLevel = LogLevel.Error;
        if (this.logLevel >= minimumLogLevel) {
            const args = [`${this.prefix(minimumLogLevel)} ${message}`].concat(...optionalParams);
            console.error.apply(this, args);
        }
    }

    warn(message?: any, ...optionalParams: any[]) {
        const minimumLogLevel = LogLevel.Warn;
        if (this.logLevel >= minimumLogLevel) {
            const args = [`${this.prefix(minimumLogLevel)} ${message}`].concat(...optionalParams);
            console.warn.apply(this, args);
        }
    }

    info(message?: any, ...optionalParams: any[]) {
        const minimumLogLevel = LogLevel.Info;
        if (this.logLevel >= minimumLogLevel) {
            const args = [`${this.prefix(minimumLogLevel)} ${message}`].concat(...optionalParams);
            console.info.apply(this, args);
        }
    }

    verbose(message?: any, ...optionalParams: any[]) {
        const minimumLogLevel = LogLevel.Verbose;
        if (this.logLevel >= minimumLogLevel) {
            const args = [`${this.prefix(minimumLogLevel)} ${message}`].concat(...optionalParams);
            console.log.apply(this, args);
        }
    }

    debug(message?: any, ...optionalParams: any[]) {
        const minimumLogLevel = LogLevel.Debug;
        if (this.logLevel >= minimumLogLevel) {
            const args = [`${this.prefix(minimumLogLevel)} ${message}`].concat(...optionalParams);
            console.log.apply(this, args);
        }
    }

    silly(message?: any, ...optionalParams: any[]) {
        const minimumLogLevel = LogLevel.Silly;
        if (this.logLevel >= minimumLogLevel) {
            const args = [`${this.prefix(minimumLogLevel)} ${message}`].concat(...optionalParams);
            console.log.apply(this, args);
        }
    }

    logTLV(level: LogLevel, tlv: TLVMap) {
        if (this.logLevel >= level) {
            this.log(level, `TLV Entries: ${tlv.size}`);
            let counter = 1;
            tlv.forEach((value, type) => {
                let typeLiteral: string;
                switch (type) {
                    case TLVTypes.Method:
                        typeLiteral = 'Method';
                        break;
                    case TLVTypes.Identifier:
                        typeLiteral = 'Identifier';
                        break;
                    case TLVTypes.Salt:
                        typeLiteral = 'Salt';
                        break;
                    case TLVTypes.PublicKey:
                        typeLiteral = 'PublicKey';
                        break;
                    case TLVTypes.Proof:
                        typeLiteral = 'Proof';
                        break;
                    case TLVTypes.EncryptedData:
                        typeLiteral = 'EncryptedData';
                        break;
                    case TLVTypes.State:
                        typeLiteral = 'State';
                        break;
                    case TLVTypes.Error:
                        typeLiteral = 'Error';
                        break;
                    case TLVTypes.RetryDelay:
                        typeLiteral = 'RetryDelay';
                        break;
                    case TLVTypes.Certificate:
                        typeLiteral = 'Certificate';
                        break;
                    case TLVTypes.Permissions:
                        typeLiteral = 'Permissions';
                        break;
                    case TLVTypes.FragmentData:
                        typeLiteral = 'FragmentData';
                        break;
                    case TLVTypes.FragmentLast:
                        typeLiteral = 'FragmentLast';
                        break;
                    case TLVTypes.Seperator:
                        typeLiteral = 'Seperator';
                        break;
                    default:
                        typeLiteral = '<unknown>';
                        break;
                }
                this.log(level, `\t- ${counter++}\t: ${typeLiteral}: ${value.toString('hex')}`);
            });
        }
    }

    logRequest(level: LogLevel, request: http.IncomingMessage) {
        if (this.logLevel >= level) {
            this.log(level, `Request: ${request.method} - ${request.url}`);
            this.log(level, '\t- Headers:');
            for (let header of Object.keys(request.headers)) {
                const headerValue = request.headers[header];
                this.log(level, `\t\t- ${header}: ${headerValue}`);
            }
        }
    }
}