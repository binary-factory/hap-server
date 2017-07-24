import { TLVMap } from '../hap/common/tlv';
import * as http from 'http';
import { LogLevel } from './debug-level';

export interface Logger {
    error(message?: any, ...optionalParams: any[]);

    warn(message?: any, ...optionalParams: any[]);

    info(message?: any, ...optionalParams: any[]);

    verbose(message?: any, ...optionalParams: any[]);

    debug(message?: any, ...optionalParams: any[]);

    silly(message?: any, ...optionalParams: any[]);

    log(logLevel: LogLevel, message?: any, ...optionalParams: any[])

    logTLV(level: LogLevel, tlv: TLVMap);

    logRequest(level: LogLevel, request: http.IncomingMessage);
}