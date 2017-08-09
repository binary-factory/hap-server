import * as http from 'http';
import { HAPRequest } from '../hap-request';

export interface RouterHandler {
    handlePairSetup(request: HAPRequest, response: http.ServerResponse): Promise<void>;

    handlePairVerify(request: HAPRequest, response: http.ServerResponse): Promise<void>;

    handlePairings(request: HAPRequest, response: http.ServerResponse): Promise<void>;

    handleAttributeDatabase(request: HAPRequest, response: http.ServerResponse): Promise<void>;

    handleCharacteristicRead(request: HAPRequest, response: http.ServerResponse): Promise<void>;

    handleCharacteristicWrite(request: HAPRequest, response: http.ServerResponse): Promise<void>;

    handleIdentify(request: HAPRequest, response: http.ServerResponse): Promise<void>;
}