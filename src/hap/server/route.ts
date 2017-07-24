import { Session } from './session';
import * as http from 'http';
import { HAPContentTypes } from './content-types';
import { Urls } from './urls';
import * as tlv from '../common/tlv';

export interface Route {
    pathname: Urls;
    method: string;
    contentType: HAPContentTypes;
    handler: (session: Session, request: http.IncomingMessage, response: http.ServerResponse, body: tlv.TLVMap | any) => Promise<void>;
}