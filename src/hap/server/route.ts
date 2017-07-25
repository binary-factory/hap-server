import * as http from 'http';
import * as tlv from '../common/tlv/tlv';
import { ContentType } from './content-type';
import { Session } from './session';
import { Urls } from './url';

export interface Route {
    pathname: Urls;
    method: string;
    contentType: ContentType;
    handler: (session: Session, request: http.IncomingMessage, response: http.ServerResponse, body: tlv.TLVMap | any) => Promise<void>;
}