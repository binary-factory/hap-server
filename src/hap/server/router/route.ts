import * as http from 'http';
import * as tlv from '../../../transport/tlv/tlv';
import { ContentType } from '../../constants/content-type';
import { HAPRequest } from '../hap-request';
import { Urls } from '../url';

export interface Route {
    pathname: Urls;
    method: string;
    contentType: ContentType;
    handler: (request: HAPRequest, response: http.ServerResponse, body: tlv.TLVMap | any) => Promise<void>;
}