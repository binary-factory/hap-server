import * as http from 'http';
import * as url from 'url';
import { ContentType } from '../../constants/content-type';
import { HAPRequest } from '../hap-request';
import { Urls } from '../url';
import { RouterHandler } from './handler';
import { Route } from './route';

export class Router {
    _routes: Route[];

    constructor(private _handler: RouterHandler) {
        this._routes = [
            {
                pathname: Urls.PairSetup,
                method: 'POST',
                contentType: ContentType.TLV8,
                handler: (request, response) => {
                    return this._handler.handlePairSetup(request, response);
                }
            },
            {
                pathname: Urls.PairVerify,
                method: 'POST',
                contentType: ContentType.TLV8,
                handler: (request, response) => {
                    return this._handler.handlePairVerify(request, response);
                }
            },
            {
                pathname: Urls.Pairings,
                method: 'POST',
                contentType: ContentType.TLV8,
                handler: (request, response) => {
                    return this._handler.handlePairings(request, response);
                }
            },
            {
                pathname: Urls.Accessories,
                method: 'GET',
                contentType: ContentType.EMPTY,
                handler: (request, response) => {
                    return this._handler.handleAttributeDatabase(request, response);
                }
            },
            {
                pathname: Urls.Characteristics,
                method: 'GET',
                contentType: ContentType.EMPTY,
                handler: (request, response) => {
                    return this._handler.handleCharacteristicRead(request, response);
                }
            },
            {
                pathname: Urls.Characteristics,
                method: 'PUT',
                contentType: ContentType.JSON,
                handler: (request, response) => {
                    return this._handler.handleCharacteristicWrite(request, response);
                }
            },
            {
                pathname: Urls.Identify,
                method: 'POST',
                contentType: ContentType.EMPTY,
                handler: (request, response) => {
                    return this._handler.handleIdentify(request, response);
                }
            }
        ];
    }

    async route(request: HAPRequest, response: http.ServerResponse): Promise<void> {
        const requestPathname = url.parse(request.http.url).pathname;
        const requestMethod = request.http.method;
        const requestContentType = request.http.headers['content-type'] || ContentType.EMPTY;


        this.logger.info('Request on Ray:', proxyConnection.rayId);
        this.logger.logRequest(LogLevel.Info, request);

        // Math pathname.
        let matching: Route[] = this._routes.filter((route) => route.pathname === requestPathname);
        if (matching.length) {
            // Math method.
            matching = matching.filter((route) => {
                return route.method === requestMethod;
            });
            if (matching.length) {
                // Match content-type.
                matching = matching.filter((route) => {
                    return route.contentType === requestContentType;
                });
                if (matching.length) {
                    // There should be only one route left.
                    const matchingRoute = matching[0];

                    // Parse body if not empty.
                    let parsedBody: TLVType | any;
                    if (body.length > 0) {
                        try {
                            if (matchingRoute.contentType === ContentType.TLV8) {
                                this.logger.debug('parse body as TLV');
                                parsedBody = tlv.decode(body);
                                this.logger.logTLV(LogLevel.Debug, parsedBody);
                            } else if (matchingRoute.contentType === ContentType.JSON) {
                                this.logger.debug('parse body as JSON');
                                parsedBody = JSON.parse(body.toString());
                                this.logger.debug(body.toString());
                            }
                        } catch (err) {
                            this.logger.error('could not parse body', err);
                            response.writeHead(HTTPStatusCode.BadRequest);
                        }
                    } else {
                        this.logger.debug('empty body');
                    }

                    // Call handler.
                    await matchingRoute.handler(request, response, parsedBody);

                } else {
                    response.writeHead(HTTPStatusCode.UnsupportedMediaType);
                }

            } else {
                response.writeHead(HTTPStatusCode.MethodNotAllowed);
            }
        } else {
            this.logger.warn('unresolved route', requestPathname);
            response.writeHead(HTTPStatusCode.NotFound);
        }

        response.end();
    }

}