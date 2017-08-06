import { PairVerifyContext } from './context';
import { VerifyFinishResponse } from './finish-response';
import { VerifyStartResponse } from './start-response';

export abstract class PairVerifyState {

    constructor(protected _handle: PairVerifyContext) {
    }

    start(): VerifyStartResponse {

    }

    finish(): VerifyFinishResponse {

    }
}