import { PairVerifyFinishResponse, PairVerifyStartResponse } from '../messages/pair-verify';
import { PairVerifyContext } from './context';

export abstract class PairVerifyState {

    constructor(protected _handle: PairVerifyContext) {
    }

    start(): PairVerifyStartResponse {

    }

    finish(): PairVerifyFinishResponse {

    }
}