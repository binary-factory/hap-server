import { PairVerifyState } from './state';
import { PairVerifyStateInitial } from './states/initial';

export class PairVerifyContext {
    private _state: PairVerifyState = new PairVerifyStateInitial(this);
}