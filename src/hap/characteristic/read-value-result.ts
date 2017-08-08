import { StatusCode } from '../server/const/status-code';

export interface CharacteristicReadValueResult {
    status: StatusCode,
    value: any
}