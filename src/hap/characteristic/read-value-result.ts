import { StatusCode } from '../server/status-code';

export interface CharacteristicReadValueResult {
    status: StatusCode,
    value: any
}