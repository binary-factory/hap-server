import { StatusCode } from '../constants/status-code';

export interface CharacteristicReadValueResult {
    status: StatusCode,
    value: any
}