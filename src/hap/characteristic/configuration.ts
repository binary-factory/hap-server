import { CharacteristicCapability } from './capability';
import { CharacteristicFormat } from './format';
import { CharacteristicUnit } from './unit';
import { CharacteristicValueConstrains } from './value-constrains';

export interface CharacteristicConfiguration {
    /** REQUIRED. String that defines the type of the characteristic. See Service and Characteristic Types (page 72). */
    type: string;

    /** REQUIRED. Array of permission strings describing the capabilities of the characteristic. See Table 5-4 (page 67). */
    capabilities: CharacteristicCapability[];

    /**
     * REQUIRED. The value of the characteristic, which must conform to the "format" property.
     * The literal value null may also be used if the characteristic has no value.
     * This property must be present if and only if the characteristic contains the Paired Read permission, see Table 5-4 (page 67).
     */
    value?: any;

    /** REQUIRED. Format of the value, e.g. "float". See Table 5-5 (page 67). */
    format: CharacteristicFormat;

    /** OPTIONAL. Unit of the value, e.g. "celsius". See Table 5-6 (page 68). */
    unit?: CharacteristicUnit;

    /** OPTIONAL. Boolean indicating if event notifications are enabled for this characteristic. */
    eventNotifications?: boolean;

    /** OPTIONAL. String describing the characteristic on a manufacturer-specific basis, such as an indoor versus outdoor temperature reading.*/
    description?: string;

    /** OPTIONAL. Constrains for the value. */
    constrains?: CharacteristicValueConstrains;
}