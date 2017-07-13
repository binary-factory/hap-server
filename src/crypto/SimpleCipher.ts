/**
 * Created by o.haase on 13.07.2017.
 */
export interface SimpleCipher {
    update(data: Buffer);
    final(): Buffer;

}