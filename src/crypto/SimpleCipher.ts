/**
 * Created by o.haase on 13.07.2017.
 */
export interface SimpleCipher {
    update(chunk: Buffer);
    final(): Buffer;

}