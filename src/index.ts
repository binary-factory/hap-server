import { HAPServer } from './hap/hap-server';

const accessory = new HAPServer('CC:C4:3D:E8:C3:A8', 'test7', 1);
accessory.listen().catch((err) => console.log('error botting device', err));

