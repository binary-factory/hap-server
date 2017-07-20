import { HAPServer } from './transport/HAPServer';

const accessory = new HAPServer('CC:22:3D:E3:CE:F3', 'test', 1);
accessory.listen().catch((err) => console.log('error botting device', err));

