import { Accessory } from './hap/accessory';

const accessory = new Accessory('CC:22:3D:E3:CE:F6', 'test', 1);
accessory.start().catch((err) => console.log('error botting device', err));