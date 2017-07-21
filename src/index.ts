import { HAPServer } from './hap/hap-server';

const accessory = new HAPServer('C1:C4:3D:E8:C4:A8', 'test8', 1);
accessory.start()
    .then(() => {
        console.log('up!');
    })
    .catch((err) => console.log('error botting device', err));

