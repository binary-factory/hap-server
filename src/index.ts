import { HAPServer } from './hap/hap-server';

const accessory = new HAPServer('C3:D4:3E:E8:C7:A8', 'test11', 1);
accessory.start()
    .then(() => {
        console.log('up!');
    })
    .catch((err) => console.log('error botting device', err));

