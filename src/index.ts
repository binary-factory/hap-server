import { HAPServer } from './hap/hap-server';


const accessory = new HAPServer('A2:D9:99:E9:C2:A9', 'bbbbbb', 1);
accessory.start()
    .then(() => {
        console.log('up!');
    })
    .catch((err) => console.log('error botting device', err));

