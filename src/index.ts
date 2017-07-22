import { HAPServer } from './hap/hap-server';

let test = Buffer.alloc(0);
console.log(test.slice(0));
const accessory = new HAPServer('C6:D6:56:E8:C7:A9', 'test12', 1);
accessory.start()
    .then(() => {
        console.log('up!');
    })
    .catch((err) => console.log('error botting device', err));

