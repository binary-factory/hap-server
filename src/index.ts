import { HAPServer } from './hap/hap-server';


const accessory = new HAPServer('C7:D9:93:E9:C2:A9', 'Acme Light Bridge', 1);
accessory.start()
    .then(() => {
        console.log('up!');
    })
    .catch((err) => console.log('error botting device', err));

