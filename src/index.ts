import { Accessory } from './hap/accessory';


const accessory = new Accessory('C8:D9:93:E4:C2:A9', 'Acme Light Bridge', 1);
accessory.start()
    .then(() => {
        console.log('up!');
    })
    .catch((err) => console.log('error botting device', err));