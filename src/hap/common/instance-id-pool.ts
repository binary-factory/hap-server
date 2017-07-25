export class InstanceIdPool {
    private counter;

    constructor(counterOffset: number) {
        this.counter = counterOffset;
    }

    nextInstanceId() : number {
        return this.counter++;
    }
}