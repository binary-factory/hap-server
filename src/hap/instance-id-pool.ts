export class InstanceIdPool {
    private counter = 1;

    nextInstanceId() : number {
        return this.counter++;
    }
}