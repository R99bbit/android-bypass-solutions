package bolts;

public class Capture<T> {
    private T value;

    public Capture() {
    }

    public Capture(T value2) {
        this.value = value2;
    }

    public T get() {
        return this.value;
    }

    public void set(T value2) {
        this.value = value2;
    }
}