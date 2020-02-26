package retrofit2.mock;

import java.io.IOException;
import java.util.Random;
import java.util.concurrent.TimeUnit;

public final class NetworkBehavior {
    private static final int DEFAULT_DELAY_MS = 2000;
    private static final int DEFAULT_FAILURE_PERCENT = 3;
    private static final int DEFAULT_VARIANCE_PERCENT = 40;
    private volatile long delayMs = 2000;
    private volatile Throwable failureException;
    private volatile int failurePercent = 3;
    private final Random random;
    private volatile int variancePercent = 40;

    public interface Adapter<T> {
        T applyBehavior(NetworkBehavior networkBehavior, T t);
    }

    public static NetworkBehavior create() {
        return new NetworkBehavior(new Random());
    }

    public static NetworkBehavior create(Random random2) {
        if (random2 != null) {
            return new NetworkBehavior(random2);
        }
        throw new NullPointerException("random == null");
    }

    private NetworkBehavior(Random random2) {
        this.random = random2;
        this.failureException = new IOException("Mock failure!");
        this.failureException.setStackTrace(new StackTraceElement[0]);
    }

    public void setDelay(long j, TimeUnit timeUnit) {
        if (j >= 0) {
            this.delayMs = timeUnit.toMillis(j);
            return;
        }
        throw new IllegalArgumentException("Amount must be positive value.");
    }

    public long delay(TimeUnit timeUnit) {
        return TimeUnit.MILLISECONDS.convert(this.delayMs, timeUnit);
    }

    public void setVariancePercent(int i) {
        if (i < 0 || i > 100) {
            throw new IllegalArgumentException("Variance percentage must be between 0 and 100.");
        }
        this.variancePercent = i;
    }

    public int variancePercent() {
        return this.variancePercent;
    }

    public void setFailurePercent(int i) {
        if (i < 0 || i > 100) {
            throw new IllegalArgumentException("Failure percentage must be between 0 and 100.");
        }
        this.failurePercent = i;
    }

    public int failurePercent() {
        return this.failurePercent;
    }

    public void setFailureException(Throwable th) {
        if (th != null) {
            this.failureException = th;
            return;
        }
        throw new NullPointerException("t == null");
    }

    public Throwable failureException() {
        return this.failureException;
    }

    public boolean calculateIsFailure() {
        return this.random.nextInt(100) < this.failurePercent;
    }

    public long calculateDelay(TimeUnit timeUnit) {
        float f = ((float) this.variancePercent) / 100.0f;
        float f2 = 1.0f - f;
        float nextFloat = this.random.nextFloat();
        float f3 = (float) this.delayMs;
        return TimeUnit.MILLISECONDS.convert((long) (f3 * (f2 + (nextFloat * ((f + 1.0f) - f2)))), timeUnit);
    }
}