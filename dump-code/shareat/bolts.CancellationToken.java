package bolts;

import java.util.Locale;
import java.util.concurrent.CancellationException;

public class CancellationToken {
    private boolean cancellationRequested;
    private final Object lock = new Object();

    CancellationToken() {
    }

    public boolean isCancellationRequested() {
        boolean z;
        synchronized (this.lock) {
            try {
                z = this.cancellationRequested;
            }
        }
        return z;
    }

    public void throwIfCancellationRequested() throws CancellationException {
        synchronized (this.lock) {
            if (this.cancellationRequested) {
                throw new CancellationException();
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public boolean tryCancel() {
        boolean z = true;
        synchronized (this.lock) {
            if (this.cancellationRequested) {
                z = false;
            } else {
                this.cancellationRequested = true;
            }
        }
        return z;
    }

    public String toString() {
        return String.format(Locale.US, "%s@%s[cancellationRequested=%s]", new Object[]{getClass().getName(), Integer.toHexString(hashCode()), Boolean.toString(this.cancellationRequested)});
    }
}