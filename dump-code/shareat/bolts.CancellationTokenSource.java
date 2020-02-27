package bolts;

import java.util.Locale;

public class CancellationTokenSource {
    private final CancellationToken token = new CancellationToken();

    public boolean isCancellationRequested() {
        return this.token.isCancellationRequested();
    }

    public CancellationToken getToken() {
        return this.token;
    }

    public void cancel() {
        this.token.tryCancel();
    }

    public String toString() {
        return String.format(Locale.US, "%s@%s[cancellationRequested=%s]", new Object[]{getClass().getName(), Integer.toHexString(hashCode()), Boolean.toString(isCancellationRequested())});
    }
}