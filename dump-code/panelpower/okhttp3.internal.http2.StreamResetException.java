package okhttp3.internal.http2;

import java.io.IOException;

public final class StreamResetException extends IOException {
    public final ErrorCode errorCode;

    /* JADX WARN: Illegal instructions before constructor call commented (this can break semantics) */
    public StreamResetException(ErrorCode errorCode2) {
        // StringBuilder sb = new StringBuilder();
        // sb.append("stream was reset: ");
        // sb.append(errorCode2);
        super(sb.toString());
        this.errorCode = errorCode2;
    }
}