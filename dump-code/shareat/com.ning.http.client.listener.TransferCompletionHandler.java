package com.ning.http.client.listener;

import com.ning.http.client.AsyncCompletionHandlerBase;
import com.ning.http.client.AsyncHandler.STATE;
import com.ning.http.client.FluentCaseInsensitiveStringsMap;
import com.ning.http.client.HttpResponseBodyPart;
import com.ning.http.client.HttpResponseHeaders;
import com.ning.http.client.Response;
import com.ning.http.util.MiscUtil;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TransferCompletionHandler extends AsyncCompletionHandlerBase {
    private static final Logger logger = LoggerFactory.getLogger(TransferCompletionHandler.class);
    private final boolean accumulateResponseBytes;
    private AtomicLong bytesTransferred;
    private final ConcurrentLinkedQueue<TransferListener> listeners;
    private AtomicLong totalBytesToTransfer;
    private TransferAdapter transferAdapter;

    public static abstract class TransferAdapter {
        private final FluentCaseInsensitiveStringsMap headers;

        public abstract void getBytes(byte[] bArr);

        public TransferAdapter(FluentCaseInsensitiveStringsMap headers2) throws IOException {
            this.headers = headers2;
        }

        public FluentCaseInsensitiveStringsMap getHeaders() {
            return this.headers;
        }
    }

    public TransferCompletionHandler() {
        this(false);
    }

    public TransferCompletionHandler(boolean accumulateResponseBytes2) {
        this.listeners = new ConcurrentLinkedQueue<>();
        this.bytesTransferred = new AtomicLong();
        this.totalBytesToTransfer = new AtomicLong(0);
        this.accumulateResponseBytes = accumulateResponseBytes2;
    }

    public TransferCompletionHandler addTransferListener(TransferListener t) {
        this.listeners.offer(t);
        return this;
    }

    public TransferCompletionHandler removeTransferListener(TransferListener t) {
        this.listeners.remove(t);
        return this;
    }

    public void transferAdapter(TransferAdapter transferAdapter2) {
        this.transferAdapter = transferAdapter2;
    }

    public STATE onHeadersReceived(HttpResponseHeaders headers) throws Exception {
        fireOnHeaderReceived(headers.getHeaders());
        return super.onHeadersReceived(headers);
    }

    public STATE onBodyPartReceived(HttpResponseBodyPart content) throws Exception {
        STATE s = STATE.CONTINUE;
        if (this.accumulateResponseBytes) {
            s = super.onBodyPartReceived(content);
        }
        fireOnBytesReceived(content.getBodyPartBytes());
        return s;
    }

    public Response onCompleted(Response response) throws Exception {
        fireOnEnd();
        return response;
    }

    public STATE onHeaderWriteCompleted() {
        List<String> list = this.transferAdapter.getHeaders().get((Object) "Content-Length");
        if (MiscUtil.isNonEmpty((Collection<?>) list) && list.get(0) != "") {
            this.totalBytesToTransfer.set(Long.valueOf(list.get(0)).longValue());
        }
        fireOnHeadersSent(this.transferAdapter.getHeaders());
        return STATE.CONTINUE;
    }

    public STATE onContentWriteCompleted() {
        return STATE.CONTINUE;
    }

    public STATE onContentWriteProgress(long amount, long current, long total) {
        if (this.bytesTransferred.get() == -1) {
            return STATE.CONTINUE;
        }
        if (this.totalBytesToTransfer.get() == 0) {
            this.totalBytesToTransfer.set(total);
        }
        this.bytesTransferred.addAndGet(amount);
        if (this.transferAdapter != null) {
            byte[] bytes = new byte[((int) amount)];
            this.transferAdapter.getBytes(bytes);
            fireOnBytesSent(bytes);
        }
        return STATE.CONTINUE;
    }

    public void onThrowable(Throwable t) {
        fireOnThrowable(t);
    }

    private void fireOnHeadersSent(FluentCaseInsensitiveStringsMap headers) {
        Iterator i$ = this.listeners.iterator();
        while (i$.hasNext()) {
            TransferListener l = i$.next();
            try {
                l.onRequestHeadersSent(headers);
            } catch (Throwable t) {
                l.onThrowable(t);
            }
        }
    }

    private void fireOnHeaderReceived(FluentCaseInsensitiveStringsMap headers) {
        Iterator i$ = this.listeners.iterator();
        while (i$.hasNext()) {
            TransferListener l = i$.next();
            try {
                l.onResponseHeadersReceived(headers);
            } catch (Throwable t) {
                l.onThrowable(t);
            }
        }
    }

    private void fireOnEnd() {
        long count = this.bytesTransferred.getAndSet(-1);
        if (!(count == this.totalBytesToTransfer.get() || this.transferAdapter == null)) {
            byte[] bytes = new byte[8192];
            int leftBytes = (int) (this.totalBytesToTransfer.get() - count);
            int length = 8192;
            while (leftBytes > 0) {
                if (leftBytes > 8192) {
                    leftBytes -= 8192;
                } else {
                    length = leftBytes;
                    leftBytes = 0;
                }
                if (length < 8192) {
                    bytes = new byte[length];
                }
                this.transferAdapter.getBytes(bytes);
                fireOnBytesSent(bytes);
            }
        }
        Iterator i$ = this.listeners.iterator();
        while (i$.hasNext()) {
            TransferListener l = i$.next();
            try {
                l.onRequestResponseCompleted();
            } catch (Throwable t) {
                l.onThrowable(t);
            }
        }
    }

    private void fireOnBytesReceived(byte[] b) {
        Iterator i$ = this.listeners.iterator();
        while (i$.hasNext()) {
            TransferListener l = i$.next();
            try {
                l.onBytesReceived(ByteBuffer.wrap(b));
            } catch (Throwable t) {
                l.onThrowable(t);
            }
        }
    }

    private void fireOnBytesSent(byte[] b) {
        Iterator i$ = this.listeners.iterator();
        while (i$.hasNext()) {
            TransferListener l = i$.next();
            try {
                l.onBytesSent(ByteBuffer.wrap(b));
            } catch (Throwable t) {
                l.onThrowable(t);
            }
        }
    }

    private void fireOnThrowable(Throwable t) {
        Iterator i$ = this.listeners.iterator();
        while (i$.hasNext()) {
            try {
                i$.next().onThrowable(t);
            } catch (Throwable t2) {
                logger.warn((String) "onThrowable", t2);
            }
        }
    }
}