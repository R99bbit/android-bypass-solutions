package com.ning.http.client.providers.grizzly;

import com.ning.http.client.Body;
import com.ning.http.client.BodyGenerator;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import org.glassfish.grizzly.Buffer;
import org.glassfish.grizzly.CompletionHandler;
import org.glassfish.grizzly.Connection;
import org.glassfish.grizzly.WriteHandler;
import org.glassfish.grizzly.WriteResult;
import org.glassfish.grizzly.filterchain.FilterChain;
import org.glassfish.grizzly.filterchain.FilterChainContext;
import org.glassfish.grizzly.http.HttpContent;
import org.glassfish.grizzly.http.HttpContent.Builder;
import org.glassfish.grizzly.http.HttpRequestPacket;
import org.glassfish.grizzly.impl.FutureImpl;
import org.glassfish.grizzly.ssl.SSLBaseFilter.HandshakeListener;
import org.glassfish.grizzly.ssl.SSLFilter;
import org.glassfish.grizzly.ssl.SSLUtils;
import org.glassfish.grizzly.threadpool.Threads;
import org.glassfish.grizzly.utils.Exceptions;
import org.glassfish.grizzly.utils.Futures;

public class FeedableBodyGenerator implements BodyGenerator {
    static final /* synthetic */ boolean $assertionsDisabled = (!FeedableBodyGenerator.class.desiredAssertionStatus());
    public static final int DEFAULT = -2;
    public static final int UNBOUND = -1;
    private final EmptyBody EMPTY_BODY = new EmptyBody();
    /* access modifiers changed from: private */
    public boolean asyncTransferInitiated;
    private int configuredMaxPendingBytes = -2;
    /* access modifiers changed from: private */
    public volatile Builder contentBuilder;
    /* access modifiers changed from: private */
    public volatile FilterChainContext context;
    /* access modifiers changed from: private */
    public Feeder feeder;
    /* access modifiers changed from: private */
    public int origMaxPendingBytes;
    /* access modifiers changed from: private */
    public volatile HttpRequestPacket requestPacket;

    public static abstract class BaseFeeder implements Feeder {
        protected final FeedableBodyGenerator feedableBodyGenerator;

        private final class LastPacketCompletionHandler implements CompletionHandler<WriteResult> {
            private final Connection c;
            private final CompletionHandler<WriteResult> delegate;
            private final int origMaxPendingBytes;

            private LastPacketCompletionHandler() {
                this.delegate = !BaseFeeder.this.feedableBodyGenerator.requestPacket.isCommitted() ? BaseFeeder.this.feedableBodyGenerator.context.getTransportContext().getCompletionHandler() : null;
                this.c = BaseFeeder.this.feedableBodyGenerator.context.getConnection();
                this.origMaxPendingBytes = BaseFeeder.this.feedableBodyGenerator.origMaxPendingBytes;
            }

            public void cancelled() {
                this.c.setMaxAsyncWriteQueueSize(this.origMaxPendingBytes);
                if (this.delegate != null) {
                    this.delegate.cancelled();
                }
            }

            public void failed(Throwable throwable) {
                this.c.setMaxAsyncWriteQueueSize(this.origMaxPendingBytes);
                if (this.delegate != null) {
                    this.delegate.failed(throwable);
                }
            }

            public void completed(WriteResult result) {
                this.c.setMaxAsyncWriteQueueSize(this.origMaxPendingBytes);
                if (this.delegate != null) {
                    this.delegate.completed(result);
                }
            }

            public void updated(WriteResult result) {
                if (this.delegate != null) {
                    this.delegate.updated(result);
                }
            }
        }

        protected BaseFeeder(FeedableBodyGenerator feedableBodyGenerator2) {
            this.feedableBodyGenerator = feedableBodyGenerator2;
        }

        public final synchronized void feed(Buffer buffer, boolean last) throws IOException {
            CompletionHandler<WriteResult> handler = null;
            synchronized (this) {
                if (buffer == null) {
                    throw new IllegalArgumentException("Buffer argument cannot be null.");
                } else if (!this.feedableBodyGenerator.asyncTransferInitiated) {
                    throw new IllegalStateException("Asynchronous transfer has not been initiated.");
                } else {
                    blockUntilQueueFree(this.feedableBodyGenerator.context.getConnection());
                    HttpContent content = this.feedableBodyGenerator.contentBuilder.content(buffer).last(last).build();
                    if (last) {
                        handler = new LastPacketCompletionHandler<>();
                    }
                    this.feedableBodyGenerator.context.write(content, handler);
                }
            }
        }

        private static void blockUntilQueueFree(Connection c) {
            if (!c.canWrite()) {
                final FutureImpl<Boolean> future = Futures.createSafeFuture();
                c.notifyCanWrite(new WriteHandler() {
                    public void onWritePossible() throws Exception {
                        future.result(Boolean.TRUE);
                    }

                    public void onError(Throwable t) {
                        future.failure(Exceptions.makeIOException(t));
                    }
                });
                block(c, future);
            }
        }

        private static void block(Connection c, FutureImpl<Boolean> future) {
            try {
                long writeTimeout = c.getTransport().getWriteTimeout(TimeUnit.MILLISECONDS);
                if (writeTimeout != -1) {
                    future.get(writeTimeout, TimeUnit.MILLISECONDS);
                } else {
                    future.get();
                }
            } catch (ExecutionException e) {
                GrizzlyAsyncHttpProvider.getHttpTransactionContext(c).abort(e.getCause());
            } catch (Exception e2) {
                GrizzlyAsyncHttpProvider.getHttpTransactionContext(c).abort(e2);
            }
        }
    }

    private final class EmptyBody implements Body {
        private EmptyBody() {
        }

        public long getContentLength() {
            return -1;
        }

        public long read(ByteBuffer buffer) throws IOException {
            return 0;
        }

        public void close() throws IOException {
            FeedableBodyGenerator.this.context.completeAndRecycle();
            FeedableBodyGenerator.this.context = null;
            FeedableBodyGenerator.this.requestPacket = null;
            FeedableBodyGenerator.this.contentBuilder = null;
        }
    }

    public interface Feeder {
        void feed(Buffer buffer, boolean z) throws IOException;

        void flush() throws IOException;
    }

    public static abstract class NonBlockingFeeder extends BaseFeeder {

        public interface ReadyToFeedListener {
            void ready();
        }

        private final class ReadyToFeedListenerImpl implements ReadyToFeedListener {
            private ReadyToFeedListenerImpl() {
            }

            public void ready() {
                NonBlockingFeeder.this.flush();
            }
        }

        private final class WriteHandlerImpl implements WriteHandler {
            private final Connection c;

            private WriteHandlerImpl() {
                this.c = NonBlockingFeeder.this.feedableBodyGenerator.context.getConnection();
            }

            public void onWritePossible() throws Exception {
                NonBlockingFeeder.this.writeUntilFullOrDone(this.c);
                if (!NonBlockingFeeder.this.isDone()) {
                    if (!NonBlockingFeeder.this.isReady()) {
                        NonBlockingFeeder.this.notifyReadyToFeed(new ReadyToFeedListenerImpl());
                    }
                    if (!this.c.canWrite()) {
                        this.c.notifyCanWrite(this);
                    }
                }
            }

            public void onError(Throwable t) {
                this.c.setMaxAsyncWriteQueueSize(NonBlockingFeeder.this.feedableBodyGenerator.origMaxPendingBytes);
                GrizzlyAsyncHttpProvider.getHttpTransactionContext(this.c).abort(t);
            }
        }

        public abstract void canFeed();

        public abstract boolean isDone();

        public abstract boolean isReady();

        public abstract void notifyReadyToFeed(ReadyToFeedListener readyToFeedListener);

        public NonBlockingFeeder(FeedableBodyGenerator feedableBodyGenerator) {
            super(feedableBodyGenerator);
        }

        public synchronized void flush() {
            Connection c = this.feedableBodyGenerator.context.getConnection();
            if (isReady()) {
                writeUntilFullOrDone(c);
                if (!isDone()) {
                    if (!isReady()) {
                        notifyReadyToFeed(new ReadyToFeedListenerImpl());
                    }
                    if (!c.canWrite()) {
                        c.notifyCanWrite(new WriteHandlerImpl());
                    }
                }
            } else {
                notifyReadyToFeed(new ReadyToFeedListenerImpl());
            }
        }

        /* access modifiers changed from: private */
        public void writeUntilFullOrDone(Connection c) {
            while (c.canWrite()) {
                if (isReady()) {
                    canFeed();
                }
                if (!isReady()) {
                    return;
                }
            }
        }
    }

    public static abstract class SimpleFeeder extends BaseFeeder {
        public SimpleFeeder(FeedableBodyGenerator feedableBodyGenerator) {
            super(feedableBodyGenerator);
        }
    }

    public Body createBody() throws IOException {
        return this.EMPTY_BODY;
    }

    public synchronized void setMaxPendingBytes(int maxPendingBytes) {
        if (maxPendingBytes < -2) {
            throw new IllegalArgumentException("Invalid maxPendingBytes value: " + maxPendingBytes);
        } else if (this.asyncTransferInitiated) {
            throw new IllegalStateException("Unable to set max pending bytes after async data transfer has been initiated.");
        } else {
            this.configuredMaxPendingBytes = maxPendingBytes;
        }
    }

    public synchronized void setFeeder(Feeder feeder2) {
        if (this.asyncTransferInitiated) {
            throw new IllegalStateException("Unable to set Feeder after async data transfer has been initiated.");
        } else if (feeder2 == null) {
            throw new IllegalArgumentException("Feeder argument cannot be null.");
        } else {
            this.feeder = feeder2;
        }
    }

    /* access modifiers changed from: 0000 */
    public synchronized void initializeAsynchronousTransfer(final FilterChainContext context2, final HttpRequestPacket requestPacket2) throws IOException {
        if (this.asyncTransferInitiated) {
            throw new IllegalStateException("Async transfer has already been initiated.");
        } else if (this.feeder == null) {
            throw new IllegalStateException("No feeder available to perform the transfer.");
        } else if (!$assertionsDisabled && context2 == null) {
            throw new AssertionError();
        } else if ($assertionsDisabled || requestPacket2 != null) {
            this.requestPacket = requestPacket2;
            this.contentBuilder = HttpContent.builder(requestPacket2);
            final Connection c = context2.getConnection();
            this.origMaxPendingBytes = c.getMaxAsyncWriteQueueSize();
            if (this.configuredMaxPendingBytes != -2) {
                c.setMaxAsyncWriteQueueSize(this.configuredMaxPendingBytes);
            }
            this.context = context2;
            this.asyncTransferInitiated = true;
            Runnable r = new Runnable() {
                public void run() {
                    try {
                        if (!requestPacket2.isSecure() || SSLUtils.getSSLEngine(context2.getConnection()) != null) {
                            FeedableBodyGenerator.this.feeder.flush();
                        } else {
                            FeedableBodyGenerator.this.flushOnSSLHandshakeComplete();
                        }
                    } catch (IOException ioe) {
                        GrizzlyAsyncHttpProvider.getHttpTransactionContext(c).abort(ioe);
                    }
                }
            };
            if (isServiceThread()) {
                c.getTransport().getWorkerThreadPool().execute(r);
            } else {
                r.run();
            }
        } else {
            throw new AssertionError();
        }
    }

    private boolean isServiceThread() {
        return Threads.isService();
    }

    /* access modifiers changed from: private */
    public void flushOnSSLHandshakeComplete() throws IOException {
        FilterChain filterChain = this.context.getFilterChain();
        int idx = filterChain.indexOfType(SSLFilter.class);
        if ($assertionsDisabled || idx != -1) {
            final SSLFilter filter = (SSLFilter) filterChain.get(idx);
            final Connection c = this.context.getConnection();
            filter.addHandshakeListener(new HandshakeListener() {
                public void onStart(Connection connection) {
                }

                public void onComplete(Connection connection) {
                    if (c.equals(connection)) {
                        filter.removeHandshakeListener(this);
                        try {
                            FeedableBodyGenerator.this.feeder.flush();
                        } catch (IOException ioe) {
                            GrizzlyAsyncHttpProvider.getHttpTransactionContext(c).abort(ioe);
                        }
                    }
                }
            });
            filter.handshake(this.context.getConnection(), null);
            return;
        }
        throw new AssertionError();
    }
}