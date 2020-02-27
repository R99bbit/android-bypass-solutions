package org.jboss.netty.handler.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SocketChannel;
import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import java.util.regex.Pattern;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelDownstreamHandler;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelState;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.DefaultChannelFuture;
import org.jboss.netty.channel.DownstreamMessageEvent;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.handler.codec.frame.FrameDecoder;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;
import org.jboss.netty.util.Timeout;
import org.jboss.netty.util.Timer;
import org.jboss.netty.util.TimerTask;
import org.jboss.netty.util.internal.DetectionUtil;
import org.jboss.netty.util.internal.NonReentrantLock;

public class SslHandler extends FrameDecoder implements ChannelDownstreamHandler {
    static final /* synthetic */ boolean $assertionsDisabled = (!SslHandler.class.desiredAssertionStatus());
    private static final AtomicIntegerFieldUpdater<SslHandler> CLOSED_OUTBOUND_AND_CHANNEL_UPDATER = AtomicIntegerFieldUpdater.newUpdater(SslHandler.class, "closedOutboundAndChannel");
    private static final ByteBuffer EMPTY_BUFFER = ByteBuffer.allocate(0);
    private static final Pattern IGNORABLE_CLASS_IN_STACK = Pattern.compile("^.*(?:Socket|Datagram|Sctp|Udt)Channel.*$");
    private static final Pattern IGNORABLE_ERROR_MESSAGE = Pattern.compile("^.*(?:connection.*(?:reset|closed|abort|broken)|broken.*pipe).*$", 2);
    private static final AtomicIntegerFieldUpdater<SslHandler> SENT_CLOSE_NOTIFY_UPDATER = AtomicIntegerFieldUpdater.newUpdater(SslHandler.class, "sentCloseNotify");
    private static final AtomicIntegerFieldUpdater<SslHandler> SENT_FIRST_MESSAGE_UPDATER = AtomicIntegerFieldUpdater.newUpdater(SslHandler.class, "sentFirstMessage");
    private static SslBufferPool defaultBufferPool;
    private static final InternalLogger logger = InternalLoggerFactory.getInstance(SslHandler.class);
    private final SslBufferPool bufferPool;
    /* access modifiers changed from: private */
    public boolean closeOnSSLException;
    private volatile int closedOutboundAndChannel;
    /* access modifiers changed from: private */
    public volatile ChannelHandlerContext ctx;
    private final Executor delegatedTaskExecutor;
    private volatile boolean enableRenegotiation;
    private final SSLEngine engine;
    /* access modifiers changed from: private */
    public volatile ChannelFuture handshakeFuture;
    final Object handshakeLock;
    private Timeout handshakeTimeout;
    /* access modifiers changed from: private */
    public final long handshakeTimeoutInMillis;
    private volatile boolean handshaken;
    private boolean handshaking;
    int ignoreClosedChannelException;
    final Object ignoreClosedChannelExceptionLock;
    private volatile boolean issueHandshake;
    private int packetLength;
    /* access modifiers changed from: private */
    public final Queue<MessageEvent> pendingEncryptedWrites;
    private final NonReentrantLock pendingEncryptedWritesLock;
    /* access modifiers changed from: private */
    public final Queue<PendingWrite> pendingUnencryptedWrites;
    /* access modifiers changed from: private */
    public final NonReentrantLock pendingUnencryptedWritesLock;
    private volatile int sentCloseNotify;
    private volatile int sentFirstMessage;
    private final SSLEngineInboundCloseFuture sslEngineCloseFuture;
    private final boolean startTls;
    private final Timer timer;

    /* renamed from: org.jboss.netty.handler.ssl.SslHandler$8 reason: invalid class name */
    static /* synthetic */ class AnonymousClass8 {
        static final /* synthetic */ int[] $SwitchMap$javax$net$ssl$SSLEngineResult$HandshakeStatus = new int[HandshakeStatus.values().length];
        static final /* synthetic */ int[] $SwitchMap$javax$net$ssl$SSLEngineResult$Status = new int[Status.values().length];

        static {
            try {
                $SwitchMap$javax$net$ssl$SSLEngineResult$Status[Status.CLOSED.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$javax$net$ssl$SSLEngineResult$Status[Status.BUFFER_OVERFLOW.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$javax$net$ssl$SSLEngineResult$HandshakeStatus[HandshakeStatus.NEED_WRAP.ordinal()] = 1;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$javax$net$ssl$SSLEngineResult$HandshakeStatus[HandshakeStatus.NEED_UNWRAP.ordinal()] = 2;
            } catch (NoSuchFieldError e4) {
            }
            try {
                $SwitchMap$javax$net$ssl$SSLEngineResult$HandshakeStatus[HandshakeStatus.NEED_TASK.ordinal()] = 3;
            } catch (NoSuchFieldError e5) {
            }
            try {
                $SwitchMap$javax$net$ssl$SSLEngineResult$HandshakeStatus[HandshakeStatus.FINISHED.ordinal()] = 4;
            } catch (NoSuchFieldError e6) {
            }
            try {
                $SwitchMap$javax$net$ssl$SSLEngineResult$HandshakeStatus[HandshakeStatus.NOT_HANDSHAKING.ordinal()] = 5;
            } catch (NoSuchFieldError e7) {
            }
            $SwitchMap$org$jboss$netty$channel$ChannelState = new int[ChannelState.values().length];
            try {
                $SwitchMap$org$jboss$netty$channel$ChannelState[ChannelState.OPEN.ordinal()] = 1;
            } catch (NoSuchFieldError e8) {
            }
            try {
                $SwitchMap$org$jboss$netty$channel$ChannelState[ChannelState.CONNECTED.ordinal()] = 2;
            } catch (NoSuchFieldError e9) {
            }
            try {
                $SwitchMap$org$jboss$netty$channel$ChannelState[ChannelState.BOUND.ordinal()] = 3;
            } catch (NoSuchFieldError e10) {
            }
        }
    }

    private static final class ClosingChannelFutureListener implements ChannelFutureListener {
        private final ChannelHandlerContext context;
        private final ChannelStateEvent e;

        ClosingChannelFutureListener(ChannelHandlerContext context2, ChannelStateEvent e2) {
            this.context = context2;
            this.e = e2;
        }

        public void operationComplete(ChannelFuture closeNotifyFuture) throws Exception {
            if (!(closeNotifyFuture.getCause() instanceof ClosedChannelException)) {
                Channels.close(this.context, this.e.getFuture());
            } else {
                this.e.getFuture().setSuccess();
            }
        }
    }

    private static final class PendingWrite {
        final ChannelFuture future;
        final ByteBuffer outAppBuf;

        PendingWrite(ChannelFuture future2, ByteBuffer outAppBuf2) {
            this.future = future2;
            this.outAppBuf = outAppBuf2;
        }
    }

    private final class SSLEngineInboundCloseFuture extends DefaultChannelFuture {
        public SSLEngineInboundCloseFuture() {
            super(null, true);
        }

        /* access modifiers changed from: 0000 */
        public void setClosed() {
            super.setSuccess();
        }

        public Channel getChannel() {
            if (SslHandler.this.ctx == null) {
                return null;
            }
            return SslHandler.this.ctx.getChannel();
        }

        public boolean setSuccess() {
            return false;
        }

        public boolean setFailure(Throwable cause) {
            return false;
        }
    }

    public static synchronized SslBufferPool getDefaultBufferPool() {
        SslBufferPool sslBufferPool;
        synchronized (SslHandler.class) {
            if (defaultBufferPool == null) {
                defaultBufferPool = new SslBufferPool();
            }
            sslBufferPool = defaultBufferPool;
        }
        return sslBufferPool;
    }

    public SslHandler(SSLEngine engine2) {
        this(engine2, getDefaultBufferPool(), (Executor) ImmediateExecutor.INSTANCE);
    }

    public SslHandler(SSLEngine engine2, SslBufferPool bufferPool2) {
        this(engine2, bufferPool2, (Executor) ImmediateExecutor.INSTANCE);
    }

    public SslHandler(SSLEngine engine2, boolean startTls2) {
        this(engine2, getDefaultBufferPool(), startTls2);
    }

    public SslHandler(SSLEngine engine2, SslBufferPool bufferPool2, boolean startTls2) {
        this(engine2, bufferPool2, startTls2, ImmediateExecutor.INSTANCE);
    }

    public SslHandler(SSLEngine engine2, Executor delegatedTaskExecutor2) {
        this(engine2, getDefaultBufferPool(), delegatedTaskExecutor2);
    }

    public SslHandler(SSLEngine engine2, SslBufferPool bufferPool2, Executor delegatedTaskExecutor2) {
        this(engine2, bufferPool2, false, delegatedTaskExecutor2);
    }

    public SslHandler(SSLEngine engine2, boolean startTls2, Executor delegatedTaskExecutor2) {
        this(engine2, getDefaultBufferPool(), startTls2, delegatedTaskExecutor2);
    }

    public SslHandler(SSLEngine engine2, SslBufferPool bufferPool2, boolean startTls2, Executor delegatedTaskExecutor2) {
        this(engine2, bufferPool2, startTls2, delegatedTaskExecutor2, null, 0);
    }

    public SslHandler(SSLEngine engine2, SslBufferPool bufferPool2, boolean startTls2, Executor delegatedTaskExecutor2, Timer timer2, long handshakeTimeoutInMillis2) {
        this.enableRenegotiation = true;
        this.handshakeLock = new Object();
        this.ignoreClosedChannelExceptionLock = new Object();
        this.pendingUnencryptedWrites = new LinkedList();
        this.pendingUnencryptedWritesLock = new NonReentrantLock();
        this.pendingEncryptedWrites = new ConcurrentLinkedQueue();
        this.pendingEncryptedWritesLock = new NonReentrantLock();
        this.sslEngineCloseFuture = new SSLEngineInboundCloseFuture();
        if (engine2 == null) {
            throw new NullPointerException("engine");
        } else if (bufferPool2 == null) {
            throw new NullPointerException("bufferPool");
        } else if (delegatedTaskExecutor2 == null) {
            throw new NullPointerException("delegatedTaskExecutor");
        } else if (timer2 != null || handshakeTimeoutInMillis2 <= 0) {
            this.engine = engine2;
            this.bufferPool = bufferPool2;
            this.delegatedTaskExecutor = delegatedTaskExecutor2;
            this.startTls = startTls2;
            this.timer = timer2;
            this.handshakeTimeoutInMillis = handshakeTimeoutInMillis2;
        } else {
            throw new IllegalArgumentException("No Timer was given but a handshakeTimeoutInMillis, need both or none");
        }
    }

    public SSLEngine getEngine() {
        return this.engine;
    }

    public ChannelFuture handshake() {
        ChannelFuture handshakeFuture2;
        synchronized (this.handshakeLock) {
            if (!this.handshaken || isEnableRenegotiation()) {
                final ChannelHandlerContext ctx2 = this.ctx;
                final Channel channel = ctx2.getChannel();
                Exception exception = null;
                if (this.handshaking) {
                    handshakeFuture2 = this.handshakeFuture;
                } else {
                    this.handshaking = true;
                    try {
                        this.engine.beginHandshake();
                        runDelegatedTasks();
                        handshakeFuture2 = Channels.future(channel);
                        this.handshakeFuture = handshakeFuture2;
                        if (this.handshakeTimeoutInMillis > 0) {
                            this.handshakeTimeout = this.timer.newTimeout(new TimerTask() {
                                public void run(Timeout timeout) throws Exception {
                                    ChannelFuture future = SslHandler.this.handshakeFuture;
                                    if (future == null || !future.isDone()) {
                                        SslHandler.this.setHandshakeFailure(channel, new SSLException("Handshake did not complete within " + SslHandler.this.handshakeTimeoutInMillis + "ms"));
                                    }
                                }
                            }, this.handshakeTimeoutInMillis, TimeUnit.MILLISECONDS);
                        }
                    } catch (Exception e) {
                        handshakeFuture2 = Channels.failedFuture(channel, e);
                        this.handshakeFuture = handshakeFuture2;
                        exception = e;
                    }
                    if (exception == null) {
                        final ChannelFuture hsFuture = handshakeFuture2;
                        try {
                            wrapNonAppData(ctx2, channel).addListener(new ChannelFutureListener() {
                                public void operationComplete(ChannelFuture future) throws Exception {
                                    if (!future.isSuccess()) {
                                        Throwable cause = future.getCause();
                                        hsFuture.setFailure(cause);
                                        Channels.fireExceptionCaught(ctx2, cause);
                                        if (SslHandler.this.closeOnSSLException) {
                                            Channels.close(ctx2, Channels.future(channel));
                                        }
                                    }
                                }
                            });
                        } catch (SSLException e2) {
                            handshakeFuture2.setFailure(e2);
                            Channels.fireExceptionCaught(ctx2, (Throwable) e2);
                            if (this.closeOnSSLException) {
                                Channels.close(ctx2, Channels.future(channel));
                            }
                        }
                    } else {
                        Channels.fireExceptionCaught(ctx2, (Throwable) exception);
                        if (this.closeOnSSLException) {
                            Channels.close(ctx2, Channels.future(channel));
                        }
                    }
                }
            } else {
                throw new IllegalStateException("renegotiation disabled");
            }
        }
        return handshakeFuture2;
    }

    @Deprecated
    public ChannelFuture handshake(Channel channel) {
        return handshake();
    }

    public ChannelFuture close() {
        ChannelHandlerContext ctx2 = this.ctx;
        Channel channel = ctx2.getChannel();
        try {
            this.engine.closeOutbound();
            return wrapNonAppData(ctx2, channel);
        } catch (SSLException e) {
            Channels.fireExceptionCaught(ctx2, (Throwable) e);
            if (this.closeOnSSLException) {
                Channels.close(ctx2, Channels.future(channel));
            }
            return Channels.failedFuture(channel, e);
        }
    }

    @Deprecated
    public ChannelFuture close(Channel channel) {
        return close();
    }

    public boolean isEnableRenegotiation() {
        return this.enableRenegotiation;
    }

    public void setEnableRenegotiation(boolean enableRenegotiation2) {
        this.enableRenegotiation = enableRenegotiation2;
    }

    public void setIssueHandshake(boolean issueHandshake2) {
        this.issueHandshake = issueHandshake2;
    }

    public boolean isIssueHandshake() {
        return this.issueHandshake;
    }

    public ChannelFuture getSSLEngineInboundCloseFuture() {
        return this.sslEngineCloseFuture;
    }

    public long getHandshakeTimeout() {
        return this.handshakeTimeoutInMillis;
    }

    public void setCloseOnSSLException(boolean closeOnSslException) {
        if (this.ctx != null) {
            throw new IllegalStateException("Can only get changed before attached to ChannelPipeline");
        }
        this.closeOnSSLException = closeOnSslException;
    }

    public boolean getCloseOnSSLException() {
        return this.closeOnSSLException;
    }

    /* JADX INFO: finally extract failed */
    public void handleDownstream(ChannelHandlerContext context, ChannelEvent evt) throws Exception {
        PendingWrite pendingWrite;
        if (evt instanceof ChannelStateEvent) {
            ChannelStateEvent e = (ChannelStateEvent) evt;
            switch (e.getState()) {
                case OPEN:
                case CONNECTED:
                case BOUND:
                    if (Boolean.FALSE.equals(e.getValue()) || e.getValue() == null) {
                        closeOutboundAndChannel(context, e);
                        return;
                    }
            }
        }
        if (!(evt instanceof MessageEvent)) {
            context.sendDownstream(evt);
            return;
        }
        MessageEvent e2 = (MessageEvent) evt;
        if (!(e2.getMessage() instanceof ChannelBuffer)) {
            context.sendDownstream(evt);
        } else if (!this.startTls || !SENT_FIRST_MESSAGE_UPDATER.compareAndSet(this, 0, 1)) {
            ChannelBuffer msg = (ChannelBuffer) e2.getMessage();
            if (msg.readable()) {
                pendingWrite = new PendingWrite(evt.getFuture(), msg.toByteBuffer(msg.readerIndex(), msg.readableBytes()));
            } else {
                pendingWrite = new PendingWrite(evt.getFuture(), null);
            }
            this.pendingUnencryptedWritesLock.lock();
            try {
                this.pendingUnencryptedWrites.add(pendingWrite);
                this.pendingUnencryptedWritesLock.unlock();
                wrap(context, evt.getChannel());
            } catch (Throwable th) {
                this.pendingUnencryptedWritesLock.unlock();
                throw th;
            }
        } else {
            context.sendDownstream(evt);
        }
    }

    private void cancelHandshakeTimeout() {
        if (this.handshakeTimeout != null) {
            this.handshakeTimeout.cancel();
        }
    }

    public void channelDisconnected(ChannelHandlerContext ctx2, ChannelStateEvent e) throws Exception {
        int i;
        boolean z;
        synchronized (this.handshakeLock) {
            if (this.handshaking) {
                cancelHandshakeTimeout();
                this.handshakeFuture.setFailure(new ClosedChannelException());
            }
        }
        try {
            super.channelDisconnected(ctx2, e);
            if (i == 0 && z) {
                try {
                    this.engine.closeInbound();
                } catch (SSLException ex) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Failed to clean up SSLEngine.", ex);
                    }
                }
            }
        } finally {
            unwrap(ctx2, e.getChannel(), ChannelBuffers.EMPTY_BUFFER, 0, 0);
            this.engine.closeOutbound();
            if (this.sentCloseNotify == 0 && this.handshaken) {
                try {
                    this.engine.closeInbound();
                } catch (SSLException ex2) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Failed to clean up SSLEngine.", ex2);
                    }
                }
            }
        }
    }

    /* JADX WARNING: Code restructure failed: missing block: B:24:?, code lost:
        return;
     */
    public void exceptionCaught(ChannelHandlerContext ctx2, ExceptionEvent e) throws Exception {
        Throwable cause = e.getCause();
        if (cause instanceof IOException) {
            if (cause instanceof ClosedChannelException) {
                synchronized (this.ignoreClosedChannelExceptionLock) {
                    if (this.ignoreClosedChannelException > 0) {
                        this.ignoreClosedChannelException--;
                        if (logger.isDebugEnabled()) {
                            logger.debug("Swallowing an exception raised while writing non-app data", cause);
                        }
                    }
                }
            } else if (ignoreException(cause)) {
                return;
            }
        }
        ctx2.sendUpstream(e);
    }

    private boolean ignoreException(Throwable t) {
        StackTraceElement[] arr$;
        if (!(t instanceof SSLException) && (t instanceof IOException) && this.engine.isOutboundDone()) {
            if (IGNORABLE_ERROR_MESSAGE.matcher(String.valueOf(t.getMessage()).toLowerCase()).matches()) {
                return true;
            }
            for (StackTraceElement element : t.getStackTrace()) {
                String classname = element.getClassName();
                String methodname = element.getMethodName();
                if (!classname.startsWith("org.jboss.netty.") && "read".equals(methodname)) {
                    if (IGNORABLE_CLASS_IN_STACK.matcher(classname).matches()) {
                        return true;
                    }
                    try {
                        Class<?> loadClass = getClass().getClassLoader().loadClass(classname);
                        if (SocketChannel.class.isAssignableFrom(loadClass) || DatagramChannel.class.isAssignableFrom(loadClass)) {
                            return true;
                        }
                        if (DetectionUtil.javaVersion() >= 7 && "com.sun.nio.sctp.SctpChannel".equals(loadClass.getSuperclass().getName())) {
                            return true;
                        }
                    } catch (ClassNotFoundException e) {
                    }
                }
            }
        }
        return false;
    }

    public static boolean isEncrypted(ChannelBuffer buffer) {
        return getEncryptedPacketLength(buffer, buffer.readerIndex()) != -1;
    }

    private static int getEncryptedPacketLength(ChannelBuffer buffer, int offset) {
        boolean tls;
        int packetLength2;
        int headerLength;
        int packetLength3 = 0;
        switch (buffer.getUnsignedByte(offset)) {
            case 20:
            case 21:
            case 22:
            case 23:
                tls = true;
                break;
            default:
                tls = false;
                break;
        }
        if (tls) {
            if (buffer.getUnsignedByte(offset + 1) == 3) {
                packetLength3 = (getShort(buffer, offset + 3) & 65535) + 5;
                if (packetLength3 <= 5) {
                    tls = false;
                }
            } else {
                tls = false;
            }
        }
        if (!tls) {
            boolean sslv2 = true;
            if ((buffer.getUnsignedByte(offset) & 128) != 0) {
                headerLength = 2;
            } else {
                headerLength = 3;
            }
            int majorVersion = buffer.getUnsignedByte(offset + headerLength + 1);
            if (majorVersion == 2 || majorVersion == 3) {
                if (headerLength == 2) {
                    packetLength2 = (getShort(buffer, offset) & Short.MAX_VALUE) + 2;
                } else {
                    packetLength2 = (getShort(buffer, offset) & 16383) + 3;
                }
                if (packetLength2 <= headerLength) {
                    sslv2 = false;
                }
            } else {
                sslv2 = false;
            }
            if (!sslv2) {
                return -1;
            }
        }
        return packetLength2;
    }

    /* access modifiers changed from: protected */
    public Object decode(ChannelHandlerContext ctx2, Channel channel, ChannelBuffer in) throws Exception {
        int startOffset = in.readerIndex();
        int endOffset = in.writerIndex();
        int offset = startOffset;
        if (this.packetLength > 0) {
            if (endOffset - startOffset < this.packetLength) {
                return null;
            }
            offset += this.packetLength;
            this.packetLength = 0;
        }
        boolean nonSslRecord = false;
        while (true) {
            int readableBytes = endOffset - offset;
            if (readableBytes < 5) {
                break;
            }
            int packetLength2 = getEncryptedPacketLength(in, offset);
            if (packetLength2 == -1) {
                nonSslRecord = true;
                break;
            } else if (!$assertionsDisabled && packetLength2 <= 0) {
                throw new AssertionError();
            } else if (packetLength2 > readableBytes) {
                this.packetLength = packetLength2;
                break;
            } else {
                offset += packetLength2;
            }
        }
        int length = offset - startOffset;
        ChannelBuffer unwrapped = null;
        if (length > 0) {
            unwrapped = unwrap(ctx2, channel, in, startOffset, length);
        }
        if (!nonSslRecord) {
            return unwrapped;
        }
        NotSslRecordException e = new NotSslRecordException("not an SSL/TLS record: " + ChannelBuffers.hexDump(in));
        in.skipBytes(in.readableBytes());
        if (this.closeOnSSLException) {
            Channels.fireExceptionCaught(ctx2, (Throwable) e);
            Channels.close(ctx2, Channels.future(channel));
            return null;
        }
        throw e;
    }

    private static short getShort(ChannelBuffer buf, int offset) {
        return (short) ((buf.getByte(offset) << 8) | (buf.getByte(offset + 1) & 255));
    }

    /* JADX INFO: finally extract failed */
    /* JADX WARNING: Code restructure failed: missing block: B:105:?, code lost:
        r22.pendingUnencryptedWritesLock.unlock();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:111:?, code lost:
        r22.pendingUnencryptedWritesLock.unlock();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:123:?, code lost:
        r22.pendingUnencryptedWritesLock.unlock();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:94:?, code lost:
        r22.pendingUnencryptedWritesLock.unlock();
     */
    private void wrap(ChannelHandlerContext context, Channel channel) throws SSLException {
        ByteBuffer outAppBuf;
        ChannelFuture future;
        ByteBuffer outNetBuf = this.bufferPool.acquireBuffer();
        boolean success = true;
        boolean offered = false;
        boolean needsUnwrap = false;
        PendingWrite pendingWrite = null;
        while (true) {
            try {
                this.pendingUnencryptedWritesLock.lock();
                try {
                    pendingWrite = this.pendingUnencryptedWrites.peek();
                    if (pendingWrite == null) {
                        this.pendingUnencryptedWritesLock.unlock();
                    } else {
                        outAppBuf = pendingWrite.outAppBuf;
                        if (outAppBuf == null) {
                            this.pendingUnencryptedWrites.remove();
                            offerEncryptedWriteRequest(new DownstreamMessageEvent(channel, pendingWrite.future, ChannelBuffers.EMPTY_BUFFER, channel.getRemoteAddress()));
                            offered = true;
                        } else {
                            synchronized (this.handshakeLock) {
                                SSLEngineResult result = this.engine.wrap(outAppBuf, outNetBuf);
                                if (!outAppBuf.hasRemaining()) {
                                    this.pendingUnencryptedWrites.remove();
                                }
                                if (result.bytesProduced() > 0) {
                                    outNetBuf.flip();
                                    ChannelBuffer msg = this.ctx.getChannel().getConfig().getBufferFactory().getBuffer(outNetBuf.remaining());
                                    msg.writeBytes(outNetBuf);
                                    outNetBuf.clear();
                                    if (pendingWrite.outAppBuf.hasRemaining()) {
                                        future = Channels.succeededFuture(channel);
                                    } else {
                                        future = pendingWrite.future;
                                    }
                                    offerEncryptedWriteRequest(new DownstreamMessageEvent(channel, future, msg, channel.getRemoteAddress()));
                                    offered = true;
                                } else if (result.getStatus() == Status.CLOSED) {
                                    success = false;
                                } else {
                                    HandshakeStatus handshakeStatus = result.getHandshakeStatus();
                                    handleRenegotiation(handshakeStatus);
                                    switch (AnonymousClass8.$SwitchMap$javax$net$ssl$SSLEngineResult$HandshakeStatus[handshakeStatus.ordinal()]) {
                                        case 1:
                                            if (!outAppBuf.hasRemaining()) {
                                                break;
                                            }
                                            break;
                                        case 2:
                                            needsUnwrap = true;
                                            break;
                                        case 3:
                                            runDelegatedTasks();
                                            break;
                                        case 4:
                                        case 5:
                                            if (handshakeStatus == HandshakeStatus.FINISHED) {
                                                setHandshakeSuccess(channel);
                                            }
                                            if (result.getStatus() == Status.CLOSED) {
                                                success = false;
                                                break;
                                            }
                                            break;
                                        default:
                                            throw new IllegalStateException("Unknown handshake status: " + handshakeStatus);
                                    }
                                }
                            }
                        }
                        this.pendingUnencryptedWritesLock.unlock();
                    }
                } catch (Throwable th) {
                    this.pendingUnencryptedWritesLock.unlock();
                    throw th;
                }
            } catch (SSLException e) {
                setHandshakeFailure(channel, e);
                throw e;
            } catch (Throwable th2) {
                this.bufferPool.releaseBuffer(outNetBuf);
                if (offered) {
                    flushPendingEncryptedWrites(context);
                }
                if (0 == 0) {
                    IllegalStateException cause = new IllegalStateException("SSLEngine already closed");
                    if (pendingWrite != null) {
                        pendingWrite.future.setFailure(cause);
                    }
                    while (true) {
                        this.pendingUnencryptedWritesLock.lock();
                        try {
                            PendingWrite pendingWrite2 = this.pendingUnencryptedWrites.poll();
                            if (pendingWrite2 == null) {
                                this.pendingUnencryptedWritesLock.unlock();
                            } else {
                                this.pendingUnencryptedWritesLock.unlock();
                                pendingWrite2.future.setFailure(cause);
                            }
                        } catch (Throwable th3) {
                            this.pendingUnencryptedWritesLock.unlock();
                            throw th3;
                        }
                    }
                }
                throw th2;
            }
        }
        this.bufferPool.releaseBuffer(outNetBuf);
        if (offered) {
            flushPendingEncryptedWrites(context);
        }
        if (!success) {
            IllegalStateException cause2 = new IllegalStateException("SSLEngine already closed");
            if (pendingWrite != null) {
                pendingWrite.future.setFailure(cause2);
            }
            while (true) {
                this.pendingUnencryptedWritesLock.lock();
                try {
                    PendingWrite pendingWrite3 = this.pendingUnencryptedWrites.poll();
                    if (pendingWrite3 == null) {
                        this.pendingUnencryptedWritesLock.unlock();
                    } else {
                        this.pendingUnencryptedWritesLock.unlock();
                        pendingWrite3.future.setFailure(cause2);
                    }
                } catch (Throwable th4) {
                    this.pendingUnencryptedWritesLock.unlock();
                    throw th4;
                }
            }
        }
        if (needsUnwrap) {
            unwrap(context, channel, ChannelBuffers.EMPTY_BUFFER, 0, 0);
        }
    }

    private void offerEncryptedWriteRequest(MessageEvent encryptedWrite) {
        boolean locked = this.pendingEncryptedWritesLock.tryLock();
        try {
            this.pendingEncryptedWrites.add(encryptedWrite);
        } finally {
            if (locked) {
                this.pendingEncryptedWritesLock.unlock();
            }
        }
    }

    private void flushPendingEncryptedWrites(ChannelHandlerContext ctx2) {
        while (!this.pendingEncryptedWrites.isEmpty() && this.pendingEncryptedWritesLock.tryLock()) {
            while (true) {
                try {
                    MessageEvent e = this.pendingEncryptedWrites.poll();
                    if (e == null) {
                        break;
                    }
                    ctx2.sendDownstream(e);
                } finally {
                    this.pendingEncryptedWritesLock.unlock();
                }
            }
        }
    }

    private ChannelFuture wrapNonAppData(ChannelHandlerContext ctx2, Channel channel) throws SSLException {
        SSLEngineResult result;
        ChannelFuture future = null;
        ByteBuffer outNetBuf = this.bufferPool.acquireBuffer();
        do {
            try {
                synchronized (this.handshakeLock) {
                    result = this.engine.wrap(EMPTY_BUFFER, outNetBuf);
                }
                if (result.bytesProduced() > 0) {
                    outNetBuf.flip();
                    ChannelBuffer msg = ctx2.getChannel().getConfig().getBufferFactory().getBuffer(outNetBuf.remaining());
                    msg.writeBytes(outNetBuf);
                    outNetBuf.clear();
                    future = Channels.future(channel);
                    future.addListener(new ChannelFutureListener() {
                        public void operationComplete(ChannelFuture future) throws Exception {
                            if (future.getCause() instanceof ClosedChannelException) {
                                synchronized (SslHandler.this.ignoreClosedChannelExceptionLock) {
                                    SslHandler.this.ignoreClosedChannelException++;
                                }
                            }
                        }
                    });
                    Channels.write(ctx2, future, (Object) msg);
                }
                HandshakeStatus handshakeStatus = result.getHandshakeStatus();
                handleRenegotiation(handshakeStatus);
                switch (AnonymousClass8.$SwitchMap$javax$net$ssl$SSLEngineResult$HandshakeStatus[handshakeStatus.ordinal()]) {
                    case 1:
                    case 5:
                        break;
                    case 2:
                        if (!Thread.holdsLock(this.handshakeLock)) {
                            unwrap(ctx2, channel, ChannelBuffers.EMPTY_BUFFER, 0, 0);
                            break;
                        }
                        break;
                    case 3:
                        runDelegatedTasks();
                        break;
                    case 4:
                        setHandshakeSuccess(channel);
                        runDelegatedTasks();
                        break;
                    default:
                        throw new IllegalStateException("Unexpected handshake status: " + handshakeStatus);
                }
            } catch (SSLException e) {
                setHandshakeFailure(channel, e);
                throw e;
            } catch (Throwable th) {
                this.bufferPool.releaseBuffer(outNetBuf);
                throw th;
            }
        } while (result.bytesProduced() != 0);
        this.bufferPool.releaseBuffer(outNetBuf);
        if (future == null) {
            return Channels.succeededFuture(channel);
        }
        return future;
    }

    /* JADX WARNING: Code restructure failed: missing block: B:101:0x0014, code lost:
        continue;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:107:?, code lost:
        return r3;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:108:?, code lost:
        return null;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:72:0x0113, code lost:
        if (r8 == false) goto L_0x0128;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:75:0x011b, code lost:
        if (java.lang.Thread.holdsLock(r15.handshakeLock) != false) goto L_0x0128;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:77:0x0123, code lost:
        if (r15.pendingEncryptedWritesLock.isHeldByCurrentThread() != false) goto L_0x0128;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:78:0x0125, code lost:
        wrap(r16, r17);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:79:0x0128, code lost:
        r15.bufferPool.releaseBuffer(r9);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:80:0x012d, code lost:
        if (r3 == null) goto L_0x0146;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:82:0x0133, code lost:
        if (r3.readable() == false) goto L_0x0146;
     */
    private ChannelBuffer unwrap(ChannelHandlerContext ctx2, Channel channel, ChannelBuffer buffer, int offset, int length) throws SSLException {
        SSLEngineResult result;
        ByteBuffer inNetBuf = buffer.toByteBuffer(offset, length);
        ByteBuffer outAppBuf = this.bufferPool.acquireBuffer();
        int bufferStartOffset = buffer.readerIndex();
        int inNetBufStartOffset = inNetBuf.position();
        ChannelBuffer frame = null;
        boolean needsWrap = false;
        while (true) {
            boolean needsHandshake = false;
            try {
                synchronized (this.handshakeLock) {
                    if (!this.handshaken && !this.handshaking && !this.engine.getUseClientMode() && !this.engine.isInboundDone() && !this.engine.isOutboundDone()) {
                        needsHandshake = true;
                    }
                }
                if (needsHandshake) {
                    handshake();
                }
                synchronized (this.handshakeLock) {
                    while (true) {
                        result = this.engine.unwrap(inNetBuf, outAppBuf);
                        switch (AnonymousClass8.$SwitchMap$javax$net$ssl$SSLEngineResult$Status[result.getStatus().ordinal()]) {
                            case 1:
                                this.sslEngineCloseFuture.setClosed();
                                break;
                            case 2:
                                outAppBuf.flip();
                                buffer.readerIndex((inNetBuf.position() + bufferStartOffset) - inNetBufStartOffset);
                                if (outAppBuf.hasRemaining()) {
                                    if (frame == null) {
                                        frame = ctx2.getChannel().getConfig().getBufferFactory().getBuffer(length);
                                    }
                                    frame.writeBytes(outAppBuf);
                                }
                                outAppBuf.clear();
                        }
                    }
                    outAppBuf.flip();
                    buffer.readerIndex((inNetBuf.position() + bufferStartOffset) - inNetBufStartOffset);
                    if (outAppBuf.hasRemaining()) {
                        if (frame == null) {
                            frame = ctx2.getChannel().getConfig().getBufferFactory().getBuffer(length);
                        }
                        frame.writeBytes(outAppBuf);
                    }
                    outAppBuf.clear();
                    HandshakeStatus handshakeStatus = result.getHandshakeStatus();
                    handleRenegotiation(handshakeStatus);
                    switch (AnonymousClass8.$SwitchMap$javax$net$ssl$SSLEngineResult$HandshakeStatus[handshakeStatus.ordinal()]) {
                        case 1:
                            wrapNonAppData(ctx2, channel);
                            break;
                        case 2:
                        case 5:
                            break;
                        case 3:
                            runDelegatedTasks();
                            break;
                        case 4:
                            setHandshakeSuccess(channel);
                            needsWrap = true;
                            break;
                        default:
                            throw new IllegalStateException("Unknown handshake status: " + handshakeStatus);
                    }
                    if (result.getStatus() == Status.BUFFER_UNDERFLOW || (result.bytesConsumed() == 0 && result.bytesProduced() == 0)) {
                    }
                }
            } catch (SSLException e) {
                try {
                    setHandshakeFailure(channel, e);
                    throw e;
                } catch (Throwable th) {
                    this.bufferPool.releaseBuffer(outAppBuf);
                    throw th;
                }
            } catch (Throwable th2) {
                outAppBuf.flip();
                buffer.readerIndex((inNetBuf.position() + bufferStartOffset) - inNetBufStartOffset);
                if (outAppBuf.hasRemaining()) {
                    if (frame == null) {
                        frame = ctx2.getChannel().getConfig().getBufferFactory().getBuffer(length);
                    }
                    frame.writeBytes(outAppBuf);
                }
                outAppBuf.clear();
                throw th2;
            }
        }
        while (true) {
        }
    }

    /* JADX WARNING: Code restructure failed: missing block: B:35:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:38:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:39:?, code lost:
        return;
     */
    private void handleRenegotiation(HandshakeStatus handshakeStatus) {
        boolean renegotiate;
        synchronized (this.handshakeLock) {
            if (handshakeStatus != HandshakeStatus.NOT_HANDSHAKING && handshakeStatus != HandshakeStatus.FINISHED) {
                if (this.handshaken) {
                    if (!this.handshaking) {
                        if (!this.engine.isInboundDone() && !this.engine.isOutboundDone()) {
                            if (isEnableRenegotiation()) {
                                renegotiate = true;
                            } else {
                                renegotiate = false;
                                this.handshaking = true;
                            }
                            if (renegotiate) {
                                handshake();
                            } else {
                                Channels.fireExceptionCaught(this.ctx, (Throwable) new SSLException("renegotiation attempted by peer; closing the connection"));
                                Channels.close(this.ctx, Channels.succeededFuture(this.ctx.getChannel()));
                            }
                        }
                    }
                }
            }
        }
    }

    private void runDelegatedTasks() {
        final Runnable task;
        while (true) {
            synchronized (this.handshakeLock) {
                task = this.engine.getDelegatedTask();
            }
            if (task != null) {
                this.delegatedTaskExecutor.execute(new Runnable() {
                    public void run() {
                        synchronized (SslHandler.this.handshakeLock) {
                            task.run();
                        }
                    }
                });
            } else {
                return;
            }
        }
    }

    private void setHandshakeSuccess(Channel channel) {
        synchronized (this.handshakeLock) {
            this.handshaking = false;
            this.handshaken = true;
            if (this.handshakeFuture == null) {
                this.handshakeFuture = Channels.future(channel);
            }
            cancelHandshakeTimeout();
        }
        this.handshakeFuture.setSuccess();
    }

    /* access modifiers changed from: private */
    /* JADX WARNING: Code restructure failed: missing block: B:14:0x0027, code lost:
        r4.handshakeFuture.setFailure(r6);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:15:0x002e, code lost:
        if (r4.closeOnSSLException == false) goto L_?;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:16:0x0030, code lost:
        org.jboss.netty.channel.Channels.close(r4.ctx, org.jboss.netty.channel.Channels.future(r5));
     */
    /* JADX WARNING: Code restructure failed: missing block: B:26:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:27:?, code lost:
        return;
     */
    /* JADX WARNING: No exception handlers in catch block: Catch:{  } */
    public void setHandshakeFailure(Channel channel, SSLException cause) {
        synchronized (this.handshakeLock) {
            if (this.handshaking) {
                this.handshaking = false;
                this.handshaken = false;
                if (this.handshakeFuture == null) {
                    this.handshakeFuture = Channels.future(channel);
                }
                cancelHandshakeTimeout();
                this.engine.closeOutbound();
                try {
                    this.engine.closeInbound();
                } catch (SSLException e) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("SSLEngine.closeInbound() raised an exception after a handshake failure.", e);
                    }
                }
            }
        }
    }

    private void closeOutboundAndChannel(final ChannelHandlerContext context, final ChannelStateEvent e) {
        if (!e.getChannel().isConnected()) {
            context.sendDownstream(e);
        } else if (!CLOSED_OUTBOUND_AND_CHANNEL_UPDATER.compareAndSet(this, 0, 1)) {
            e.getChannel().getCloseFuture().addListener(new ChannelFutureListener() {
                public void operationComplete(ChannelFuture future) throws Exception {
                    context.sendDownstream(e);
                }
            });
        } else {
            boolean passthrough = true;
            try {
                unwrap(context, e.getChannel(), ChannelBuffers.EMPTY_BUFFER, 0, 0);
            } catch (SSLException ex) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Failed to unwrap before sending a close_notify message", ex);
                }
            } catch (Throwable th) {
                if (1 != 0) {
                    context.sendDownstream(e);
                }
                throw th;
            }
            if (!this.engine.isOutboundDone() && SENT_CLOSE_NOTIFY_UPDATER.compareAndSet(this, 0, 1)) {
                this.engine.closeOutbound();
                try {
                    wrapNonAppData(context, e.getChannel()).addListener(new ClosingChannelFutureListener(context, e));
                    passthrough = false;
                } catch (SSLException ex2) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Failed to encode a close_notify message", ex2);
                    }
                }
            }
            if (passthrough) {
                context.sendDownstream(e);
            }
        }
    }

    public void beforeAdd(ChannelHandlerContext ctx2) throws Exception {
        super.beforeAdd(ctx2);
        this.ctx = ctx2;
    }

    public void afterRemove(ChannelHandlerContext ctx2) throws Exception {
        Throwable cause = null;
        while (true) {
            PendingWrite pw = this.pendingUnencryptedWrites.poll();
            if (pw == null) {
                break;
            }
            if (cause == null) {
                cause = new IOException("Unable to write data");
            }
            pw.future.setFailure(cause);
        }
        while (true) {
            MessageEvent ev = this.pendingEncryptedWrites.poll();
            if (ev == null) {
                break;
            }
            if (cause == null) {
                cause = new IOException("Unable to write data");
            }
            ev.getFuture().setFailure(cause);
        }
        if (cause != null) {
            Channels.fireExceptionCaughtLater(ctx2, cause);
        }
    }

    public void channelConnected(final ChannelHandlerContext ctx2, final ChannelStateEvent e) throws Exception {
        if (this.issueHandshake) {
            handshake().addListener(new ChannelFutureListener() {
                public void operationComplete(ChannelFuture future) throws Exception {
                    if (future.isSuccess()) {
                        ctx2.sendUpstream(e);
                    }
                }
            });
        } else {
            super.channelConnected(ctx2, e);
        }
    }

    public void channelClosed(final ChannelHandlerContext ctx2, ChannelStateEvent e) throws Exception {
        ctx2.getPipeline().execute(new Runnable() {
            public void run() {
                Throwable cause;
                Throwable cause2;
                if (SslHandler.this.pendingUnencryptedWritesLock.tryLock()) {
                    Throwable cause3 = null;
                    while (true) {
                        try {
                            cause = cause3;
                            PendingWrite pw = (PendingWrite) SslHandler.this.pendingUnencryptedWrites.poll();
                            if (pw == null) {
                                break;
                            }
                            if (cause == null) {
                                cause3 = new ClosedChannelException();
                            } else {
                                cause3 = cause;
                            }
                            try {
                                pw.future.setFailure(cause3);
                            } catch (Throwable th) {
                                th = th;
                                SslHandler.this.pendingUnencryptedWritesLock.unlock();
                                throw th;
                            }
                        } catch (Throwable th2) {
                            th = th2;
                            Throwable th3 = cause;
                            SslHandler.this.pendingUnencryptedWritesLock.unlock();
                            throw th;
                        }
                    }
                    while (true) {
                        MessageEvent ev = (MessageEvent) SslHandler.this.pendingEncryptedWrites.poll();
                        if (ev == null) {
                            break;
                        }
                        if (cause == null) {
                            cause2 = new ClosedChannelException();
                        } else {
                            cause2 = cause;
                        }
                        ev.getFuture().setFailure(cause2);
                        cause = cause2;
                    }
                    SslHandler.this.pendingUnencryptedWritesLock.unlock();
                    if (cause != null) {
                        Channels.fireExceptionCaught(ctx2, cause);
                    }
                }
            }
        });
        super.channelClosed(ctx2, e);
    }
}