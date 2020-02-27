package org.jboss.netty.channel.socket.nio;

import java.net.InetSocketAddress;
import java.nio.channels.SelectableChannel;
import java.nio.channels.WritableByteChannel;
import java.util.Collection;
import java.util.Iterator;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.AbstractChannel;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFactory;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelSink;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.util.internal.ThreadLocalBoolean;

abstract class AbstractNioChannel<C extends SelectableChannel & WritableByteChannel> extends AbstractChannel {
    final C channel;
    SendBuffer currentWriteBuffer;
    MessageEvent currentWriteEvent;
    final AtomicInteger highWaterMarkCounter = new AtomicInteger();
    boolean inWriteNowLoop;
    private volatile InetSocketAddress localAddress;
    volatile InetSocketAddress remoteAddress;
    final AbstractNioWorker worker;
    final Queue<MessageEvent> writeBufferQueue = new WriteRequestQueue();
    final AtomicInteger writeBufferSize = new AtomicInteger();
    final Object writeLock = new Object();
    boolean writeSuspended;
    final Runnable writeTask = new WriteTask();
    final AtomicBoolean writeTaskInTaskQueue = new AtomicBoolean();

    private final class WriteRequestQueue implements Queue<MessageEvent> {
        static final /* synthetic */ boolean $assertionsDisabled = (!AbstractNioChannel.class.desiredAssertionStatus());
        private final ThreadLocalBoolean notifying = new ThreadLocalBoolean();
        private final Queue<MessageEvent> queue = new ConcurrentLinkedQueue();

        public WriteRequestQueue() {
        }

        public MessageEvent remove() {
            return this.queue.remove();
        }

        public MessageEvent element() {
            return this.queue.element();
        }

        public MessageEvent peek() {
            return this.queue.peek();
        }

        public int size() {
            return this.queue.size();
        }

        public boolean isEmpty() {
            return this.queue.isEmpty();
        }

        public Iterator<MessageEvent> iterator() {
            return this.queue.iterator();
        }

        public Object[] toArray() {
            return this.queue.toArray();
        }

        public <T> T[] toArray(T[] a) {
            return this.queue.toArray(a);
        }

        public boolean containsAll(Collection<?> c) {
            return this.queue.containsAll(c);
        }

        public boolean addAll(Collection<? extends MessageEvent> c) {
            return this.queue.addAll(c);
        }

        public boolean removeAll(Collection<?> c) {
            return this.queue.removeAll(c);
        }

        public boolean retainAll(Collection<?> c) {
            return this.queue.retainAll(c);
        }

        public void clear() {
            this.queue.clear();
        }

        public boolean add(MessageEvent e) {
            return this.queue.add(e);
        }

        public boolean remove(Object o) {
            return this.queue.remove(o);
        }

        public boolean contains(Object o) {
            return this.queue.contains(o);
        }

        public boolean offer(MessageEvent e) {
            boolean success = this.queue.offer(e);
            if ($assertionsDisabled || success) {
                int messageSize = getMessageSize(e);
                int newWriteBufferSize = AbstractNioChannel.this.writeBufferSize.addAndGet(messageSize);
                int highWaterMark = AbstractNioChannel.this.getConfig().getWriteBufferHighWaterMark();
                if (newWriteBufferSize >= highWaterMark && newWriteBufferSize - messageSize < highWaterMark) {
                    AbstractNioChannel.this.highWaterMarkCounter.incrementAndGet();
                    if (!((Boolean) this.notifying.get()).booleanValue()) {
                        this.notifying.set(Boolean.TRUE);
                        Channels.fireChannelInterestChanged((Channel) AbstractNioChannel.this);
                        this.notifying.set(Boolean.FALSE);
                    }
                }
                return true;
            }
            throw new AssertionError();
        }

        public MessageEvent poll() {
            MessageEvent e = this.queue.poll();
            if (e != null) {
                int messageSize = getMessageSize(e);
                int newWriteBufferSize = AbstractNioChannel.this.writeBufferSize.addAndGet(-messageSize);
                int lowWaterMark = AbstractNioChannel.this.getConfig().getWriteBufferLowWaterMark();
                if ((newWriteBufferSize == 0 || newWriteBufferSize < lowWaterMark) && newWriteBufferSize + messageSize >= lowWaterMark) {
                    AbstractNioChannel.this.highWaterMarkCounter.decrementAndGet();
                    if (AbstractNioChannel.this.isConnected() && !((Boolean) this.notifying.get()).booleanValue()) {
                        this.notifying.set(Boolean.TRUE);
                        Channels.fireChannelInterestChanged((Channel) AbstractNioChannel.this);
                        this.notifying.set(Boolean.FALSE);
                    }
                }
            }
            return e;
        }

        private int getMessageSize(MessageEvent e) {
            Object m = e.getMessage();
            if (m instanceof ChannelBuffer) {
                return ((ChannelBuffer) m).readableBytes();
            }
            return 0;
        }
    }

    private final class WriteTask implements Runnable {
        WriteTask() {
        }

        public void run() {
            AbstractNioChannel.this.writeTaskInTaskQueue.set(false);
            AbstractNioChannel.this.worker.writeFromTaskLoop(AbstractNioChannel.this);
        }
    }

    public abstract NioChannelConfig getConfig();

    /* access modifiers changed from: 0000 */
    public abstract InetSocketAddress getLocalSocketAddress() throws Exception;

    /* access modifiers changed from: 0000 */
    public abstract InetSocketAddress getRemoteSocketAddress() throws Exception;

    protected AbstractNioChannel(Integer id, Channel parent, ChannelFactory factory, ChannelPipeline pipeline, ChannelSink sink, AbstractNioWorker worker2, C ch) {
        super(id, parent, factory, pipeline, sink);
        this.worker = worker2;
        this.channel = ch;
    }

    protected AbstractNioChannel(Channel parent, ChannelFactory factory, ChannelPipeline pipeline, ChannelSink sink, AbstractNioWorker worker2, C ch) {
        super(parent, factory, pipeline, sink);
        this.worker = worker2;
        this.channel = ch;
    }

    public AbstractNioWorker getWorker() {
        return this.worker;
    }

    public InetSocketAddress getLocalAddress() {
        InetSocketAddress localAddress2 = this.localAddress;
        if (localAddress2 == null) {
            try {
                localAddress2 = getLocalSocketAddress();
                if (localAddress2.getAddress().isAnyLocalAddress()) {
                    return localAddress2;
                }
                this.localAddress = localAddress2;
            } catch (Throwable th) {
                return null;
            }
        }
        return localAddress2;
    }

    public InetSocketAddress getRemoteAddress() {
        InetSocketAddress remoteAddress2 = this.remoteAddress;
        if (remoteAddress2 == null) {
            try {
                remoteAddress2 = getRemoteSocketAddress();
                this.remoteAddress = remoteAddress2;
            } catch (Throwable th) {
                return null;
            }
        }
        return remoteAddress2;
    }

    /* access modifiers changed from: 0000 */
    public int getRawInterestOps() {
        return super.getInterestOps();
    }

    /* access modifiers changed from: 0000 */
    public void setRawInterestOpsNow(int interestOps) {
        setInterestOpsNow(interestOps);
    }

    public int getInterestOps() {
        if (!isOpen()) {
            return 4;
        }
        int interestOps = getRawInterestOps();
        int writeBufferSize2 = this.writeBufferSize.get();
        if (writeBufferSize2 == 0) {
            return interestOps & -5;
        }
        if (this.highWaterMarkCounter.get() > 0) {
            if (writeBufferSize2 >= getConfig().getWriteBufferLowWaterMark()) {
                return interestOps | 4;
            }
            return interestOps & -5;
        } else if (writeBufferSize2 >= getConfig().getWriteBufferHighWaterMark()) {
            return interestOps | 4;
        } else {
            return interestOps & -5;
        }
    }

    /* access modifiers changed from: protected */
    public boolean setClosed() {
        return super.setClosed();
    }
}