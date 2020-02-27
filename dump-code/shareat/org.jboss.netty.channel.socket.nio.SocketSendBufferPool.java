package org.jboss.netty.channel.socket.nio;

import java.io.IOException;
import java.lang.ref.SoftReference;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.GatheringByteChannel;
import java.nio.channels.WritableByteChannel;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.CompositeChannelBuffer;
import org.jboss.netty.channel.DefaultFileRegion;
import org.jboss.netty.channel.FileRegion;
import org.jboss.netty.util.ExternalResourceReleasable;
import org.jboss.netty.util.internal.ByteBufferUtil;

final class SocketSendBufferPool implements ExternalResourceReleasable {
    private static final int ALIGN_MASK = 15;
    private static final int ALIGN_SHIFT = 4;
    private static final int DEFAULT_PREALLOCATION_SIZE = 65536;
    private static final SendBuffer EMPTY_BUFFER = new EmptySendBuffer();
    /* access modifiers changed from: private */
    public Preallocation current = new Preallocation(65536);
    /* access modifiers changed from: private */
    public PreallocationRef poolHead;

    static final class EmptySendBuffer implements SendBuffer {
        EmptySendBuffer() {
        }

        public boolean finished() {
            return true;
        }

        public long writtenBytes() {
            return 0;
        }

        public long totalBytes() {
            return 0;
        }

        public long transferTo(WritableByteChannel ch) {
            return 0;
        }

        public long transferTo(DatagramChannel ch, SocketAddress raddr) {
            return 0;
        }

        public void release() {
        }
    }

    final class FileSendBuffer implements SendBuffer {
        private final FileRegion file;
        private long writtenBytes;

        FileSendBuffer(FileRegion file2) {
            this.file = file2;
        }

        public boolean finished() {
            return this.writtenBytes >= this.file.getCount();
        }

        public long writtenBytes() {
            return this.writtenBytes;
        }

        public long totalBytes() {
            return this.file.getCount();
        }

        public long transferTo(WritableByteChannel ch) throws IOException {
            long localWrittenBytes = this.file.transferTo(ch, this.writtenBytes);
            this.writtenBytes += localWrittenBytes;
            return localWrittenBytes;
        }

        public long transferTo(DatagramChannel ch, SocketAddress raddr) {
            throw new UnsupportedOperationException();
        }

        public void release() {
            if ((this.file instanceof DefaultFileRegion) && ((DefaultFileRegion) this.file).releaseAfterTransfer()) {
                this.file.releaseExternalResources();
            }
        }
    }

    static class GatheringSendBuffer implements SendBuffer {
        private final ByteBuffer[] buffers;
        private final int last;
        private final int total;
        private long written;

        GatheringSendBuffer(ByteBuffer[] buffers2) {
            this.buffers = buffers2;
            this.last = buffers2.length - 1;
            int total2 = 0;
            for (ByteBuffer buf : buffers2) {
                total2 += buf.remaining();
            }
            this.total = total2;
        }

        public boolean finished() {
            return !this.buffers[this.last].hasRemaining();
        }

        public long writtenBytes() {
            return this.written;
        }

        public long totalBytes() {
            return (long) this.total;
        }

        public long transferTo(WritableByteChannel ch) throws IOException {
            ByteBuffer[] arr$;
            if (ch instanceof GatheringByteChannel) {
                long w = ((GatheringByteChannel) ch).write(this.buffers);
                this.written += w;
                return w;
            }
            int send = 0;
            for (ByteBuffer buf : this.buffers) {
                if (buf.hasRemaining()) {
                    int w2 = ch.write(buf);
                    if (w2 == 0) {
                        break;
                    }
                    send += w2;
                }
            }
            this.written += (long) send;
            return (long) send;
        }

        public long transferTo(DatagramChannel ch, SocketAddress raddr) throws IOException {
            ByteBuffer[] arr$;
            int send = 0;
            for (ByteBuffer buf : this.buffers) {
                if (buf.hasRemaining()) {
                    int w = ch.send(buf, raddr);
                    if (w == 0) {
                        break;
                    }
                    send += w;
                }
            }
            this.written += (long) send;
            return (long) send;
        }

        public void release() {
        }
    }

    final class PooledSendBuffer extends UnpooledSendBuffer {
        private final Preallocation parent;

        PooledSendBuffer(Preallocation parent2, ByteBuffer buffer) {
            super(buffer);
            this.parent = parent2;
        }

        public void release() {
            Preallocation parent2 = this.parent;
            int i = parent2.refCnt - 1;
            parent2.refCnt = i;
            if (i == 0) {
                parent2.buffer.clear();
                if (parent2 != SocketSendBufferPool.this.current) {
                    SocketSendBufferPool.this.poolHead = new PreallocationRef(parent2, SocketSendBufferPool.this.poolHead);
                }
            }
        }
    }

    private static final class Preallocation {
        final ByteBuffer buffer;
        int refCnt;

        Preallocation(int capacity) {
            this.buffer = ByteBuffer.allocateDirect(capacity);
        }
    }

    private final class PreallocationRef extends SoftReference<Preallocation> {
        final PreallocationRef next;

        PreallocationRef(Preallocation prealloation, PreallocationRef next2) {
            super(prealloation);
            this.next = next2;
        }
    }

    interface SendBuffer {
        boolean finished();

        void release();

        long totalBytes();

        long transferTo(DatagramChannel datagramChannel, SocketAddress socketAddress) throws IOException;

        long transferTo(WritableByteChannel writableByteChannel) throws IOException;

        long writtenBytes();
    }

    static class UnpooledSendBuffer implements SendBuffer {
        final ByteBuffer buffer;
        final int initialPos;

        UnpooledSendBuffer(ByteBuffer buffer2) {
            this.buffer = buffer2;
            this.initialPos = buffer2.position();
        }

        public final boolean finished() {
            return !this.buffer.hasRemaining();
        }

        public final long writtenBytes() {
            return (long) (this.buffer.position() - this.initialPos);
        }

        public final long totalBytes() {
            return (long) (this.buffer.limit() - this.initialPos);
        }

        public final long transferTo(WritableByteChannel ch) throws IOException {
            return (long) ch.write(this.buffer);
        }

        public final long transferTo(DatagramChannel ch, SocketAddress raddr) throws IOException {
            return (long) ch.send(this.buffer, raddr);
        }

        public void release() {
        }
    }

    SocketSendBufferPool() {
    }

    /* access modifiers changed from: 0000 */
    public SendBuffer acquire(Object message) {
        if (message instanceof ChannelBuffer) {
            return acquire((ChannelBuffer) message);
        }
        if (message instanceof FileRegion) {
            return acquire((FileRegion) message);
        }
        throw new IllegalArgumentException("unsupported message type: " + message.getClass());
    }

    private SendBuffer acquire(FileRegion src) {
        if (src.getCount() == 0) {
            return EMPTY_BUFFER;
        }
        return new FileSendBuffer(src);
    }

    private SendBuffer acquire(ChannelBuffer src) {
        PooledSendBuffer dst;
        int size = src.readableBytes();
        if (size == 0) {
            return EMPTY_BUFFER;
        }
        if ((src instanceof CompositeChannelBuffer) && ((CompositeChannelBuffer) src).useGathering()) {
            return new GatheringSendBuffer(src.toByteBuffers());
        }
        if (src.isDirect()) {
            return new UnpooledSendBuffer(src.toByteBuffer());
        }
        if (src.readableBytes() > 65536) {
            return new UnpooledSendBuffer(src.toByteBuffer());
        }
        Preallocation current2 = this.current;
        ByteBuffer buffer = current2.buffer;
        int remaining = buffer.remaining();
        if (size < remaining) {
            int nextPos = buffer.position() + size;
            ByteBuffer slice = buffer.duplicate();
            buffer.position(align(nextPos));
            slice.limit(nextPos);
            current2.refCnt++;
            dst = new PooledSendBuffer(current2, slice);
        } else if (size > remaining) {
            Preallocation current3 = getPreallocation();
            this.current = current3;
            ByteBuffer buffer2 = current3.buffer;
            ByteBuffer slice2 = buffer2.duplicate();
            buffer2.position(align(size));
            slice2.limit(size);
            current3.refCnt++;
            dst = new PooledSendBuffer(current3, slice2);
        } else {
            current2.refCnt++;
            this.current = getPreallocation0();
            dst = new PooledSendBuffer(current2, current2.buffer);
        }
        ByteBuffer dstbuf = dst.buffer;
        dstbuf.mark();
        src.getBytes(src.readerIndex(), dstbuf);
        dstbuf.reset();
        return dst;
    }

    private Preallocation getPreallocation() {
        Preallocation current2 = this.current;
        if (current2.refCnt != 0) {
            return getPreallocation0();
        }
        current2.buffer.clear();
        return current2;
    }

    private Preallocation getPreallocation0() {
        PreallocationRef ref = this.poolHead;
        if (ref != null) {
            do {
                Preallocation p = (Preallocation) ref.get();
                ref = ref.next;
                if (p != null) {
                    this.poolHead = ref;
                    return p;
                }
            } while (ref != null);
            this.poolHead = ref;
        }
        return new Preallocation(65536);
    }

    private static int align(int pos) {
        int q = pos >>> 4;
        if ((pos & 15) != 0) {
            q++;
        }
        return q << 4;
    }

    public void releaseExternalResources() {
        if (this.current.buffer != null) {
            ByteBufferUtil.destroy(this.current.buffer);
        }
    }
}