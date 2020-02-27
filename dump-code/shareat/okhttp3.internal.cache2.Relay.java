package okhttp3.internal.cache2;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import okhttp3.internal.Util;
import okio.Buffer;
import okio.ByteString;
import okio.Source;
import okio.Timeout;

final class Relay {
    private static final long FILE_HEADER_SIZE = 32;
    static final ByteString PREFIX_CLEAN = ByteString.encodeUtf8("OkHttp cache v1\n");
    static final ByteString PREFIX_DIRTY = ByteString.encodeUtf8("OkHttp DIRTY :(\n");
    private static final int SOURCE_FILE = 2;
    private static final int SOURCE_UPSTREAM = 1;
    final Buffer buffer = new Buffer();
    final long bufferMaxSize;
    boolean complete;
    RandomAccessFile file;
    private final ByteString metadata;
    int sourceCount;
    Source upstream;
    final Buffer upstreamBuffer = new Buffer();
    long upstreamPos;
    Thread upstreamReader;

    class RelaySource implements Source {
        private FileOperator fileOperator = new FileOperator(Relay.this.file.getChannel());
        private long sourcePos;
        private final Timeout timeout = new Timeout();

        RelaySource() {
        }

        /* JADX INFO: finally extract failed */
        /* JADX WARNING: Code restructure failed: missing block: B:105:?, code lost:
            return r8;
         */
        /* JADX WARNING: Code restructure failed: missing block: B:22:?, code lost:
            r28.this$0.upstreamReader = java.lang.Thread.currentThread();
            r24 = 1;
         */
        /* JADX WARNING: Code restructure failed: missing block: B:29:?, code lost:
            r22 = r26 - r28.this$0.buffer.size();
         */
        /* JADX WARNING: Code restructure failed: missing block: B:30:0x0092, code lost:
            if (r28.sourcePos >= r22) goto L_0x0098;
         */
        /* JADX WARNING: Code restructure failed: missing block: B:31:0x0094, code lost:
            r24 = 2;
         */
        /* JADX WARNING: Code restructure failed: missing block: B:34:0x0098, code lost:
            r8 = java.lang.Math.min(r30, r26 - r28.sourcePos);
            r28.this$0.buffer.copyTo(r29, r28.sourcePos - r22, r8);
            r28.sourcePos += r8;
         */
        public long read(Buffer sink, long byteCount) throws IOException {
            long upstreamPos;
            char c;
            if (this.fileOperator == null) {
                throw new IllegalStateException("closed");
            }
            synchronized (Relay.this) {
                while (true) {
                    long j = this.sourcePos;
                    upstreamPos = Relay.this.upstreamPos;
                    if (j == upstreamPos) {
                        if (!Relay.this.complete) {
                            if (Relay.this.upstreamReader == null) {
                                break;
                            }
                            this.timeout.waitUntilNotified(Relay.this);
                        } else {
                            return -1;
                        }
                    } else {
                        break;
                    }
                }
                if (c == 2) {
                    long bytesToRead = Math.min(byteCount, upstreamPos - this.sourcePos);
                    this.fileOperator.read(32 + this.sourcePos, sink, bytesToRead);
                    this.sourcePos += bytesToRead;
                    return bytesToRead;
                }
                try {
                    long upstreamBytesRead = Relay.this.upstream.read(Relay.this.upstreamBuffer, Relay.this.bufferMaxSize);
                    if (upstreamBytesRead == -1) {
                        Relay.this.commit(upstreamPos);
                        synchronized (Relay.this) {
                            Relay.this.upstreamReader = null;
                            Relay.this.notifyAll();
                        }
                        return -1;
                    }
                    long bytesRead = Math.min(upstreamBytesRead, byteCount);
                    Relay.this.upstreamBuffer.copyTo(sink, 0, bytesRead);
                    this.sourcePos += bytesRead;
                    this.fileOperator.write(32 + upstreamPos, Relay.this.upstreamBuffer.clone(), upstreamBytesRead);
                    synchronized (Relay.this) {
                        Relay.this.buffer.write(Relay.this.upstreamBuffer, upstreamBytesRead);
                        if (Relay.this.buffer.size() > Relay.this.bufferMaxSize) {
                            Relay.this.buffer.skip(Relay.this.buffer.size() - Relay.this.bufferMaxSize);
                        }
                        Relay.this.upstreamPos += upstreamBytesRead;
                    }
                    synchronized (Relay.this) {
                        Relay.this.upstreamReader = null;
                        Relay.this.notifyAll();
                    }
                    return bytesRead;
                } catch (Throwable th) {
                    synchronized (Relay.this) {
                        Relay.this.upstreamReader = null;
                        Relay.this.notifyAll();
                        throw th;
                    }
                }
            }
        }

        public Timeout timeout() {
            return this.timeout;
        }

        public void close() throws IOException {
            if (this.fileOperator != null) {
                this.fileOperator = null;
                RandomAccessFile fileToClose = null;
                synchronized (Relay.this) {
                    Relay.this.sourceCount--;
                    if (Relay.this.sourceCount == 0) {
                        fileToClose = Relay.this.file;
                        Relay.this.file = null;
                    }
                }
                if (fileToClose != null) {
                    Util.closeQuietly((Closeable) fileToClose);
                }
            }
        }
    }

    private Relay(RandomAccessFile file2, Source upstream2, long upstreamPos2, ByteString metadata2, long bufferMaxSize2) {
        this.file = file2;
        this.upstream = upstream2;
        this.complete = upstream2 == null;
        this.upstreamPos = upstreamPos2;
        this.metadata = metadata2;
        this.bufferMaxSize = bufferMaxSize2;
    }

    public static Relay edit(File file2, Source upstream2, ByteString metadata2, long bufferMaxSize2) throws IOException {
        RandomAccessFile randomAccessFile = new RandomAccessFile(file2, "rw");
        Relay result = new Relay(randomAccessFile, upstream2, 0, metadata2, bufferMaxSize2);
        randomAccessFile.setLength(0);
        result.writeHeader(PREFIX_DIRTY, -1, -1);
        return result;
    }

    public static Relay read(File file2) throws IOException {
        RandomAccessFile randomAccessFile = new RandomAccessFile(file2, "rw");
        FileOperator fileOperator = new FileOperator(randomAccessFile.getChannel());
        Buffer header = new Buffer();
        fileOperator.read(0, header, 32);
        if (!header.readByteString((long) PREFIX_CLEAN.size()).equals(PREFIX_CLEAN)) {
            throw new IOException("unreadable cache file");
        }
        long upstreamSize = header.readLong();
        long metadataSize = header.readLong();
        Buffer metadataBuffer = new Buffer();
        fileOperator.read(32 + upstreamSize, metadataBuffer, metadataSize);
        return new Relay(randomAccessFile, null, upstreamSize, metadataBuffer.readByteString(), 0);
    }

    private void writeHeader(ByteString prefix, long upstreamSize, long metadataSize) throws IOException {
        Buffer header = new Buffer();
        header.write(prefix);
        header.writeLong(upstreamSize);
        header.writeLong(metadataSize);
        if (header.size() != 32) {
            throw new IllegalArgumentException();
        }
        new FileOperator(this.file.getChannel()).write(0, header, 32);
    }

    private void writeMetadata(long upstreamSize) throws IOException {
        Buffer metadataBuffer = new Buffer();
        metadataBuffer.write(this.metadata);
        new FileOperator(this.file.getChannel()).write(32 + upstreamSize, metadataBuffer, (long) this.metadata.size());
    }

    /* access modifiers changed from: 0000 */
    public void commit(long upstreamSize) throws IOException {
        writeMetadata(upstreamSize);
        this.file.getChannel().force(false);
        writeHeader(PREFIX_CLEAN, upstreamSize, (long) this.metadata.size());
        this.file.getChannel().force(false);
        synchronized (this) {
            this.complete = true;
        }
        Util.closeQuietly((Closeable) this.upstream);
        this.upstream = null;
    }

    /* access modifiers changed from: 0000 */
    public boolean isClosed() {
        return this.file == null;
    }

    public ByteString metadata() {
        return this.metadata;
    }

    public Source newSource() {
        synchronized (this) {
            if (this.file == null) {
                return null;
            }
            this.sourceCount++;
            return new RelaySource();
        }
    }
}