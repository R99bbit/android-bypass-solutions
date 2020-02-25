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

        /* JADX WARNING: Code restructure failed: missing block: B:17:0x0039, code lost:
            r5 = r7 - r1.this$0.buffer.size();
         */
        /* JADX WARNING: Code restructure failed: missing block: B:18:0x0047, code lost:
            if (r1.sourcePos >= r5) goto L_0x011b;
         */
        /* JADX WARNING: Code restructure failed: missing block: B:20:0x004a, code lost:
            r5 = 2;
         */
        /* JADX WARNING: Code restructure failed: missing block: B:74:?, code lost:
            r2 = java.lang.Math.min(r2, r7 - r1.sourcePos);
            r1.this$0.buffer.copyTo(r22, r1.sourcePos - r5, r2);
            r1.sourcePos += r2;
         */
        /* JADX WARNING: Code restructure failed: missing block: B:76:0x0136, code lost:
            return r2;
         */
        public long read(Buffer buffer, long j) throws IOException {
            long j2;
            char c;
            long j3 = j;
            if (this.fileOperator != null) {
                synchronized (Relay.this) {
                    while (true) {
                        long j4 = this.sourcePos;
                        j2 = Relay.this.upstreamPos;
                        if (j4 != j2) {
                            break;
                        } else if (Relay.this.complete) {
                            return -1;
                        } else {
                            if (Relay.this.upstreamReader != null) {
                                this.timeout.waitUntilNotified(Relay.this);
                            } else {
                                Relay.this.upstreamReader = Thread.currentThread();
                                c = 1;
                            }
                        }
                    }
                    if (c == 2) {
                        long min = Math.min(j3, j2 - this.sourcePos);
                        this.fileOperator.read(this.sourcePos + 32, buffer, min);
                        this.sourcePos += min;
                        return min;
                    }
                    try {
                        long read = Relay.this.upstream.read(Relay.this.upstreamBuffer, Relay.this.bufferMaxSize);
                        if (read == -1) {
                            Relay.this.commit(j2);
                            synchronized (Relay.this) {
                                Relay.this.upstreamReader = null;
                                Relay.this.notifyAll();
                            }
                            return -1;
                        }
                        long min2 = Math.min(read, j3);
                        Relay.this.upstreamBuffer.copyTo(buffer, 0, min2);
                        this.sourcePos += min2;
                        this.fileOperator.write(j2 + 32, Relay.this.upstreamBuffer.clone(), read);
                        synchronized (Relay.this) {
                            Relay.this.buffer.write(Relay.this.upstreamBuffer, read);
                            if (Relay.this.buffer.size() > Relay.this.bufferMaxSize) {
                                Relay.this.buffer.skip(Relay.this.buffer.size() - Relay.this.bufferMaxSize);
                            }
                            Relay.this.upstreamPos += read;
                        }
                        synchronized (Relay.this) {
                            Relay.this.upstreamReader = null;
                            Relay.this.notifyAll();
                        }
                        return min2;
                    } catch (Throwable th) {
                        synchronized (Relay.this) {
                            Relay.this.upstreamReader = null;
                            Relay.this.notifyAll();
                            throw th;
                        }
                    }
                }
            } else {
                throw new IllegalStateException("closed");
            }
        }

        public Timeout timeout() {
            return this.timeout;
        }

        public void close() throws IOException {
            if (this.fileOperator != null) {
                Closeable closeable = null;
                this.fileOperator = null;
                synchronized (Relay.this) {
                    Relay.this.sourceCount--;
                    if (Relay.this.sourceCount == 0) {
                        RandomAccessFile randomAccessFile = Relay.this.file;
                        Relay.this.file = null;
                        closeable = randomAccessFile;
                    }
                }
                if (closeable != null) {
                    Util.closeQuietly(closeable);
                }
            }
        }
    }

    private Relay(RandomAccessFile randomAccessFile, Source source, long j, ByteString byteString, long j2) {
        this.file = randomAccessFile;
        this.upstream = source;
        this.complete = source == null;
        this.upstreamPos = j;
        this.metadata = byteString;
        this.bufferMaxSize = j2;
    }

    public static Relay edit(File file2, Source source, ByteString byteString, long j) throws IOException {
        RandomAccessFile randomAccessFile = new RandomAccessFile(file2, "rw");
        Relay relay = new Relay(randomAccessFile, source, 0, byteString, j);
        randomAccessFile.setLength(0);
        relay.writeHeader(PREFIX_DIRTY, -1, -1);
        return relay;
    }

    public static Relay read(File file2) throws IOException {
        RandomAccessFile randomAccessFile = new RandomAccessFile(file2, "rw");
        FileOperator fileOperator = new FileOperator(randomAccessFile.getChannel());
        Buffer buffer2 = new Buffer();
        fileOperator.read(0, buffer2, 32);
        if (buffer2.readByteString((long) PREFIX_CLEAN.size()).equals(PREFIX_CLEAN)) {
            long readLong = buffer2.readLong();
            long readLong2 = buffer2.readLong();
            Buffer buffer3 = new Buffer();
            fileOperator.read(readLong + 32, buffer3, readLong2);
            Relay relay = new Relay(randomAccessFile, null, readLong, buffer3.readByteString(), 0);
            return relay;
        }
        throw new IOException("unreadable cache file");
    }

    private void writeHeader(ByteString byteString, long j, long j2) throws IOException {
        Buffer buffer2 = new Buffer();
        buffer2.write(byteString);
        buffer2.writeLong(j);
        buffer2.writeLong(j2);
        if (buffer2.size() == 32) {
            new FileOperator(this.file.getChannel()).write(0, buffer2, 32);
            return;
        }
        throw new IllegalArgumentException();
    }

    private void writeMetadata(long j) throws IOException {
        Buffer buffer2 = new Buffer();
        buffer2.write(this.metadata);
        new FileOperator(this.file.getChannel()).write(32 + j, buffer2, (long) this.metadata.size());
    }

    /* access modifiers changed from: 0000 */
    public void commit(long j) throws IOException {
        writeMetadata(j);
        this.file.getChannel().force(false);
        writeHeader(PREFIX_CLEAN, j, (long) this.metadata.size());
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