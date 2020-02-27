package okio;

import java.io.IOException;

public final class Pipe {
    final Buffer buffer = new Buffer();
    final long maxBufferSize;
    private final Sink sink = new PipeSink();
    boolean sinkClosed;
    private final Source source = new PipeSource();
    boolean sourceClosed;

    final class PipeSink implements Sink {
        final Timeout timeout = new Timeout();

        PipeSink() {
        }

        /* JADX WARNING: CFG modification limit reached, blocks count: 127 */
        public void write(Buffer source, long byteCount) throws IOException {
            synchronized (Pipe.this.buffer) {
                if (Pipe.this.sinkClosed) {
                    throw new IllegalStateException("closed");
                }
                while (byteCount > 0) {
                    if (Pipe.this.sourceClosed) {
                        throw new IOException("source is closed");
                    }
                    long bufferSpaceAvailable = Pipe.this.maxBufferSize - Pipe.this.buffer.size();
                    if (bufferSpaceAvailable == 0) {
                        this.timeout.waitUntilNotified(Pipe.this.buffer);
                    } else {
                        long bytesToWrite = Math.min(bufferSpaceAvailable, byteCount);
                        Pipe.this.buffer.write(source, bytesToWrite);
                        byteCount -= bytesToWrite;
                        Pipe.this.buffer.notifyAll();
                    }
                }
            }
        }

        public void flush() throws IOException {
            synchronized (Pipe.this.buffer) {
                if (Pipe.this.sinkClosed) {
                    throw new IllegalStateException("closed");
                } else if (Pipe.this.sourceClosed && Pipe.this.buffer.size() > 0) {
                    throw new IOException("source is closed");
                }
            }
        }

        public void close() throws IOException {
            synchronized (Pipe.this.buffer) {
                if (!Pipe.this.sinkClosed) {
                    if (!Pipe.this.sourceClosed || Pipe.this.buffer.size() <= 0) {
                        Pipe.this.sinkClosed = true;
                        Pipe.this.buffer.notifyAll();
                        return;
                    }
                    throw new IOException("source is closed");
                }
            }
        }

        public Timeout timeout() {
            return this.timeout;
        }
    }

    final class PipeSource implements Source {
        final Timeout timeout = new Timeout();

        PipeSource() {
        }

        public long read(Buffer sink, long byteCount) throws IOException {
            long read;
            synchronized (Pipe.this.buffer) {
                if (!Pipe.this.sourceClosed) {
                    while (true) {
                        if (Pipe.this.buffer.size() != 0) {
                            read = Pipe.this.buffer.read(sink, byteCount);
                            Pipe.this.buffer.notifyAll();
                            break;
                        } else if (Pipe.this.sinkClosed) {
                            read = -1;
                            break;
                        } else {
                            this.timeout.waitUntilNotified(Pipe.this.buffer);
                        }
                    }
                } else {
                    throw new IllegalStateException("closed");
                }
            }
            return read;
        }

        public void close() throws IOException {
            synchronized (Pipe.this.buffer) {
                Pipe.this.sourceClosed = true;
                Pipe.this.buffer.notifyAll();
            }
        }

        public Timeout timeout() {
            return this.timeout;
        }
    }

    public Pipe(long maxBufferSize2) {
        if (maxBufferSize2 < 1) {
            throw new IllegalArgumentException("maxBufferSize < 1: " + maxBufferSize2);
        }
        this.maxBufferSize = maxBufferSize2;
    }

    public Source source() {
        return this.source;
    }

    public Sink sink() {
        return this.sink;
    }
}