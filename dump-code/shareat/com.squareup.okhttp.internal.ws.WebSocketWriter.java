package com.squareup.okhttp.internal.ws;

import com.squareup.okhttp.ws.WebSocket.PayloadType;
import java.io.IOException;
import java.util.Random;
import okio.Buffer;
import okio.BufferedSink;
import okio.BufferedSource;
import okio.Okio;
import okio.Sink;
import okio.Timeout;

public final class WebSocketWriter {
    /* access modifiers changed from: private */
    public boolean activeWriter;
    /* access modifiers changed from: private */
    public boolean closed;
    private final FrameSink frameSink = new FrameSink();
    /* access modifiers changed from: private */
    public final boolean isClient;
    private final byte[] maskBuffer;
    /* access modifiers changed from: private */
    public final byte[] maskKey;
    /* access modifiers changed from: private */
    public final Random random;
    /* access modifiers changed from: private */
    public final BufferedSink sink;

    private final class FrameSink implements Sink {
        /* access modifiers changed from: private */
        public boolean isFirstFrame;
        /* access modifiers changed from: private */
        public PayloadType payloadType;

        private FrameSink() {
        }

        public void write(Buffer source, long byteCount) throws IOException {
            WebSocketWriter.this.writeFrame(this.payloadType, source, byteCount, this.isFirstFrame, false);
            this.isFirstFrame = false;
        }

        public void flush() throws IOException {
            if (WebSocketWriter.this.closed) {
                throw new IOException("closed");
            }
            synchronized (WebSocketWriter.this.sink) {
                WebSocketWriter.this.sink.flush();
            }
        }

        public Timeout timeout() {
            return WebSocketWriter.this.sink.timeout();
        }

        public void close() throws IOException {
            if (WebSocketWriter.this.closed) {
                throw new IOException("closed");
            }
            synchronized (WebSocketWriter.this.sink) {
                WebSocketWriter.this.sink.writeByte(128);
                if (WebSocketWriter.this.isClient) {
                    WebSocketWriter.this.sink.writeByte(128);
                    WebSocketWriter.this.random.nextBytes(WebSocketWriter.this.maskKey);
                    WebSocketWriter.this.sink.write(WebSocketWriter.this.maskKey);
                } else {
                    WebSocketWriter.this.sink.writeByte(0);
                }
                WebSocketWriter.this.sink.flush();
            }
            WebSocketWriter.this.activeWriter = false;
        }
    }

    public WebSocketWriter(boolean isClient2, BufferedSink sink2, Random random2) {
        byte[] bArr;
        byte[] bArr2 = null;
        if (sink2 == null) {
            throw new NullPointerException("sink == null");
        } else if (random2 == null) {
            throw new NullPointerException("random == null");
        } else {
            this.isClient = isClient2;
            this.sink = sink2;
            this.random = random2;
            if (isClient2) {
                bArr = new byte[4];
            } else {
                bArr = null;
            }
            this.maskKey = bArr;
            this.maskBuffer = isClient2 ? new byte[2048] : bArr2;
        }
    }

    public void writePing(Buffer payload) throws IOException {
        synchronized (this.sink) {
            writeControlFrame(9, payload);
        }
    }

    public void writePong(Buffer payload) throws IOException {
        synchronized (this.sink) {
            writeControlFrame(10, payload);
        }
    }

    public void writeClose(int code, String reason) throws IOException {
        Buffer payload = null;
        if (!(code == 0 && reason == null)) {
            if (code == 0 || (code >= 1000 && code < 5000)) {
                payload = new Buffer();
                payload.writeShort(code);
                if (reason != null) {
                    payload.writeUtf8(reason);
                }
            } else {
                throw new IllegalArgumentException("Code must be in range [1000,5000).");
            }
        }
        synchronized (this.sink) {
            writeControlFrame(8, payload);
            this.closed = true;
        }
    }

    private void writeControlFrame(int opcode, Buffer payload) throws IOException {
        if (this.closed) {
            throw new IOException("closed");
        }
        int length = 0;
        if (payload != null) {
            length = (int) payload.size();
            if (length > 125) {
                throw new IllegalArgumentException("Payload size must be less than or equal to 125");
            }
        }
        this.sink.writeByte(opcode | 128);
        int b1 = length;
        if (this.isClient) {
            this.sink.writeByte(b1 | 128);
            this.random.nextBytes(this.maskKey);
            this.sink.write(this.maskKey);
            if (payload != null) {
                writeAllMasked(payload, (long) length);
            }
        } else {
            this.sink.writeByte(b1);
            if (payload != null) {
                this.sink.writeAll(payload);
            }
        }
        this.sink.flush();
    }

    public BufferedSink newMessageSink(PayloadType type) {
        if (type == null) {
            throw new NullPointerException("type == null");
        } else if (this.activeWriter) {
            throw new IllegalStateException("Another message writer is active. Did you call close()?");
        } else {
            this.activeWriter = true;
            this.frameSink.payloadType = type;
            this.frameSink.isFirstFrame = true;
            return Okio.buffer((Sink) this.frameSink);
        }
    }

    public void sendMessage(PayloadType type, Buffer payload) throws IOException {
        if (type == null) {
            throw new NullPointerException("type == null");
        } else if (payload == null) {
            throw new NullPointerException("payload == null");
        } else if (this.activeWriter) {
            throw new IllegalStateException("A message writer is active. Did you call close()?");
        } else {
            writeFrame(type, payload, payload.size(), true, true);
        }
    }

    /* access modifiers changed from: private */
    public void writeFrame(PayloadType payloadType, Buffer source, long byteCount, boolean isFirstFrame, boolean isFinal) throws IOException {
        if (this.closed) {
            throw new IOException("closed");
        }
        int opcode = 0;
        if (isFirstFrame) {
            switch (payloadType) {
                case TEXT:
                    opcode = 1;
                    break;
                case BINARY:
                    opcode = 2;
                    break;
                default:
                    throw new IllegalStateException("Unknown payload type: " + payloadType);
            }
        }
        synchronized (this.sink) {
            int b0 = opcode;
            if (isFinal) {
                b0 |= 128;
            }
            this.sink.writeByte(b0);
            int b1 = 0;
            if (this.isClient) {
                b1 = 0 | 128;
                this.random.nextBytes(this.maskKey);
            }
            if (byteCount <= 125) {
                this.sink.writeByte(b1 | ((int) byteCount));
            } else if (byteCount <= 65535) {
                this.sink.writeByte(b1 | 126);
                this.sink.writeShort((int) byteCount);
            } else {
                this.sink.writeByte(b1 | 127);
                this.sink.writeLong(byteCount);
            }
            if (this.isClient) {
                this.sink.write(this.maskKey);
                writeAllMasked(source, byteCount);
            } else {
                this.sink.write(source, byteCount);
            }
            this.sink.flush();
        }
    }

    private void writeAllMasked(BufferedSource source, long byteCount) throws IOException {
        long written = 0;
        while (written < byteCount) {
            int read = source.read(this.maskBuffer, 0, (int) Math.min(byteCount, (long) this.maskBuffer.length));
            if (read == -1) {
                throw new AssertionError();
            }
            WebSocketProtocol.toggleMask(this.maskBuffer, (long) read, this.maskKey, written);
            this.sink.write(this.maskBuffer, 0, read);
            written += (long) read;
        }
    }
}