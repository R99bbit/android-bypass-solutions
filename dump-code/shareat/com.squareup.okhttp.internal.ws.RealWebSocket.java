package com.squareup.okhttp.internal.ws;

import com.squareup.okhttp.internal.NamedRunnable;
import com.squareup.okhttp.internal.ws.WebSocketReader.FrameCallback;
import com.squareup.okhttp.ws.WebSocket;
import com.squareup.okhttp.ws.WebSocket.PayloadType;
import com.squareup.okhttp.ws.WebSocketListener;
import java.io.IOException;
import java.net.ProtocolException;
import java.util.Random;
import java.util.concurrent.Executor;
import okio.Buffer;
import okio.BufferedSink;
import okio.BufferedSource;

public abstract class RealWebSocket implements WebSocket {
    private static final int CLOSE_PROTOCOL_EXCEPTION = 1002;
    /* access modifiers changed from: private */
    public final Object closeLock = new Object();
    private final WebSocketListener listener;
    private final WebSocketReader reader;
    /* access modifiers changed from: private */
    public volatile boolean readerSentClose;
    /* access modifiers changed from: private */
    public final WebSocketWriter writer;
    /* access modifiers changed from: private */
    public volatile boolean writerSentClose;

    /* access modifiers changed from: protected */
    public abstract void closeConnection() throws IOException;

    public RealWebSocket(boolean isClient, BufferedSource source, BufferedSink sink, Random random, final Executor replyExecutor, final WebSocketListener listener2, final String url) {
        this.listener = listener2;
        this.writer = new WebSocketWriter(isClient, sink, random);
        this.reader = new WebSocketReader(isClient, source, new FrameCallback() {
            public void onMessage(BufferedSource source, PayloadType type) throws IOException {
                listener2.onMessage(source, type);
            }

            public void onPing(final Buffer buffer) {
                replyExecutor.execute(new NamedRunnable("OkHttp %s WebSocket Pong Reply", new Object[]{url}) {
                    /* access modifiers changed from: protected */
                    public void execute() {
                        try {
                            RealWebSocket.this.writer.writePong(buffer);
                        } catch (IOException e) {
                        }
                    }
                });
            }

            public void onPong(Buffer buffer) {
                listener2.onPong(buffer);
            }

            public void onClose(int code, String reason) {
                final boolean writeCloseResponse;
                synchronized (RealWebSocket.this.closeLock) {
                    RealWebSocket.this.readerSentClose = true;
                    if (!RealWebSocket.this.writerSentClose) {
                        writeCloseResponse = true;
                    } else {
                        writeCloseResponse = false;
                    }
                }
                final int i = code;
                final String str = reason;
                replyExecutor.execute(new NamedRunnable("OkHttp %s WebSocket Close Reply", new Object[]{url}) {
                    /* access modifiers changed from: protected */
                    public void execute() {
                        RealWebSocket.this.peerClose(i, str, writeCloseResponse);
                    }
                });
            }
        });
    }

    public boolean readMessage() {
        try {
            this.reader.processNextFrame();
            if (!this.readerSentClose) {
                return true;
            }
            return false;
        } catch (IOException e) {
            readerErrorClose(e);
            return false;
        }
    }

    public BufferedSink newMessageSink(PayloadType type) {
        if (!this.writerSentClose) {
            return this.writer.newMessageSink(type);
        }
        throw new IllegalStateException("closed");
    }

    public void sendMessage(PayloadType type, Buffer payload) throws IOException {
        if (this.writerSentClose) {
            throw new IllegalStateException("closed");
        }
        this.writer.sendMessage(type, payload);
    }

    public void sendPing(Buffer payload) throws IOException {
        if (this.writerSentClose) {
            throw new IllegalStateException("closed");
        }
        this.writer.writePing(payload);
    }

    public void sendPong(Buffer payload) throws IOException {
        if (this.writerSentClose) {
            throw new IllegalStateException("closed");
        }
        this.writer.writePong(payload);
    }

    public void close(int code, String reason) throws IOException {
        boolean closeConnection;
        if (this.writerSentClose) {
            throw new IllegalStateException("closed");
        }
        synchronized (this.closeLock) {
            this.writerSentClose = true;
            closeConnection = this.readerSentClose;
        }
        this.writer.writeClose(code, reason);
        if (closeConnection) {
            closeConnection();
        }
    }

    /* access modifiers changed from: private */
    public void peerClose(int code, String reason, boolean writeCloseResponse) {
        if (writeCloseResponse) {
            try {
                this.writer.writeClose(code, reason);
            } catch (IOException e) {
            }
        }
        try {
            closeConnection();
        } catch (IOException e2) {
        }
        this.listener.onClose(code, reason);
    }

    private void readerErrorClose(IOException e) {
        boolean writeCloseResponse = true;
        synchronized (this.closeLock) {
            this.readerSentClose = true;
            if (this.writerSentClose) {
                writeCloseResponse = false;
            }
        }
        if (writeCloseResponse && (e instanceof ProtocolException)) {
            try {
                this.writer.writeClose(1002, null);
            } catch (IOException e2) {
            }
        }
        try {
            closeConnection();
        } catch (IOException e3) {
        }
        this.listener.onFailure(e, null);
    }
}