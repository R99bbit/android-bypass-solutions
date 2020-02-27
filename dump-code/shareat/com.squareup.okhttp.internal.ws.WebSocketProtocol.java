package com.squareup.okhttp.internal.ws;

public final class WebSocketProtocol {
    public static final String ACCEPT_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    static final int B0_FLAG_FIN = 128;
    static final int B0_FLAG_RSV1 = 64;
    static final int B0_FLAG_RSV2 = 32;
    static final int B0_FLAG_RSV3 = 16;
    static final int B0_MASK_OPCODE = 15;
    static final int B1_FLAG_MASK = 128;
    static final int B1_MASK_LENGTH = 127;
    static final int OPCODE_BINARY = 2;
    static final int OPCODE_CONTINUATION = 0;
    static final int OPCODE_CONTROL_CLOSE = 8;
    static final int OPCODE_CONTROL_PING = 9;
    static final int OPCODE_CONTROL_PONG = 10;
    static final int OPCODE_FLAG_CONTROL = 8;
    static final int OPCODE_TEXT = 1;
    static final int PAYLOAD_LONG = 127;
    static final int PAYLOAD_MAX = 125;
    static final int PAYLOAD_SHORT = 126;

    static void toggleMask(byte[] buffer, long byteCount, byte[] key, long frameBytesRead) {
        int keyLength = key.length;
        int i = 0;
        while (((long) i) < byteCount) {
            buffer[i] = (byte) (buffer[i] ^ key[(int) (frameBytesRead % ((long) keyLength))]);
            i++;
            frameBytesRead++;
        }
    }

    private WebSocketProtocol() {
        throw new AssertionError("No instances.");
    }
}