package com.github.nkzawa.engineio.parser;

import com.github.nkzawa.utf8.UTF8;
import com.github.nkzawa.utf8.UTF8Exception;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

public class Parser {
    private static final int MAX_INT_CHAR_LENGTH = String.valueOf(ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED).length();
    private static Packet<String> err = new Packet<>("error", "parser error");
    private static final Map<String, Integer> packets = new HashMap<String, Integer>() {
        {
            put("open", Integer.valueOf(0));
            put("close", Integer.valueOf(1));
            put(Packet.PING, Integer.valueOf(2));
            put(Packet.PONG, Integer.valueOf(3));
            put("message", Integer.valueOf(4));
            put("upgrade", Integer.valueOf(5));
            put(Packet.NOOP, Integer.valueOf(6));
        }
    };
    private static final Map<Integer, String> packetslist = new HashMap();
    public static final int protocol = 3;

    public interface DecodePayloadCallback<T> {
        boolean call(Packet<T> packet, int i, int i2);
    }

    public interface EncodeCallback<T> {
        void call(T t);
    }

    static {
        for (Entry<String, Integer> entry : packets.entrySet()) {
            packetslist.put(entry.getValue(), entry.getKey());
        }
    }

    private Parser() {
    }

    public static void encodePacket(Packet packet, EncodeCallback callback) {
        encodePacket(packet, false, callback);
    }

    public static void encodePacket(Packet packet, boolean utf8encode, EncodeCallback callback) {
        if (packet.data instanceof byte[]) {
            encodeByteArray(packet, callback);
            return;
        }
        String encoded = String.valueOf(packets.get(packet.type));
        if (packet.data != null) {
            encoded = encoded + (utf8encode ? UTF8.encode(String.valueOf(packet.data)) : String.valueOf(packet.data));
        }
        callback.call(encoded);
    }

    private static void encodeByteArray(Packet<byte[]> packet, EncodeCallback<byte[]> callback) {
        byte[] data = (byte[]) packet.data;
        byte[] resultArray = new byte[(data.length + 1)];
        resultArray[0] = packets.get(packet.type).byteValue();
        System.arraycopy(data, 0, resultArray, 1, data.length);
        callback.call(resultArray);
    }

    public static Packet<String> decodePacket(String data) {
        return decodePacket(data, false);
    }

    public static Packet<String> decodePacket(String data, boolean utf8decode) {
        int type;
        try {
            type = Character.getNumericValue(data.charAt(0));
        } catch (IndexOutOfBoundsException e) {
            type = -1;
        }
        if (utf8decode) {
            try {
                data = UTF8.decode(data);
            } catch (UTF8Exception e2) {
                return err;
            }
        }
        if (type < 0 || type >= packetslist.size()) {
            return err;
        }
        if (data.length() > 1) {
            return new Packet(packetslist.get(Integer.valueOf(type)), data.substring(1));
        }
        return new Packet(packetslist.get(Integer.valueOf(type)));
    }

    public static Packet<byte[]> decodePacket(byte[] data) {
        byte type = data[0];
        byte[] intArray = new byte[(data.length - 1)];
        System.arraycopy(data, 1, intArray, 0, intArray.length);
        return new Packet<>(packetslist.get(Integer.valueOf(type)), intArray);
    }

    public static void encodePayload(Packet[] packets2, EncodeCallback<byte[]> callback) {
        if (packets2.length == 0) {
            callback.call(new byte[0]);
            return;
        }
        final ArrayList<byte[]> results = new ArrayList<>(packets2.length);
        for (Packet packet : packets2) {
            encodePacket(packet, true, new EncodeCallback() {
                public void call(Object packet) {
                    if (packet instanceof String) {
                        String encodingLength = String.valueOf(((String) packet).length());
                        byte[] sizeBuffer = new byte[(encodingLength.length() + 2)];
                        sizeBuffer[0] = 0;
                        for (int i = 0; i < encodingLength.length(); i++) {
                            sizeBuffer[i + 1] = (byte) Character.getNumericValue(encodingLength.charAt(i));
                        }
                        sizeBuffer[sizeBuffer.length - 1] = -1;
                        results.add(Buffer.concat(new byte[][]{sizeBuffer, Parser.stringToByteArray((String) packet)}));
                        return;
                    }
                    String encodingLength2 = String.valueOf(((byte[]) packet).length);
                    byte[] sizeBuffer2 = new byte[(encodingLength2.length() + 2)];
                    sizeBuffer2[0] = 1;
                    for (int i2 = 0; i2 < encodingLength2.length(); i2++) {
                        sizeBuffer2[i2 + 1] = (byte) Character.getNumericValue(encodingLength2.charAt(i2));
                    }
                    sizeBuffer2[sizeBuffer2.length - 1] = -1;
                    results.add(Buffer.concat(new byte[][]{sizeBuffer2, (byte[]) packet}));
                }
            });
        }
        callback.call(Buffer.concat((byte[][]) results.toArray(new byte[results.size()][])));
    }

    public static void decodePayload(String data, DecodePayloadCallback<String> callback) {
        if (data == null || data.length() == 0) {
            callback.call(err, 0, 1);
            return;
        }
        StringBuilder length = new StringBuilder();
        int i = 0;
        int l = data.length();
        while (i < l) {
            char chr = data.charAt(i);
            if (':' != chr) {
                length.append(chr);
            } else {
                try {
                    int n = Integer.parseInt(length.toString());
                    try {
                        String msg = data.substring(i + 1, i + 1 + n);
                        if (msg.length() != 0) {
                            Packet<String> packet = decodePacket(msg, true);
                            if (err.type.equals(packet.type) && ((String) err.data).equals(packet.data)) {
                                callback.call(err, 0, 1);
                                return;
                            } else if (!callback.call(packet, i + n, l)) {
                                return;
                            }
                        }
                        i += n;
                        length = new StringBuilder();
                    } catch (IndexOutOfBoundsException e) {
                        callback.call(err, 0, 1);
                        return;
                    }
                } catch (NumberFormatException e2) {
                    callback.call(err, 0, 1);
                    return;
                }
            }
            i++;
        }
        if (length.length() > 0) {
            callback.call(err, 0, 1);
        }
    }

    public static void decodePayload(byte[] data, DecodePayloadCallback callback) {
        ByteBuffer bufferTail = ByteBuffer.wrap(data);
        List<Object> buffers = new ArrayList<>();
        while (bufferTail.capacity() > 0) {
            StringBuilder strLen = new StringBuilder();
            boolean isString = (bufferTail.get(0) & 255) == 0;
            boolean numberTooLong = false;
            int i = 1;
            while (true) {
                int b = bufferTail.get(i) & 255;
                if (b == 255) {
                    break;
                } else if (strLen.length() > MAX_INT_CHAR_LENGTH) {
                    numberTooLong = true;
                    break;
                } else {
                    strLen.append(b);
                    i++;
                }
            }
            if (numberTooLong) {
                callback.call(err, 0, 1);
                return;
            }
            bufferTail.position(strLen.length() + 1);
            ByteBuffer bufferTail2 = bufferTail.slice();
            int msgLength = Integer.parseInt(strLen.toString());
            bufferTail2.position(1);
            bufferTail2.limit(msgLength + 1);
            byte[] msg = new byte[bufferTail2.remaining()];
            bufferTail2.get(msg);
            if (isString) {
                buffers.add(byteArrayToString(msg));
            } else {
                buffers.add(msg);
            }
            bufferTail2.clear();
            bufferTail2.position(msgLength + 1);
            bufferTail = bufferTail2.slice();
        }
        int total = buffers.size();
        for (int i2 = 0; i2 < total; i2++) {
            Object buffer = buffers.get(i2);
            if (buffer instanceof String) {
                callback.call(decodePacket((String) buffer, true), i2, total);
            } else if (buffer instanceof byte[]) {
                callback.call(decodePacket((byte[]) (byte[]) buffer), i2, total);
            }
        }
    }

    private static String byteArrayToString(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (byte b : bytes) {
            builder.appendCodePoint(b & 255);
        }
        return builder.toString();
    }

    /* access modifiers changed from: private */
    public static byte[] stringToByteArray(String string) {
        int len = string.length();
        byte[] bytes = new byte[len];
        for (int i = 0; i < len; i++) {
            bytes[i] = (byte) Character.codePointAt(string, i);
        }
        return bytes;
    }
}