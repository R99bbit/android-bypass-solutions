package org.jboss.netty.buffer;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;
import java.util.ArrayList;
import java.util.List;
import org.jboss.netty.util.CharsetUtil;

public final class ChannelBuffers {
    public static final ByteOrder BIG_ENDIAN = ByteOrder.BIG_ENDIAN;
    public static final ChannelBuffer EMPTY_BUFFER = new EmptyChannelBuffer();
    private static final char[] HEXDUMP_TABLE = new char[1024];
    public static final ByteOrder LITTLE_ENDIAN = ByteOrder.LITTLE_ENDIAN;

    static {
        char[] DIGITS = "0123456789abcdef".toCharArray();
        for (int i = 0; i < 256; i++) {
            HEXDUMP_TABLE[i << 1] = DIGITS[(i >>> 4) & 15];
            HEXDUMP_TABLE[(i << 1) + 1] = DIGITS[i & 15];
        }
    }

    public static ChannelBuffer buffer(int capacity) {
        return buffer(BIG_ENDIAN, capacity);
    }

    public static ChannelBuffer buffer(ByteOrder endianness, int capacity) {
        if (endianness == BIG_ENDIAN) {
            if (capacity == 0) {
                return EMPTY_BUFFER;
            }
            return new BigEndianHeapChannelBuffer(capacity);
        } else if (endianness != LITTLE_ENDIAN) {
            throw new NullPointerException("endianness");
        } else if (capacity == 0) {
            return EMPTY_BUFFER;
        } else {
            return new LittleEndianHeapChannelBuffer(capacity);
        }
    }

    public static ChannelBuffer directBuffer(int capacity) {
        return directBuffer(BIG_ENDIAN, capacity);
    }

    public static ChannelBuffer directBuffer(ByteOrder endianness, int capacity) {
        if (endianness == null) {
            throw new NullPointerException("endianness");
        } else if (capacity == 0) {
            return EMPTY_BUFFER;
        } else {
            ChannelBuffer buffer = new ByteBufferBackedChannelBuffer(ByteBuffer.allocateDirect(capacity).order(endianness));
            buffer.clear();
            return buffer;
        }
    }

    public static ChannelBuffer dynamicBuffer() {
        return dynamicBuffer(BIG_ENDIAN, 256);
    }

    public static ChannelBuffer dynamicBuffer(ChannelBufferFactory factory) {
        if (factory != null) {
            return new DynamicChannelBuffer(factory.getDefaultOrder(), 256, factory);
        }
        throw new NullPointerException("factory");
    }

    public static ChannelBuffer dynamicBuffer(int estimatedLength) {
        return dynamicBuffer(BIG_ENDIAN, estimatedLength);
    }

    public static ChannelBuffer dynamicBuffer(ByteOrder endianness, int estimatedLength) {
        return new DynamicChannelBuffer(endianness, estimatedLength);
    }

    public static ChannelBuffer dynamicBuffer(int estimatedLength, ChannelBufferFactory factory) {
        if (factory != null) {
            return new DynamicChannelBuffer(factory.getDefaultOrder(), estimatedLength, factory);
        }
        throw new NullPointerException("factory");
    }

    public static ChannelBuffer dynamicBuffer(ByteOrder endianness, int estimatedLength, ChannelBufferFactory factory) {
        return new DynamicChannelBuffer(endianness, estimatedLength, factory);
    }

    public static ChannelBuffer wrappedBuffer(byte[] array) {
        return wrappedBuffer(BIG_ENDIAN, array);
    }

    public static ChannelBuffer wrappedBuffer(ByteOrder endianness, byte[] array) {
        if (endianness == BIG_ENDIAN) {
            if (array.length == 0) {
                return EMPTY_BUFFER;
            }
            return new BigEndianHeapChannelBuffer(array);
        } else if (endianness != LITTLE_ENDIAN) {
            throw new NullPointerException("endianness");
        } else if (array.length == 0) {
            return EMPTY_BUFFER;
        } else {
            return new LittleEndianHeapChannelBuffer(array);
        }
    }

    public static ChannelBuffer wrappedBuffer(byte[] array, int offset, int length) {
        return wrappedBuffer(BIG_ENDIAN, array, offset, length);
    }

    public static ChannelBuffer wrappedBuffer(ByteOrder endianness, byte[] array, int offset, int length) {
        if (endianness == null) {
            throw new NullPointerException("endianness");
        } else if (offset == 0) {
            if (length == array.length) {
                return wrappedBuffer(endianness, array);
            }
            if (length == 0) {
                return EMPTY_BUFFER;
            }
            return new TruncatedChannelBuffer(wrappedBuffer(endianness, array), length);
        } else if (length == 0) {
            return EMPTY_BUFFER;
        } else {
            return new SlicedChannelBuffer(wrappedBuffer(endianness, array), offset, length);
        }
    }

    public static ChannelBuffer wrappedBuffer(ByteBuffer buffer) {
        if (!buffer.hasRemaining()) {
            return EMPTY_BUFFER;
        }
        if (buffer.hasArray()) {
            return wrappedBuffer(buffer.order(), buffer.array(), buffer.arrayOffset() + buffer.position(), buffer.remaining());
        }
        return new ByteBufferBackedChannelBuffer(buffer);
    }

    public static ChannelBuffer wrappedBuffer(ChannelBuffer buffer) {
        if (buffer.readable()) {
            return buffer.slice();
        }
        return EMPTY_BUFFER;
    }

    public static ChannelBuffer wrappedBuffer(byte[]... arrays) {
        return wrappedBuffer(BIG_ENDIAN, arrays);
    }

    public static ChannelBuffer wrappedBuffer(ByteOrder endianness, byte[]... arrays) {
        byte[][] arr$;
        switch (arrays.length) {
            case 0:
                break;
            case 1:
                if (arrays[0].length != 0) {
                    return wrappedBuffer(endianness, arrays[0]);
                }
                break;
            default:
                List<ChannelBuffer> components = new ArrayList<>(arrays.length);
                for (byte[] a : arrays) {
                    if (a == null) {
                        return compositeBuffer(endianness, components, false);
                    }
                    if (a.length > 0) {
                        components.add(wrappedBuffer(endianness, a));
                    }
                }
                return compositeBuffer(endianness, components, false);
        }
        return EMPTY_BUFFER;
    }

    private static ChannelBuffer compositeBuffer(ByteOrder endianness, List<ChannelBuffer> components, boolean gathering) {
        switch (components.size()) {
            case 0:
                return EMPTY_BUFFER;
            case 1:
                return components.get(0);
            default:
                return new CompositeChannelBuffer(endianness, components, gathering);
        }
    }

    public static ChannelBuffer wrappedBuffer(ChannelBuffer... buffers) {
        return wrappedBuffer(false, buffers);
    }

    public static ChannelBuffer wrappedBuffer(boolean gathering, ChannelBuffer... buffers) {
        ChannelBuffer[] arr$;
        switch (buffers.length) {
            case 0:
                break;
            case 1:
                if (buffers[0].readable()) {
                    return wrappedBuffer(buffers[0]);
                }
                break;
            default:
                ByteOrder order = null;
                List<ChannelBuffer> components = new ArrayList<>(buffers.length);
                for (ChannelBuffer c : buffers) {
                    if (c == null) {
                        return compositeBuffer(order, components, gathering);
                    }
                    if (c.readable()) {
                        if (order == null) {
                            order = c.order();
                        } else if (!order.equals(c.order())) {
                            throw new IllegalArgumentException("inconsistent byte order");
                        }
                        if (c instanceof CompositeChannelBuffer) {
                            components.addAll(((CompositeChannelBuffer) c).decompose(c.readerIndex(), c.readableBytes()));
                        } else {
                            components.add(c.slice());
                        }
                    }
                }
                return compositeBuffer(order, components, gathering);
        }
        return EMPTY_BUFFER;
    }

    public static ChannelBuffer wrappedBuffer(ByteBuffer... buffers) {
        return wrappedBuffer(false, buffers);
    }

    public static ChannelBuffer wrappedBuffer(boolean gathering, ByteBuffer... buffers) {
        ByteBuffer[] arr$;
        switch (buffers.length) {
            case 0:
                break;
            case 1:
                if (buffers[0].hasRemaining()) {
                    return wrappedBuffer(buffers[0]);
                }
                break;
            default:
                ByteOrder order = null;
                List<ChannelBuffer> components = new ArrayList<>(buffers.length);
                for (ByteBuffer b : buffers) {
                    if (b == null) {
                        return compositeBuffer(order, components, gathering);
                    }
                    if (b.hasRemaining()) {
                        if (order == null) {
                            order = b.order();
                        } else if (!order.equals(b.order())) {
                            throw new IllegalArgumentException("inconsistent byte order");
                        }
                        components.add(wrappedBuffer(b));
                    }
                }
                return compositeBuffer(order, components, gathering);
        }
        return EMPTY_BUFFER;
    }

    public static ChannelBuffer copiedBuffer(byte[] array) {
        return copiedBuffer(BIG_ENDIAN, array);
    }

    public static ChannelBuffer copiedBuffer(ByteOrder endianness, byte[] array) {
        if (endianness == BIG_ENDIAN) {
            if (array.length == 0) {
                return EMPTY_BUFFER;
            }
            return new BigEndianHeapChannelBuffer((byte[]) array.clone());
        } else if (endianness != LITTLE_ENDIAN) {
            throw new NullPointerException("endianness");
        } else if (array.length == 0) {
            return EMPTY_BUFFER;
        } else {
            return new LittleEndianHeapChannelBuffer((byte[]) array.clone());
        }
    }

    public static ChannelBuffer copiedBuffer(byte[] array, int offset, int length) {
        return copiedBuffer(BIG_ENDIAN, array, offset, length);
    }

    public static ChannelBuffer copiedBuffer(ByteOrder endianness, byte[] array, int offset, int length) {
        if (endianness == null) {
            throw new NullPointerException("endianness");
        } else if (length == 0) {
            return EMPTY_BUFFER;
        } else {
            byte[] copy = new byte[length];
            System.arraycopy(array, offset, copy, 0, length);
            return wrappedBuffer(endianness, copy);
        }
    }

    /* JADX INFO: finally extract failed */
    public static ChannelBuffer copiedBuffer(ByteBuffer buffer) {
        int length = buffer.remaining();
        if (length == 0) {
            return EMPTY_BUFFER;
        }
        byte[] copy = new byte[length];
        int position = buffer.position();
        try {
            buffer.get(copy);
            buffer.position(position);
            return wrappedBuffer(buffer.order(), copy);
        } catch (Throwable th) {
            buffer.position(position);
            throw th;
        }
    }

    public static ChannelBuffer copiedBuffer(ChannelBuffer buffer) {
        if (buffer.readable()) {
            return buffer.copy();
        }
        return EMPTY_BUFFER;
    }

    public static ChannelBuffer copiedBuffer(byte[]... arrays) {
        return copiedBuffer(BIG_ENDIAN, arrays);
    }

    public static ChannelBuffer copiedBuffer(ByteOrder endianness, byte[]... arrays) {
        byte[][] arr$;
        switch (arrays.length) {
            case 0:
                return EMPTY_BUFFER;
            case 1:
                if (arrays[0].length == 0) {
                    return EMPTY_BUFFER;
                }
                return copiedBuffer(endianness, arrays[0]);
            default:
                int length = 0;
                for (byte[] a : arrays) {
                    if (ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED - length < a.length) {
                        throw new IllegalArgumentException("The total length of the specified arrays is too big.");
                    }
                    length += a.length;
                }
                if (length == 0) {
                    return EMPTY_BUFFER;
                }
                byte[] mergedArray = new byte[length];
                int j = 0;
                for (byte[] a2 : arrays) {
                    System.arraycopy(a2, 0, mergedArray, j, a2.length);
                    j += a2.length;
                }
                return wrappedBuffer(endianness, mergedArray);
        }
    }

    public static ChannelBuffer copiedBuffer(ChannelBuffer... buffers) {
        switch (buffers.length) {
            case 0:
                return EMPTY_BUFFER;
            case 1:
                return copiedBuffer(buffers[0]);
            default:
                ChannelBuffer[] copiedBuffers = new ChannelBuffer[buffers.length];
                for (int i = 0; i < buffers.length; i++) {
                    copiedBuffers[i] = copiedBuffer(buffers[i]);
                }
                return wrappedBuffer(false, copiedBuffers);
        }
    }

    public static ChannelBuffer copiedBuffer(ByteBuffer... buffers) {
        switch (buffers.length) {
            case 0:
                return EMPTY_BUFFER;
            case 1:
                return copiedBuffer(buffers[0]);
            default:
                ChannelBuffer[] copiedBuffers = new ChannelBuffer[buffers.length];
                for (int i = 0; i < buffers.length; i++) {
                    copiedBuffers[i] = copiedBuffer(buffers[i]);
                }
                return wrappedBuffer(false, copiedBuffers);
        }
    }

    public static ChannelBuffer copiedBuffer(CharSequence string, Charset charset) {
        return copiedBuffer(BIG_ENDIAN, string, charset);
    }

    public static ChannelBuffer copiedBuffer(CharSequence string, int offset, int length, Charset charset) {
        return copiedBuffer(BIG_ENDIAN, string, offset, length, charset);
    }

    public static ChannelBuffer copiedBuffer(ByteOrder endianness, CharSequence string, Charset charset) {
        if (string == null) {
            throw new NullPointerException("string");
        } else if (string instanceof CharBuffer) {
            return copiedBuffer(endianness, (CharBuffer) string, charset);
        } else {
            return copiedBuffer(endianness, CharBuffer.wrap(string), charset);
        }
    }

    public static ChannelBuffer copiedBuffer(ByteOrder endianness, CharSequence string, int offset, int length, Charset charset) {
        if (string == null) {
            throw new NullPointerException("string");
        } else if (length == 0) {
            return EMPTY_BUFFER;
        } else {
            if (!(string instanceof CharBuffer)) {
                return copiedBuffer(endianness, CharBuffer.wrap(string, offset, offset + length), charset);
            }
            CharBuffer buf = (CharBuffer) string;
            if (buf.hasArray()) {
                return copiedBuffer(endianness, buf.array(), buf.arrayOffset() + buf.position() + offset, length, charset);
            }
            CharBuffer buf2 = buf.slice();
            buf2.limit(length);
            buf2.position(offset);
            return copiedBuffer(endianness, buf2, charset);
        }
    }

    public static ChannelBuffer copiedBuffer(char[] array, Charset charset) {
        return copiedBuffer(BIG_ENDIAN, array, 0, array.length, charset);
    }

    public static ChannelBuffer copiedBuffer(char[] array, int offset, int length, Charset charset) {
        return copiedBuffer(BIG_ENDIAN, array, offset, length, charset);
    }

    public static ChannelBuffer copiedBuffer(ByteOrder endianness, char[] array, Charset charset) {
        return copiedBuffer(endianness, array, 0, array.length, charset);
    }

    public static ChannelBuffer copiedBuffer(ByteOrder endianness, char[] array, int offset, int length, Charset charset) {
        if (array == null) {
            throw new NullPointerException("array");
        } else if (length == 0) {
            return EMPTY_BUFFER;
        } else {
            return copiedBuffer(endianness, CharBuffer.wrap(array, offset, length), charset);
        }
    }

    private static ChannelBuffer copiedBuffer(ByteOrder endianness, CharBuffer buffer, Charset charset) {
        ByteBuffer dst = encodeString(buffer, charset);
        ChannelBuffer result = wrappedBuffer(endianness, dst.array());
        result.writerIndex(dst.remaining());
        return result;
    }

    @Deprecated
    public static ChannelBuffer copiedBuffer(String string, String charsetName) {
        return copiedBuffer((CharSequence) string, Charset.forName(charsetName));
    }

    @Deprecated
    public static ChannelBuffer copiedBuffer(ByteOrder endianness, String string, String charsetName) {
        return copiedBuffer(endianness, (CharSequence) string, Charset.forName(charsetName));
    }

    public static ChannelBuffer unmodifiableBuffer(ChannelBuffer buffer) {
        if (buffer instanceof ReadOnlyChannelBuffer) {
            buffer = ((ReadOnlyChannelBuffer) buffer).unwrap();
        }
        return new ReadOnlyChannelBuffer(buffer);
    }

    public static ChannelBuffer hexDump(String hexString) {
        int len = hexString.length();
        byte[] hexData = new byte[(len / 2)];
        for (int i = 0; i < len; i += 2) {
            hexData[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4) + Character.digit(hexString.charAt(i + 1), 16));
        }
        return wrappedBuffer(hexData);
    }

    public static String hexDump(ChannelBuffer buffer) {
        return hexDump(buffer, buffer.readerIndex(), buffer.readableBytes());
    }

    public static String hexDump(ChannelBuffer buffer, int fromIndex, int length) {
        if (length < 0) {
            throw new IllegalArgumentException("length: " + length);
        } else if (length == 0) {
            return "";
        } else {
            int endIndex = fromIndex + length;
            char[] buf = new char[(length << 1)];
            int srcIdx = fromIndex;
            int dstIdx = 0;
            while (srcIdx < endIndex) {
                System.arraycopy(HEXDUMP_TABLE, buffer.getUnsignedByte(srcIdx) << 1, buf, dstIdx, 2);
                srcIdx++;
                dstIdx += 2;
            }
            return new String(buf);
        }
    }

    public static int hashCode(ChannelBuffer buffer) {
        int aLen = buffer.readableBytes();
        int intCount = aLen >>> 2;
        int byteCount = aLen & 3;
        int hashCode = 1;
        int arrayIndex = buffer.readerIndex();
        if (buffer.order() == BIG_ENDIAN) {
            for (int i = intCount; i > 0; i--) {
                hashCode = (hashCode * 31) + buffer.getInt(arrayIndex);
                arrayIndex += 4;
            }
        } else {
            for (int i2 = intCount; i2 > 0; i2--) {
                hashCode = (hashCode * 31) + swapInt(buffer.getInt(arrayIndex));
                arrayIndex += 4;
            }
        }
        int i3 = byteCount;
        int arrayIndex2 = arrayIndex;
        while (i3 > 0) {
            hashCode = (hashCode * 31) + buffer.getByte(arrayIndex2);
            i3--;
            arrayIndex2++;
        }
        if (hashCode == 0) {
            return 1;
        }
        return hashCode;
    }

    public static boolean equals(ChannelBuffer bufferA, ChannelBuffer bufferB) {
        int aLen = bufferA.readableBytes();
        if (aLen != bufferB.readableBytes()) {
            return false;
        }
        int longCount = aLen >>> 3;
        int byteCount = aLen & 7;
        int aIndex = bufferA.readerIndex();
        int bIndex = bufferB.readerIndex();
        if (bufferA.order() == bufferB.order()) {
            for (int i = longCount; i > 0; i--) {
                if (bufferA.getLong(aIndex) != bufferB.getLong(bIndex)) {
                    return false;
                }
                aIndex += 8;
                bIndex += 8;
            }
        } else {
            for (int i2 = longCount; i2 > 0; i2--) {
                if (bufferA.getLong(aIndex) != swapLong(bufferB.getLong(bIndex))) {
                    return false;
                }
                aIndex += 8;
                bIndex += 8;
            }
        }
        for (int i3 = byteCount; i3 > 0; i3--) {
            if (bufferA.getByte(aIndex) != bufferB.getByte(bIndex)) {
                return false;
            }
            aIndex++;
            bIndex++;
        }
        return true;
    }

    public static int compare(ChannelBuffer bufferA, ChannelBuffer bufferB) {
        int aLen = bufferA.readableBytes();
        int bLen = bufferB.readableBytes();
        int minLength = Math.min(aLen, bLen);
        int uintCount = minLength >>> 2;
        int byteCount = minLength & 3;
        int aIndex = bufferA.readerIndex();
        int bIndex = bufferB.readerIndex();
        if (bufferA.order() == bufferB.order()) {
            for (int i = uintCount; i > 0; i--) {
                long va = bufferA.getUnsignedInt(aIndex);
                long vb = bufferB.getUnsignedInt(bIndex);
                if (va > vb) {
                    return 1;
                }
                if (va < vb) {
                    return -1;
                }
                aIndex += 4;
                bIndex += 4;
            }
        } else {
            for (int i2 = uintCount; i2 > 0; i2--) {
                long va2 = bufferA.getUnsignedInt(aIndex);
                long vb2 = ((long) swapInt(bufferB.getInt(bIndex))) & 4294967295L;
                if (va2 > vb2) {
                    return 1;
                }
                if (va2 < vb2) {
                    return -1;
                }
                aIndex += 4;
                bIndex += 4;
            }
        }
        for (int i3 = byteCount; i3 > 0; i3--) {
            short va3 = bufferA.getUnsignedByte(aIndex);
            short vb3 = bufferB.getUnsignedByte(bIndex);
            if (va3 > vb3) {
                return 1;
            }
            if (va3 < vb3) {
                return -1;
            }
            aIndex++;
            bIndex++;
        }
        return aLen - bLen;
    }

    public static int indexOf(ChannelBuffer buffer, int fromIndex, int toIndex, byte value) {
        if (fromIndex <= toIndex) {
            return firstIndexOf(buffer, fromIndex, toIndex, value);
        }
        return lastIndexOf(buffer, fromIndex, toIndex, value);
    }

    public static int indexOf(ChannelBuffer buffer, int fromIndex, int toIndex, ChannelBufferIndexFinder indexFinder) {
        if (fromIndex <= toIndex) {
            return firstIndexOf(buffer, fromIndex, toIndex, indexFinder);
        }
        return lastIndexOf(buffer, fromIndex, toIndex, indexFinder);
    }

    public static short swapShort(short value) {
        return (short) ((value << 8) | ((value >>> 8) & 255));
    }

    public static int swapMedium(int value) {
        return ((value << 16) & 16711680) | (65280 & value) | ((value >>> 16) & 255);
    }

    public static int swapInt(int value) {
        return (swapShort((short) value) << 16) | (swapShort((short) (value >>> 16)) & 65535);
    }

    public static long swapLong(long value) {
        return (((long) swapInt((int) value)) << 32) | (((long) swapInt((int) (value >>> 32))) & 4294967295L);
    }

    private static int firstIndexOf(ChannelBuffer buffer, int fromIndex, int toIndex, byte value) {
        int fromIndex2 = Math.max(fromIndex, 0);
        if (fromIndex2 >= toIndex || buffer.capacity() == 0) {
            return -1;
        }
        for (int i = fromIndex2; i < toIndex; i++) {
            if (buffer.getByte(i) == value) {
                return i;
            }
        }
        return -1;
    }

    private static int lastIndexOf(ChannelBuffer buffer, int fromIndex, int toIndex, byte value) {
        int fromIndex2 = Math.min(fromIndex, buffer.capacity());
        if (fromIndex2 < 0 || buffer.capacity() == 0) {
            return -1;
        }
        for (int i = fromIndex2 - 1; i >= toIndex; i--) {
            if (buffer.getByte(i) == value) {
                return i;
            }
        }
        return -1;
    }

    private static int firstIndexOf(ChannelBuffer buffer, int fromIndex, int toIndex, ChannelBufferIndexFinder indexFinder) {
        int fromIndex2 = Math.max(fromIndex, 0);
        if (fromIndex2 >= toIndex || buffer.capacity() == 0) {
            return -1;
        }
        for (int i = fromIndex2; i < toIndex; i++) {
            if (indexFinder.find(buffer, i)) {
                return i;
            }
        }
        return -1;
    }

    private static int lastIndexOf(ChannelBuffer buffer, int fromIndex, int toIndex, ChannelBufferIndexFinder indexFinder) {
        int fromIndex2 = Math.min(fromIndex, buffer.capacity());
        if (fromIndex2 < 0 || buffer.capacity() == 0) {
            return -1;
        }
        for (int i = fromIndex2 - 1; i >= toIndex; i--) {
            if (indexFinder.find(buffer, i)) {
                return i;
            }
        }
        return -1;
    }

    static ByteBuffer encodeString(CharBuffer src, Charset charset) {
        CharsetEncoder encoder = CharsetUtil.getEncoder(charset);
        ByteBuffer dst = ByteBuffer.allocate((int) (((double) src.remaining()) * ((double) encoder.maxBytesPerChar())));
        try {
            CoderResult cr = encoder.encode(src, dst, true);
            if (!cr.isUnderflow()) {
                cr.throwException();
            }
            CoderResult cr2 = encoder.flush(dst);
            if (!cr2.isUnderflow()) {
                cr2.throwException();
            }
            dst.flip();
            return dst;
        } catch (CharacterCodingException x) {
            throw new IllegalStateException(x);
        }
    }

    static String decodeString(ByteBuffer src, Charset charset) {
        CharsetDecoder decoder = CharsetUtil.getDecoder(charset);
        CharBuffer dst = CharBuffer.allocate((int) (((double) src.remaining()) * ((double) decoder.maxCharsPerByte())));
        try {
            CoderResult cr = decoder.decode(src, dst, true);
            if (!cr.isUnderflow()) {
                cr.throwException();
            }
            CoderResult cr2 = decoder.flush(dst);
            if (!cr2.isUnderflow()) {
                cr2.throwException();
            }
            return dst.flip().toString();
        } catch (CharacterCodingException x) {
            throw new IllegalStateException(x);
        }
    }

    private ChannelBuffers() {
    }
}