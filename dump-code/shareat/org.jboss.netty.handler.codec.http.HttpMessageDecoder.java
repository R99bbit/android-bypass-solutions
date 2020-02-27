package org.jboss.netty.handler.codec.http;

import java.util.List;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.frame.TooLongFrameException;
import org.jboss.netty.handler.codec.http.HttpHeaders.Names;
import org.jboss.netty.handler.codec.replay.ReplayingDecoder;

public abstract class HttpMessageDecoder extends ReplayingDecoder<State> {
    static final /* synthetic */ boolean $assertionsDisabled = (!HttpMessageDecoder.class.desiredAssertionStatus());
    private long chunkSize;
    private ChannelBuffer content;
    private int contentRead;
    private int headerSize;
    private final int maxChunkSize;
    private final int maxHeaderSize;
    private final int maxInitialLineLength;
    private HttpMessage message;

    protected enum State {
        SKIP_CONTROL_CHARS,
        READ_INITIAL,
        READ_HEADER,
        READ_VARIABLE_LENGTH_CONTENT,
        READ_VARIABLE_LENGTH_CONTENT_AS_CHUNKS,
        READ_FIXED_LENGTH_CONTENT,
        READ_FIXED_LENGTH_CONTENT_AS_CHUNKS,
        READ_CHUNK_SIZE,
        READ_CHUNKED_CONTENT,
        READ_CHUNKED_CONTENT_AS_CHUNKS,
        READ_CHUNK_DELIMITER,
        READ_CHUNK_FOOTER
    }

    /* access modifiers changed from: protected */
    public abstract HttpMessage createMessage(String[] strArr) throws Exception;

    /* access modifiers changed from: protected */
    public abstract boolean isDecodingRequest();

    protected HttpMessageDecoder() {
        this(4096, 8192, 8192);
    }

    protected HttpMessageDecoder(int maxInitialLineLength2, int maxHeaderSize2, int maxChunkSize2) {
        super(State.SKIP_CONTROL_CHARS, true);
        if (maxInitialLineLength2 <= 0) {
            throw new IllegalArgumentException("maxInitialLineLength must be a positive integer: " + maxInitialLineLength2);
        } else if (maxHeaderSize2 <= 0) {
            throw new IllegalArgumentException("maxHeaderSize must be a positive integer: " + maxHeaderSize2);
        } else if (maxChunkSize2 < 0) {
            throw new IllegalArgumentException("maxChunkSize must be a positive integer: " + maxChunkSize2);
        } else {
            this.maxInitialLineLength = maxInitialLineLength2;
            this.maxHeaderSize = maxHeaderSize2;
            this.maxChunkSize = maxChunkSize2;
        }
    }

    /* access modifiers changed from: protected */
    /* JADX WARNING: Code restructure failed: missing block: B:112:0x02c9, code lost:
        r9 = r21.readByte();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:113:0x02cf, code lost:
        if (r9 != 13) goto L_0x02e5;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:115:0x02d7, code lost:
        if (r21.readByte() != 10) goto L_0x02c9;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:116:0x02d9, code lost:
        checkpoint(org.jboss.netty.handler.codec.http.HttpMessageDecoder.State.READ_CHUNK_SIZE);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:119:0x02e7, code lost:
        if (r9 != 10) goto L_0x02c9;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:120:0x02e9, code lost:
        checkpoint(org.jboss.netty.handler.codec.http.HttpMessageDecoder.State.READ_CHUNK_SIZE);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:131:?, code lost:
        return null;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:132:?, code lost:
        return r18.message;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:133:?, code lost:
        return r18.message;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:134:?, code lost:
        return reset();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:135:?, code lost:
        return r18.message;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:136:?, code lost:
        return r18.message;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:137:?, code lost:
        return null;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:13:0x0041, code lost:
        r18.message = createMessage(r3);
        checkpoint(org.jboss.netty.handler.codec.http.HttpMessageDecoder.State.READ_HEADER);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:149:?, code lost:
        return r2;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:14:0x0052, code lost:
        r10 = readHeaders(r21);
        checkpoint(r10);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:152:?, code lost:
        return null;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:153:?, code lost:
        return null;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:15:0x0061, code lost:
        if (r10 != org.jboss.netty.handler.codec.http.HttpMessageDecoder.State.READ_CHUNK_SIZE) goto L_0x0070;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:16:0x0063, code lost:
        r18.message.setChunked(true);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:18:0x0072, code lost:
        if (r10 != org.jboss.netty.handler.codec.http.HttpMessageDecoder.State.SKIP_CONTROL_CHARS) goto L_0x0087;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:19:0x0074, code lost:
        r18.message.headers().remove(org.jboss.netty.handler.codec.http.HttpHeaders.Names.TRANSFER_ENCODING);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:20:0x0087, code lost:
        r6 = org.jboss.netty.handler.codec.http.HttpHeaders.getContentLength(r18.message, -1);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:21:0x0097, code lost:
        if (r6 == 0) goto L_0x00a5;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:23:0x009d, code lost:
        if (r6 != -1) goto L_0x00b0;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:25:0x00a3, code lost:
        if (isDecodingRequest() == false) goto L_0x00b0;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:26:0x00a5, code lost:
        r18.content = org.jboss.netty.buffer.ChannelBuffers.EMPTY_BUFFER;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:28:0x00b8, code lost:
        switch(r10) {
            case org.jboss.netty.handler.codec.http.HttpMessageDecoder.State.READ_FIXED_LENGTH_CONTENT :org.jboss.netty.handler.codec.http.HttpMessageDecoder$State: goto L_0x00d5;
            case org.jboss.netty.handler.codec.http.HttpMessageDecoder.State.READ_VARIABLE_LENGTH_CONTENT :org.jboss.netty.handler.codec.http.HttpMessageDecoder$State: goto L_0x010d;
            default: goto L_0x00bb;
        };
     */
    /* JADX WARNING: Code restructure failed: missing block: B:30:0x00d4, code lost:
        throw new java.lang.IllegalStateException("Unexpected state: " + r10);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:32:0x00dc, code lost:
        if (r6 > ((long) r18.maxChunkSize)) goto L_0x00e8;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:34:0x00e6, code lost:
        if (org.jboss.netty.handler.codec.http.HttpHeaders.is100ContinueExpected(r18.message) == false) goto L_0x0136;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:35:0x00e8, code lost:
        checkpoint(org.jboss.netty.handler.codec.http.HttpMessageDecoder.State.READ_FIXED_LENGTH_CONTENT_AS_CHUNKS);
        r18.message.setChunked(true);
        r18.chunkSize = org.jboss.netty.handler.codec.http.HttpHeaders.getContentLength(r18.message, -1);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:37:0x0115, code lost:
        if (r21.readableBytes() > r18.maxChunkSize) goto L_0x0121;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:39:0x011f, code lost:
        if (org.jboss.netty.handler.codec.http.HttpHeaders.is100ContinueExpected(r18.message) == false) goto L_0x0136;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:40:0x0121, code lost:
        checkpoint(org.jboss.netty.handler.codec.http.HttpMessageDecoder.State.READ_VARIABLE_LENGTH_CONTENT_AS_CHUNKS);
        r18.message.setChunked(true);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:7:0x0021, code lost:
        r3 = splitInitialLine(readLine(r21, r18.maxInitialLineLength));
     */
    /* JADX WARNING: Code restructure failed: missing block: B:83:0x0242, code lost:
        if ($assertionsDisabled != false) goto L_0x025d;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:85:0x024d, code lost:
        if (r18.chunkSize <= 2147483647L) goto L_0x025d;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:87:0x0254, code lost:
        throw new java.lang.AssertionError();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:89:0x025d, code lost:
        r2 = new org.jboss.netty.handler.codec.http.DefaultHttpChunk(r21.readBytes((int) r18.chunkSize));
        checkpoint(org.jboss.netty.handler.codec.http.HttpMessageDecoder.State.READ_CHUNK_DELIMITER);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:8:0x0031, code lost:
        if (r3.length >= 3) goto L_0x0041;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:9:0x0033, code lost:
        checkpoint(org.jboss.netty.handler.codec.http.HttpMessageDecoder.State.SKIP_CONTROL_CHARS);
     */
    public Object decode(ChannelHandlerContext ctx, Channel channel, ChannelBuffer buffer, State state) throws Exception {
        int chunkSize2;
        long chunkSize3;
        switch (state) {
            case READ_FIXED_LENGTH_CONTENT:
                return readFixedLengthContent(buffer);
            case READ_VARIABLE_LENGTH_CONTENT:
                int toRead = actualReadableBytes();
                if (toRead > this.maxChunkSize) {
                    toRead = this.maxChunkSize;
                }
                if (this.message.isChunked()) {
                    return new DefaultHttpChunk(buffer.readBytes(toRead));
                }
                this.message.setChunked(true);
                return new Object[]{this.message, new DefaultHttpChunk(buffer.readBytes(toRead))};
            case SKIP_CONTROL_CHARS:
                try {
                    skipControlCharacters(buffer);
                    checkpoint(State.READ_INITIAL);
                    break;
                } finally {
                    checkpoint();
                }
            case READ_INITIAL:
                break;
            case READ_HEADER:
                break;
            case READ_VARIABLE_LENGTH_CONTENT_AS_CHUNKS:
                int toRead2 = actualReadableBytes();
                if (toRead2 > this.maxChunkSize) {
                    toRead2 = this.maxChunkSize;
                }
                HttpChunk chunk = new DefaultHttpChunk(buffer.readBytes(toRead2));
                if (buffer.readable()) {
                    return chunk;
                }
                reset();
                if (chunk.isLast()) {
                    return chunk;
                }
                return new Object[]{chunk, HttpChunk.LAST_CHUNK};
            case READ_FIXED_LENGTH_CONTENT_AS_CHUNKS:
                long chunkSize4 = this.chunkSize;
                int readLimit = actualReadableBytes();
                if (readLimit == 0) {
                    return null;
                }
                int toRead3 = readLimit;
                if (toRead3 > this.maxChunkSize) {
                    toRead3 = this.maxChunkSize;
                }
                if (((long) toRead3) > chunkSize4) {
                    toRead3 = (int) chunkSize4;
                }
                HttpChunk chunk2 = new DefaultHttpChunk(buffer.readBytes(toRead3));
                if (chunkSize4 > ((long) toRead3)) {
                    chunkSize3 = chunkSize4 - ((long) toRead3);
                } else {
                    chunkSize3 = 0;
                }
                this.chunkSize = chunkSize3;
                if (chunkSize3 != 0) {
                    return chunk2;
                }
                reset();
                if (chunk2.isLast()) {
                    return chunk2;
                }
                return new Object[]{chunk2, HttpChunk.LAST_CHUNK};
            case READ_CHUNK_SIZE:
                int chunkSize5 = getChunkSize(readLine(buffer, this.maxInitialLineLength));
                this.chunkSize = (long) chunkSize5;
                if (chunkSize5 != 0) {
                    if (chunkSize5 <= this.maxChunkSize) {
                        checkpoint(State.READ_CHUNKED_CONTENT);
                        break;
                    } else {
                        checkpoint(State.READ_CHUNKED_CONTENT_AS_CHUNKS);
                        break;
                    }
                } else {
                    checkpoint(State.READ_CHUNK_FOOTER);
                    return null;
                }
            case READ_CHUNKED_CONTENT:
                break;
            case READ_CHUNKED_CONTENT_AS_CHUNKS:
                if ($assertionsDisabled || this.chunkSize <= 2147483647L) {
                    int chunkSize6 = (int) this.chunkSize;
                    int readLimit2 = actualReadableBytes();
                    if (readLimit2 == 0) {
                        return null;
                    }
                    int toRead4 = chunkSize6;
                    if (toRead4 > this.maxChunkSize) {
                        toRead4 = this.maxChunkSize;
                    }
                    if (toRead4 > readLimit2) {
                        toRead4 = readLimit2;
                    }
                    HttpChunk chunk3 = new DefaultHttpChunk(buffer.readBytes(toRead4));
                    if (chunkSize6 > toRead4) {
                        chunkSize2 = chunkSize6 - toRead4;
                    } else {
                        chunkSize2 = 0;
                    }
                    this.chunkSize = (long) chunkSize2;
                    if (chunkSize2 == 0) {
                        checkpoint(State.READ_CHUNK_DELIMITER);
                    }
                    if (!chunk3.isLast()) {
                        return chunk3;
                    }
                } else {
                    throw new AssertionError();
                }
                break;
            case READ_CHUNK_DELIMITER:
                break;
            case READ_CHUNK_FOOTER:
                HttpChunkTrailer trailer = readTrailingHeaders(buffer);
                if (this.maxChunkSize == 0) {
                    return reset();
                }
                reset();
                return trailer;
            default:
                throw new Error("Shouldn't reach here.");
        }
    }

    /* access modifiers changed from: protected */
    public boolean isContentAlwaysEmpty(HttpMessage msg) {
        if (!(msg instanceof HttpResponse)) {
            return false;
        }
        HttpResponse res = (HttpResponse) msg;
        int code = res.getStatus().getCode();
        if (code < 100 || code >= 200) {
            switch (code) {
                case 204:
                case 205:
                case 304:
                    return true;
                default:
                    return false;
            }
        } else if (code != 101 || res.headers().contains(Names.SEC_WEBSOCKET_ACCEPT)) {
            return true;
        } else {
            return false;
        }
    }

    private Object reset() {
        HttpMessage message2 = this.message;
        ChannelBuffer content2 = this.content;
        if (content2 != null) {
            message2.setContent(content2);
            this.content = null;
        }
        this.message = null;
        checkpoint(State.SKIP_CONTROL_CHARS);
        return message2;
    }

    private static void skipControlCharacters(ChannelBuffer buffer) {
        while (true) {
            char c = (char) buffer.readUnsignedByte();
            if (!Character.isISOControl(c) && !Character.isWhitespace(c)) {
                buffer.readerIndex(buffer.readerIndex() - 1);
                return;
            }
        }
    }

    private Object readFixedLengthContent(ChannelBuffer buffer) {
        long length = HttpHeaders.getContentLength(this.message, -1);
        if ($assertionsDisabled || length <= 2147483647L) {
            int toRead = ((int) length) - this.contentRead;
            if (toRead > actualReadableBytes()) {
                toRead = actualReadableBytes();
            }
            this.contentRead += toRead;
            if (length >= ((long) this.contentRead)) {
                if (this.content == null) {
                    this.content = buffer.readBytes((int) length);
                } else {
                    this.content.writeBytes(buffer, (int) length);
                }
                return reset();
            } else if (this.message.isChunked()) {
                return new DefaultHttpChunk(buffer.readBytes(toRead));
            } else {
                this.message.setChunked(true);
                return new Object[]{this.message, new DefaultHttpChunk(buffer.readBytes(toRead))};
            }
        } else {
            throw new AssertionError();
        }
    }

    private State readHeaders(ChannelBuffer buffer) throws TooLongFrameException {
        this.headerSize = 0;
        HttpMessage message2 = this.message;
        String line = readHeader(buffer);
        String name = null;
        String value = null;
        if (line.length() != 0) {
            message2.headers().clear();
            do {
                char firstChar = line.charAt(0);
                if (name == null || !(firstChar == ' ' || firstChar == 9)) {
                    if (name != null) {
                        message2.headers().add(name, (Object) value);
                    }
                    String[] header = splitHeader(line);
                    name = header[0];
                    value = header[1];
                } else {
                    value = value + ' ' + line.trim();
                }
                line = readHeader(buffer);
            } while (line.length() != 0);
            if (name != null) {
                message2.headers().add(name, (Object) value);
            }
        }
        if (isContentAlwaysEmpty(message2)) {
            return State.SKIP_CONTROL_CHARS;
        }
        if (message2.isChunked()) {
            return State.READ_CHUNK_SIZE;
        }
        if (HttpHeaders.getContentLength(message2, -1) >= 0) {
            return State.READ_FIXED_LENGTH_CONTENT;
        }
        return State.READ_VARIABLE_LENGTH_CONTENT;
    }

    private HttpChunkTrailer readTrailingHeaders(ChannelBuffer buffer) throws TooLongFrameException {
        this.headerSize = 0;
        String line = readHeader(buffer);
        String lastHeader = null;
        if (line.length() == 0) {
            return HttpChunk.LAST_CHUNK;
        }
        HttpChunkTrailer trailer = new DefaultHttpChunkTrailer();
        do {
            char firstChar = line.charAt(0);
            if (lastHeader == null || !(firstChar == ' ' || firstChar == 9)) {
                String[] header = splitHeader(line);
                String name = header[0];
                if (!name.equalsIgnoreCase("Content-Length") && !name.equalsIgnoreCase(Names.TRANSFER_ENCODING) && !name.equalsIgnoreCase(Names.TRAILER)) {
                    trailer.trailingHeaders().add(name, (Object) header[1]);
                }
                lastHeader = name;
            } else {
                List<String> current = trailer.trailingHeaders().getAll(lastHeader);
                if (!current.isEmpty()) {
                    int lastPos = current.size() - 1;
                    current.set(lastPos, current.get(lastPos) + line.trim());
                }
            }
            line = readHeader(buffer);
        } while (line.length() != 0);
        return trailer;
    }

    /* JADX WARNING: Code restructure failed: missing block: B:4:0x0015, code lost:
        if (r0 < r6.maxHeaderSize) goto L_0x004c;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:6:0x0039, code lost:
        throw new org.jboss.netty.handler.codec.frame.TooLongFrameException("HTTP header is larger than " + r6.maxHeaderSize + " bytes.");
     */
    private String readHeader(ChannelBuffer buffer) throws TooLongFrameException {
        StringBuilder sb = new StringBuilder(64);
        int headerSize2 = this.headerSize;
        while (true) {
            char nextByte = (char) buffer.readByte();
            headerSize2++;
            switch (nextByte) {
                case 10:
                    break;
                case 13:
                    nextByte = (char) buffer.readByte();
                    headerSize2++;
                    if (nextByte == 10) {
                        break;
                    }
                    break;
            }
            sb.append(nextByte);
        }
        this.headerSize = headerSize2;
        return sb.toString();
    }

    private static int getChunkSize(String hex) {
        String hex2 = hex.trim();
        int i = 0;
        while (true) {
            if (i >= hex2.length()) {
                break;
            }
            char c = hex2.charAt(i);
            if (c == ';' || Character.isWhitespace(c) || Character.isISOControl(c)) {
                hex2 = hex2.substring(0, i);
            } else {
                i++;
            }
        }
        hex2 = hex2.substring(0, i);
        return Integer.parseInt(hex2, 16);
    }

    private static String readLine(ChannelBuffer buffer, int maxLineLength) throws TooLongFrameException {
        StringBuilder sb = new StringBuilder(64);
        int lineLength = 0;
        while (true) {
            byte nextByte = buffer.readByte();
            if (nextByte == 13) {
                if (buffer.readByte() == 10) {
                    return sb.toString();
                }
            } else if (nextByte == 10) {
                return sb.toString();
            } else {
                if (lineLength >= maxLineLength) {
                    throw new TooLongFrameException("An HTTP line is larger than " + maxLineLength + " bytes.");
                }
                lineLength++;
                sb.append((char) nextByte);
            }
        }
    }

    private static String[] splitInitialLine(String sb) {
        int aStart = findNonWhitespace(sb, 0);
        int aEnd = findWhitespace(sb, aStart);
        int bStart = findNonWhitespace(sb, aEnd);
        int bEnd = findWhitespace(sb, bStart);
        int cStart = findNonWhitespace(sb, bEnd);
        int cEnd = findEndOfString(sb);
        String[] strArr = new String[3];
        strArr[0] = sb.substring(aStart, aEnd);
        strArr[1] = sb.substring(bStart, bEnd);
        strArr[2] = cStart < cEnd ? sb.substring(cStart, cEnd) : "";
        return strArr;
    }

    private static String[] splitHeader(String sb) {
        int length = sb.length();
        int nameStart = findNonWhitespace(sb, 0);
        int nameEnd = nameStart;
        while (nameEnd < length) {
            char ch = sb.charAt(nameEnd);
            if (ch == ':' || Character.isWhitespace(ch)) {
                break;
            }
            nameEnd++;
        }
        int colonEnd = nameEnd;
        while (true) {
            if (colonEnd >= length) {
                break;
            } else if (sb.charAt(colonEnd) == ':') {
                colonEnd++;
                break;
            } else {
                colonEnd++;
            }
        }
        int valueStart = findNonWhitespace(sb, colonEnd);
        if (valueStart == length) {
            return new String[]{sb.substring(nameStart, nameEnd), ""};
        }
        return new String[]{sb.substring(nameStart, nameEnd), sb.substring(valueStart, findEndOfString(sb))};
    }

    private static int findNonWhitespace(String sb, int offset) {
        int result = offset;
        while (result < sb.length() && Character.isWhitespace(sb.charAt(result))) {
            result++;
        }
        return result;
    }

    private static int findWhitespace(String sb, int offset) {
        int result = offset;
        while (result < sb.length() && !Character.isWhitespace(sb.charAt(result))) {
            result++;
        }
        return result;
    }

    private static int findEndOfString(String sb) {
        int result = sb.length();
        while (result > 0 && Character.isWhitespace(sb.charAt(result - 1))) {
            result--;
        }
        return result;
    }
}