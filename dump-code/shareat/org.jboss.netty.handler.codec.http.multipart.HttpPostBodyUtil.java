package org.jboss.netty.handler.codec.http.multipart;

import com.ning.http.multipart.StringPart;
import java.nio.charset.Charset;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.util.CharsetUtil;

final class HttpPostBodyUtil {
    public static final String ATTACHMENT = "attachment";
    public static final String CONTENT_DISPOSITION = "Content-Disposition";
    public static final String DEFAULT_BINARY_CONTENT_TYPE = "application/octet-stream";
    public static final String DEFAULT_TEXT_CONTENT_TYPE = "text/plain";
    public static final String FILE = "file";
    public static final String FILENAME = "filename";
    public static final String FORM_DATA = "form-data";
    public static final Charset ISO_8859_1 = CharsetUtil.ISO_8859_1;
    public static final String MULTIPART_MIXED = "multipart/mixed";
    public static final String NAME = "name";
    public static final Charset US_ASCII = CharsetUtil.US_ASCII;
    public static final int chunkSize = 8096;

    static class SeekAheadNoBackArrayException extends Exception {
        private static final long serialVersionUID = -630418804938699495L;

        SeekAheadNoBackArrayException() {
        }
    }

    static class SeekAheadOptimize {
        ChannelBuffer buffer;
        byte[] bytes;
        int limit;
        int origPos;
        int pos;
        int readerIndex;

        SeekAheadOptimize(ChannelBuffer buffer2) throws SeekAheadNoBackArrayException {
            if (!buffer2.hasArray()) {
                throw new SeekAheadNoBackArrayException();
            }
            this.buffer = buffer2;
            this.bytes = buffer2.array();
            this.readerIndex = buffer2.readerIndex();
            int arrayOffset = buffer2.arrayOffset() + this.readerIndex;
            this.pos = arrayOffset;
            this.origPos = arrayOffset;
            this.limit = buffer2.arrayOffset() + buffer2.writerIndex();
        }

        /* access modifiers changed from: 0000 */
        public void setReadPosition(int minus) {
            this.pos -= minus;
            this.readerIndex = getReadPosition(this.pos);
            this.buffer.readerIndex(this.readerIndex);
        }

        /* access modifiers changed from: 0000 */
        public int getReadPosition(int index) {
            return (index - this.origPos) + this.readerIndex;
        }

        /* access modifiers changed from: 0000 */
        public void clear() {
            this.buffer = null;
            this.bytes = null;
            this.limit = 0;
            this.pos = 0;
            this.readerIndex = 0;
        }
    }

    public enum TransferEncodingMechanism {
        BIT7("7bit"),
        BIT8(StringPart.DEFAULT_TRANSFER_ENCODING),
        BINARY("binary");
        
        private final String value;

        private TransferEncodingMechanism(String value2) {
            this.value = value2;
        }

        public String value() {
            return this.value;
        }

        public String toString() {
            return this.value;
        }
    }

    private HttpPostBodyUtil() {
    }

    static int findNonWhitespace(String sb, int offset) {
        int result = offset;
        while (result < sb.length() && Character.isWhitespace(sb.charAt(result))) {
            result++;
        }
        return result;
    }

    static int findWhitespace(String sb, int offset) {
        int result = offset;
        while (result < sb.length() && !Character.isWhitespace(sb.charAt(result))) {
            result++;
        }
        return result;
    }

    static int findEndOfString(String sb) {
        int result = sb.length();
        while (result > 0 && Character.isWhitespace(sb.charAt(result - 1))) {
            result--;
        }
        return result;
    }
}