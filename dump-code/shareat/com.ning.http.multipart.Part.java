package com.ning.http.multipart;

import java.io.IOException;
import java.io.OutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class Part implements com.ning.http.client.Part {
    protected static final String CHARSET = "; charset=";
    static final byte[] CHARSET_BYTES = MultipartEncodingUtil.getAsciiBytes(CHARSET);
    protected static final String CONTENT_DISPOSITION = "Content-Disposition: form-data; name=";
    static final byte[] CONTENT_DISPOSITION_BYTES = MultipartEncodingUtil.getAsciiBytes(CONTENT_DISPOSITION);
    protected static final String CONTENT_ID = "Content-ID: ";
    static final byte[] CONTENT_ID_BYTES = MultipartEncodingUtil.getAsciiBytes(CONTENT_ID);
    protected static final String CONTENT_TRANSFER_ENCODING = "Content-Transfer-Encoding: ";
    static final byte[] CONTENT_TRANSFER_ENCODING_BYTES = MultipartEncodingUtil.getAsciiBytes(CONTENT_TRANSFER_ENCODING);
    protected static final String CONTENT_TYPE = "Content-Type: ";
    static final byte[] CONTENT_TYPE_BYTES = MultipartEncodingUtil.getAsciiBytes(CONTENT_TYPE);
    protected static final String CRLF = "\r\n";
    static final byte[] CRLF_BYTES = MultipartEncodingUtil.getAsciiBytes(CRLF);
    protected static final String EXTRA = "--";
    static final byte[] EXTRA_BYTES = MultipartEncodingUtil.getAsciiBytes(EXTRA);
    private static final Logger LOGGER = LoggerFactory.getLogger(Part.class);
    protected static final String QUOTE = "\"";
    static final byte[] QUOTE_BYTES = MultipartEncodingUtil.getAsciiBytes(QUOTE);

    public abstract String getCharSet();

    public abstract String getContentId();

    public abstract String getContentType();

    public abstract String getName();

    public abstract String getTransferEncoding();

    /* access modifiers changed from: protected */
    public abstract long lengthOfData();

    /* access modifiers changed from: protected */
    public abstract void sendData(OutputStream outputStream) throws IOException;

    public boolean isRepeatable() {
        return true;
    }

    /* access modifiers changed from: protected */
    public void sendStart(OutputStream out, byte[] boundary) throws IOException {
        out.write(EXTRA_BYTES);
        out.write(boundary);
    }

    private int startLength(byte[] boundary) {
        return EXTRA_BYTES.length + boundary.length;
    }

    /* access modifiers changed from: protected */
    public void sendDispositionHeader(OutputStream out) throws IOException {
        if (getName() != null) {
            out.write(CRLF_BYTES);
            out.write(CONTENT_DISPOSITION_BYTES);
            out.write(QUOTE_BYTES);
            out.write(MultipartEncodingUtil.getAsciiBytes(getName()));
            out.write(QUOTE_BYTES);
        }
    }

    /* access modifiers changed from: protected */
    public long dispositionHeaderLength() {
        if (getName() != null) {
            return 0 + ((long) CRLF_BYTES.length) + ((long) CONTENT_DISPOSITION_BYTES.length) + ((long) QUOTE_BYTES.length) + ((long) MultipartEncodingUtil.getAsciiBytes(getName()).length) + ((long) QUOTE_BYTES.length);
        }
        return 0;
    }

    /* access modifiers changed from: protected */
    public void sendContentTypeHeader(OutputStream out) throws IOException {
        String contentType = getContentType();
        if (contentType != null) {
            out.write(CRLF_BYTES);
            out.write(CONTENT_TYPE_BYTES);
            out.write(MultipartEncodingUtil.getAsciiBytes(contentType));
            String charSet = getCharSet();
            if (charSet != null) {
                out.write(CHARSET_BYTES);
                out.write(MultipartEncodingUtil.getAsciiBytes(charSet));
            }
        }
    }

    /* access modifiers changed from: protected */
    public long contentTypeHeaderLength() {
        String contentType = getContentType();
        if (contentType == null) {
            return 0;
        }
        long length = 0 + ((long) CRLF_BYTES.length) + ((long) CONTENT_TYPE_BYTES.length) + ((long) MultipartEncodingUtil.getAsciiBytes(contentType).length);
        String charSet = getCharSet();
        if (charSet != null) {
            return length + ((long) CHARSET_BYTES.length) + ((long) MultipartEncodingUtil.getAsciiBytes(charSet).length);
        }
        return length;
    }

    /* access modifiers changed from: protected */
    public void sendTransferEncodingHeader(OutputStream out) throws IOException {
        String transferEncoding = getTransferEncoding();
        if (transferEncoding != null) {
            out.write(CRLF_BYTES);
            out.write(CONTENT_TRANSFER_ENCODING_BYTES);
            out.write(MultipartEncodingUtil.getAsciiBytes(transferEncoding));
        }
    }

    /* access modifiers changed from: protected */
    public long transferEncodingHeaderLength() {
        String transferEncoding = getTransferEncoding();
        if (transferEncoding != null) {
            return 0 + ((long) CRLF_BYTES.length) + ((long) CONTENT_TRANSFER_ENCODING_BYTES.length) + ((long) MultipartEncodingUtil.getAsciiBytes(transferEncoding).length);
        }
        return 0;
    }

    /* access modifiers changed from: protected */
    public void sendContentIdHeader(OutputStream out) throws IOException {
        String contentId = getContentId();
        if (contentId != null) {
            out.write(CRLF_BYTES);
            out.write(CONTENT_ID_BYTES);
            out.write(MultipartEncodingUtil.getAsciiBytes(contentId));
        }
    }

    /* access modifiers changed from: protected */
    public long contentIdHeaderLength() {
        String contentId = getContentId();
        if (contentId != null) {
            return 0 + ((long) CRLF_BYTES.length) + ((long) CONTENT_ID_BYTES.length) + ((long) MultipartEncodingUtil.getAsciiBytes(contentId).length);
        }
        return 0;
    }

    /* access modifiers changed from: protected */
    public void sendEndOfHeader(OutputStream out) throws IOException {
        out.write(CRLF_BYTES);
        out.write(CRLF_BYTES);
    }

    /* access modifiers changed from: protected */
    public long endOfHeaderLength() {
        return (long) (CRLF_BYTES.length * 2);
    }

    /* access modifiers changed from: protected */
    public void sendEnd(OutputStream out) throws IOException {
        out.write(CRLF_BYTES);
    }

    /* access modifiers changed from: protected */
    public long endLength() {
        return (long) CRLF_BYTES.length;
    }

    public void send(OutputStream out, byte[] boundary) throws IOException {
        sendStart(out, boundary);
        sendDispositionHeader(out);
        sendContentTypeHeader(out);
        sendTransferEncodingHeader(out);
        sendContentIdHeader(out);
        sendEndOfHeader(out);
        sendData(out);
        sendEnd(out);
    }

    public long length(byte[] boundary) {
        long lengthOfData = lengthOfData();
        if (lengthOfData < 0) {
            return -1;
        }
        return ((long) startLength(boundary)) + lengthOfData + dispositionHeaderLength() + contentTypeHeaderLength() + transferEncodingHeaderLength() + contentIdHeaderLength() + endOfHeaderLength() + endLength();
    }

    public String toString() {
        return getName();
    }

    public static void sendParts(OutputStream out, Part[] parts, byte[] partBoundary) throws IOException {
        if (parts == null) {
            throw new IllegalArgumentException("Parts may not be null");
        } else if (partBoundary == null || partBoundary.length == 0) {
            throw new IllegalArgumentException("partBoundary may not be empty");
        } else {
            for (Part part : parts) {
                part.send(out, partBoundary);
            }
            out.write(EXTRA_BYTES);
            out.write(partBoundary);
            out.write(EXTRA_BYTES);
            out.write(CRLF_BYTES);
        }
    }

    public static void sendMessageEnd(OutputStream out, byte[] partBoundary) throws IOException {
        if (partBoundary == null || partBoundary.length == 0) {
            throw new IllegalArgumentException("partBoundary may not be empty");
        }
        out.write(EXTRA_BYTES);
        out.write(partBoundary);
        out.write(EXTRA_BYTES);
        out.write(CRLF_BYTES);
    }

    public static void sendPart(OutputStream out, Part part, byte[] partBoundary) throws IOException {
        if (part == null) {
            throw new IllegalArgumentException("Parts may not be null");
        }
        part.send(out, partBoundary);
    }

    public static long getLengthOfParts(Part[] parts, byte[] partBoundary) {
        if (parts == null) {
            try {
                throw new IllegalArgumentException("Parts may not be null");
            } catch (Exception e) {
                LOGGER.error((String) "An exception occurred while getting the length of the parts", (Throwable) e);
                return 0;
            }
        } else {
            long total = 0;
            for (Part part : parts) {
                long l = part.length(partBoundary);
                if (l < 0) {
                    return -1;
                }
                total += l;
            }
            return total + ((long) EXTRA_BYTES.length) + ((long) partBoundary.length) + ((long) EXTRA_BYTES.length) + ((long) CRLF_BYTES.length);
        }
    }
}